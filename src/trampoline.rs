//! Trampoline function creation for MinHook-rs
//!
//! This module handles creating trampoline functions that preserve original function behavior
//! while redirecting execution to detour functions.

use crate::buffer::{allocate_buffer, is_executable_address};
use crate::disasm::decode_instruction;
use crate::error::{HookError, Result};
use crate::instruction::*;
use std::ffi::c_void;
use std::ptr;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("Trampoline module only supports x86_64 architecture");

/// Maximum size of a trampoline function (buffer size - relay jump size)
const TRAMPOLINE_MAX_SIZE: usize = 64 - size_of::<JmpAbs>();

/// Minimum size required for hook installation (5 bytes for JMP rel32)
const MIN_HOOK_SIZE: usize = 5;

/// Size of short jump instruction
const SHORT_JMP_SIZE: usize = 2;

/// Check if memory region contains only padding bytes
fn is_code_padding(code: &[u8]) -> bool {
    if code.is_empty() {
        return false;
    }

    let first_byte = code[0];
    if first_byte != 0x00 && first_byte != 0x90 && first_byte != 0xCC {
        return false;
    }

    code.iter().all(|&byte| byte == first_byte)
}

/// Create a trampoline function based on original MinHook logic
pub fn create_trampoline_function(trampoline: &mut Trampoline) -> Result<()> {
    // Pre-defined instruction templates for x64
    let call_abs = CallAbs {
        opcode0: 0xFF,
        opcode1: 0x15,
        dummy0: 0x00000002, // FF15 00000002: CALL [RIP+8]
        dummy1: 0xEB,       // EB 08:         JMP +10
        dummy2: 0x08,
        address: 0x0000000000000000,
    };

    let jmp_abs = JmpAbs {
        opcode0: 0xFF,
        opcode1: 0x25,
        dummy: 0x00000000, // FF25 00000000: JMP [RIP+6]
        address: 0x0000000000000000,
    };

    let jcc_abs = JccAbs {
        opcode: 0x70,
        dummy0: 0x0E, // 7* 0E:         J** +16
        dummy1: 0xFF, // FF25 00000000: JMP [RIP+6]
        dummy2: 0x25,
        dummy3: 0x00000000,
        address: 0x0000000000000000,
    };

    let mut old_pos = 0u8;
    let mut new_pos = 0u8;
    let mut jmp_dest = 0usize; // Destination address of internal jumps
    let mut finished = false;
    let mut inst_buf = [0u8; 16];

    trampoline.patch_above = false;
    trampoline.n_ip = 0;

    loop {
        let old_inst_addr = trampoline.target as usize + old_pos as usize;
        let new_inst_addr = trampoline.trampoline as usize + new_pos as usize;

        // Read instruction bytes
        let code_slice = unsafe { std::slice::from_raw_parts(old_inst_addr as *const u8, 16) };

        let inst = decode_instruction(code_slice);
        if inst.error {
            return Err(HookError::UnsupportedFunction);
        }

        let mut copy_size = inst.len as usize;
        let mut copy_src = old_inst_addr as *const u8;

        // Check if we have enough bytes for the hook
        if old_pos >= MIN_HOOK_SIZE as u8 {
            // Complete the trampoline with jump back to original function
            let mut final_jmp = jmp_abs;
            final_jmp.address = old_inst_addr as u64;

            unsafe {
                ptr::copy_nonoverlapping(
                    &final_jmp as *const JmpAbs as *const u8,
                    inst_buf.as_mut_ptr(),
                    size_of::<JmpAbs>(),
                );
            }

            copy_src = inst_buf.as_ptr();
            copy_size = size_of::<JmpAbs>();
            finished = true;
        }
        // Handle RIP-relative addressing instructions
        else if inst.is_rip_relative() {
            // Copy instruction to buffer and modify RIP-relative address
            unsafe {
                ptr::copy_nonoverlapping(
                    old_inst_addr as *const u8,
                    inst_buf.as_mut_ptr(),
                    inst.len as usize,
                );
            }

            // Relative address is stored at (instruction length - immediate value length - 4)
            let imm_size = inst.immediate_size() as usize;
            let rel_addr_offset = inst.len as usize - imm_size - 4;
            let rel_addr_ptr = unsafe { inst_buf.as_mut_ptr().add(rel_addr_offset) as *mut u32 };

            let original_target = old_inst_addr + inst.len as usize + inst.displacement as usize;
            let new_relative =
                (original_target as i64 - (new_inst_addr + inst.len as usize) as i64) as u32;

            unsafe {
                *rel_addr_ptr = new_relative;
            }

            copy_src = inst_buf.as_ptr();

            // Complete the function if indirect JMP (FF /4)
            if inst.opcode == 0xFF && (inst.modrm >> 3 & 7) == 4 {
                finished = true;
            }
        }
        // Handle direct relative CALL
        else if inst.opcode == 0xE8 {
            let dest = old_inst_addr + inst.len as usize + inst.immediate as usize;

            let mut call = call_abs;
            call.address = dest as u64;

            unsafe {
                ptr::copy_nonoverlapping(
                    &call as *const CallAbs as *const u8,
                    inst_buf.as_mut_ptr(),
                    size_of::<CallAbs>(),
                );
            }

            copy_src = inst_buf.as_ptr();
            copy_size = size_of::<CallAbs>();
        }
        // Handle direct relative JMP (EB or E9)
        else if (inst.opcode & 0xFD) == 0xE9 {
            let dest = old_inst_addr + inst.len as usize;
            let dest = if inst.opcode == 0xEB {
                // Short jump (8-bit signed offset)
                dest + (inst.immediate as i8) as usize
            } else {
                // Long jump (32-bit signed offset)
                dest + inst.immediate as usize
            };

            // Simply copy internal jumps
            if (trampoline.target as usize) <= dest
                && dest < (trampoline.target as usize + MIN_HOOK_SIZE)
            {
                if jmp_dest < dest {
                    jmp_dest = dest;
                }
            } else {
                // External jump - convert to absolute
                let mut jmp = jmp_abs;
                jmp.address = dest as u64;

                unsafe {
                    ptr::copy_nonoverlapping(
                        &jmp as *const JmpAbs as *const u8,
                        inst_buf.as_mut_ptr(),
                        size_of::<JmpAbs>(),
                    );
                }

                copy_src = inst_buf.as_ptr();
                copy_size = size_of::<JmpAbs>();

                // Exit the function if it is not in the branch
                finished = old_inst_addr >= jmp_dest;
            }
        }
        // Handle conditional jumps and LOOP instructions
        else if (inst.opcode & 0xF0) == 0x70
            || (inst.opcode & 0xFC) == 0xE0
            || (inst.opcode2 & 0xF0) == 0x80
        {
            let dest = old_inst_addr + inst.len as usize;
            let dest = if (inst.opcode & 0xF0) == 0x70 || (inst.opcode & 0xFC) == 0xE0 {
                // Short conditional jump or LOOP instruction
                dest + (inst.immediate as i8) as usize
            } else {
                // Long conditional jump (0F 8x)
                dest + inst.immediate as usize
            };

            // Simply copy internal jumps
            if (trampoline.target as usize) <= dest
                && dest < (trampoline.target as usize + MIN_HOOK_SIZE)
            {
                if jmp_dest < dest {
                    jmp_dest = dest;
                }
            } else if (inst.opcode & 0xFC) == 0xE0 {
                // LOOPNZ/LOOPZ/LOOP/JCXZ/JECXZ to the outside are not supported
                return Err(HookError::UnsupportedFunction);
            } else {
                // External conditional jump - convert to absolute form
                let condition = if inst.opcode != 0x0F {
                    inst.opcode
                } else {
                    inst.opcode2
                } & 0x0F;

                // Invert the condition in x64 mode to simplify the conditional jump logic
                // This matches the original MinHook approach
                let mut jcc = jcc_abs;
                jcc.opcode = 0x71 ^ condition;
                jcc.address = dest as u64;

                unsafe {
                    ptr::copy_nonoverlapping(
                        &jcc as *const JccAbs as *const u8,
                        inst_buf.as_mut_ptr(),
                        size_of::<JccAbs>(),
                    );
                }

                copy_src = inst_buf.as_ptr();
                copy_size = size_of::<JccAbs>();
            }
        }
        // Handle RET instructions
        else if (inst.opcode & 0xFE) == 0xC2 {
            // Complete the function if not in a branch
            finished = old_inst_addr >= jmp_dest;
        }

        // Can't alter the instruction length in a branch
        if old_inst_addr < jmp_dest && copy_size != inst.len as usize {
            return Err(HookError::UnsupportedFunction);
        }

        // Trampoline function is too large
        if new_pos as usize + copy_size > TRAMPOLINE_MAX_SIZE {
            return Err(HookError::UnsupportedFunction);
        }

        // Trampoline function has too many instructions
        if trampoline.n_ip >= 8 {
            return Err(HookError::UnsupportedFunction);
        }

        // Record instruction boundaries
        trampoline.old_ips[trampoline.n_ip as usize] = old_pos;
        trampoline.new_ips[trampoline.n_ip as usize] = new_pos;
        trampoline.n_ip += 1;

        // Copy instruction using ptr::copy_nonoverlapping (like original)
        unsafe {
            ptr::copy_nonoverlapping(
                copy_src,
                (trampoline.trampoline as *mut u8).add(new_pos as usize),
                copy_size,
            );
        }

        new_pos += copy_size as u8;
        old_pos += inst.len;

        if finished {
            break;
        }
    }

    // Is there enough place for a long jump?
    if (old_pos as usize) < MIN_HOOK_SIZE {
        let remaining = MIN_HOOK_SIZE - old_pos as usize;
        let padding_addr = unsafe { (trampoline.target as *const u8).add(old_pos as usize) };
        let padding_slice = unsafe { std::slice::from_raw_parts(padding_addr, remaining) };

        if !is_code_padding(padding_slice) {
            // Is there enough place for a short jump?
            if (old_pos as usize) < SHORT_JMP_SIZE {
                let short_remaining = SHORT_JMP_SIZE - old_pos as usize;
                let short_padding_slice =
                    unsafe { std::slice::from_raw_parts(padding_addr, short_remaining) };

                if !is_code_padding(short_padding_slice) {
                    return Err(HookError::UnsupportedFunction);
                }
            }

            // Can we place the long jump above the function?
            let above_addr = unsafe { (trampoline.target as *const u8).sub(MIN_HOOK_SIZE) };

            if !is_executable_address(above_addr as *mut c_void) {
                return Err(HookError::UnsupportedFunction);
            }

            let above_slice = unsafe { std::slice::from_raw_parts(above_addr, MIN_HOOK_SIZE) };

            if !is_code_padding(above_slice) {
                return Err(HookError::UnsupportedFunction);
            }

            trampoline.patch_above = true;
        }
    }

    // Create relay function (points to detour)
    let mut relay_jmp = jmp_abs;
    relay_jmp.address = trampoline.detour as u64;

    trampoline.relay =
        unsafe { (trampoline.trampoline as *mut u8).add(new_pos as usize) as *mut c_void };

    unsafe {
        ptr::copy_nonoverlapping(
            &relay_jmp as *const JmpAbs as *const u8,
            trampoline.relay as *mut u8,
            size_of::<JmpAbs>(),
        );
    }

    Ok(())
}

/// Allocate and create a trampoline function
pub fn allocate_trampoline(target: *mut c_void, detour: *mut c_void) -> Result<Trampoline> {
    // Allocate buffer near the target function
    let buffer = allocate_buffer(target)?;

    // Create trampoline structure
    let mut trampoline = Trampoline::new(target, detour, buffer);

    // Create the trampoline function
    match create_trampoline_function(&mut trampoline) {
        Ok(()) => Ok(trampoline),
        Err(e) => {
            // Clean up on error
            crate::buffer::free_buffer(buffer);
            Err(e)
        }
    }
}

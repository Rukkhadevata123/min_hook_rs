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
const TRAMPOLINE_MAX_SIZE: usize = 64 - std::mem::size_of::<JmpAbs>();

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

/// Create a trampoline function
pub fn create_trampoline_function(trampoline: &mut Trampoline) -> Result<()> {
    // Pre-defined instruction templates for x64
    let mut call_abs = CallAbs::new(0);
    let mut jmp_abs = JmpAbs::new(0);

    let mut old_pos = 0u8;
    let mut new_pos = 0u8;
    let mut jmp_dest = 0usize; // Destination address of internal jumps
    let mut finished = false;

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

        let mut copy_src = old_inst_addr as *const u8;
        let mut copy_size = inst.len as usize;
        let mut inst_buf = [0u8; 16];

        // Check if we have enough bytes for the hook
        if old_pos >= MIN_HOOK_SIZE as u8 {
            // Complete the trampoline with jump back to original function
            jmp_abs.address = old_inst_addr as u64;

            unsafe {
                ptr::copy_nonoverlapping(
                    &jmp_abs as *const JmpAbs as *const u8,
                    inst_buf.as_mut_ptr(),
                    std::mem::size_of::<JmpAbs>(),
                );
            }

            copy_src = inst_buf.as_ptr();
            copy_size = std::mem::size_of::<JmpAbs>();
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

            // Calculate the position of the relative address field
            let rel_addr_offset = inst.len as usize - 4;
            let rel_addr_ptr = unsafe { inst_buf.as_mut_ptr().add(rel_addr_offset) as *mut u32 };

            // Calculate the new relative address
            let original_target = old_inst_addr + inst.len as usize + inst.displacement as usize;
            let new_relative =
                (original_target as i64 - (new_inst_addr + inst.len as usize) as i64) as i32;

            unsafe {
                *rel_addr_ptr = new_relative as u32;
            }

            copy_src = inst_buf.as_ptr();

            // Check if this is an indirect JMP that completes the function
            if inst.opcode == 0xFF && (inst.modrm >> 3 & 7) == 4 {
                finished = true;
            }
        }
        // Handle direct relative CALL
        else if inst.is_call() {
            let dest = old_inst_addr + inst.len as usize + inst.immediate as usize;
            call_abs.address = dest as u64;

            unsafe {
                ptr::copy_nonoverlapping(
                    &call_abs as *const CallAbs as *const u8,
                    inst_buf.as_mut_ptr(),
                    std::mem::size_of::<CallAbs>(),
                );
            }

            copy_src = inst_buf.as_ptr();
            copy_size = std::mem::size_of::<CallAbs>();
        }
        // Handle direct relative JMP
        else if inst.is_jmp() {
            let dest = if inst.opcode == 0xEB {
                // Short jump (8-bit offset)
                old_inst_addr + inst.len as usize + (inst.immediate as i8) as usize
            } else {
                // Long jump (32-bit offset)
                old_inst_addr + inst.len as usize + inst.immediate as usize
            };

            // Check if this is an internal jump
            let target_start = trampoline.target as usize;
            let target_end = target_start + MIN_HOOK_SIZE;

            if dest >= target_start && dest < target_end {
                // Internal jump - just copy it and track the destination
                if jmp_dest < dest {
                    jmp_dest = dest;
                }
            } else {
                // External jump - convert to absolute jump
                jmp_abs.address = dest as u64;

                unsafe {
                    ptr::copy_nonoverlapping(
                        &jmp_abs as *const JmpAbs as *const u8,
                        inst_buf.as_mut_ptr(),
                        std::mem::size_of::<JmpAbs>(),
                    );
                }

                copy_src = inst_buf.as_ptr();
                copy_size = std::mem::size_of::<JmpAbs>();

                // Finish if we're not in a branch
                finished = old_inst_addr >= jmp_dest;
            }
        }
        // Handle conditional jumps - simplified processing
        else if inst.is_conditional() {
            let dest = if (inst.opcode & 0xF0) == 0x70 || (inst.opcode & 0xFC) == 0xE0 {
                // Short conditional jump or LOOP instruction
                old_inst_addr + inst.len as usize + (inst.immediate as i8) as usize
            } else {
                // Long conditional jump
                old_inst_addr + inst.len as usize + inst.immediate as usize
            };

            let target_start = trampoline.target as usize;
            let target_end = target_start + MIN_HOOK_SIZE;

            if dest >= target_start && dest < target_end {
                // Internal conditional jump - just copy it
                if jmp_dest < dest {
                    jmp_dest = dest;
                }
            }
            // For external conditional jumps, copy as-is to avoid complex conversion errors
        }
        // Handle RET instruction
        else if inst.is_ret() {
            // Complete the function if not in a branch
            finished = old_inst_addr >= jmp_dest;
        }

        // Check if we're modifying instruction length inside a branch target
        if old_inst_addr < jmp_dest && copy_size != inst.len as usize {
            return Err(HookError::UnsupportedFunction);
        }

        // Check trampoline size limits
        if new_pos as usize + copy_size > TRAMPOLINE_MAX_SIZE {
            return Err(HookError::UnsupportedFunction);
        }

        // Check instruction boundary limits
        if trampoline.n_ip >= 8 {
            return Err(HookError::UnsupportedFunction);
        }

        // Record instruction boundaries
        trampoline.old_ips[trampoline.n_ip as usize] = old_pos;
        trampoline.new_ips[trampoline.n_ip as usize] = new_pos;
        trampoline.n_ip += 1;

        // Copy the instruction to trampoline
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

    // Check if there's enough space for the hook
    if (old_pos as usize) < MIN_HOOK_SIZE {
        let remaining_bytes = MIN_HOOK_SIZE - old_pos as usize;
        let padding_start = unsafe { (trampoline.target as *const u8).add(old_pos as usize) };
        let padding_slice = unsafe { std::slice::from_raw_parts(padding_start, remaining_bytes) };

        if !is_code_padding(padding_slice) {
            // Check if we can use a short jump
            if (old_pos as usize) < SHORT_JMP_SIZE {
                let short_padding_slice = unsafe {
                    std::slice::from_raw_parts(padding_start, SHORT_JMP_SIZE - old_pos as usize)
                };

                if !is_code_padding(short_padding_slice) {
                    return Err(HookError::UnsupportedFunction);
                }
            }

            // Check if we can patch above the function
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
    jmp_abs.address = trampoline.detour as u64;
    trampoline.relay =
        unsafe { (trampoline.trampoline as *mut u8).add(new_pos as usize) as *mut c_void };

    unsafe {
        ptr::copy_nonoverlapping(
            &jmp_abs as *const JmpAbs as *const u8,
            trampoline.relay as *mut u8,
            std::mem::size_of::<JmpAbs>(),
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

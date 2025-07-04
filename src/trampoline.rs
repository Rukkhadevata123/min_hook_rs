//! Trampoline function creation for MinHook-rs
//!
//! Direct port of trampoline.c for x64, maintaining exact compatibility

use crate::buffer::{allocate_buffer, is_executable_address};
use crate::disasm::{F_ERROR, decode_instruction};
use crate::error::{HookError, Result};
use crate::instruction::*;
use std::ffi::c_void;
use std::ptr;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("Trampoline module only supports x86_64 architecture");

/// Maximum size of a trampoline function (64 - sizeof(JMP_ABS))
const TRAMPOLINE_MAX_SIZE: usize = 64 - size_of::<JmpAbs>();

/// Size of JMP_REL (E9 xxxxxxxx) for minimum hook size
const JMP_REL_SIZE: usize = 5;

/// Size of short jump (EB xx)  
const JMP_REL_SHORT_SIZE: usize = 2;

/// Check if memory region contains only padding bytes (like original IsCodePadding)
fn is_code_padding(inst: &[u8]) -> bool {
    if inst.is_empty() {
        return false;
    }

    let first_byte = inst[0];
    if first_byte != 0x00 && first_byte != 0x90 && first_byte != 0xCC {
        return false;
    }

    inst.iter().all(|&byte| byte == first_byte)
}

/// Create trampoline function - direct port of CreateTrampolineFunction
pub fn create_trampoline_function(trampoline: &mut Trampoline) -> Result<()> {
    // Pre-defined instruction templates (exactly like original)
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
    let mut jmp_dest = 0usize; // Destination address of an internal jump
    let mut finished = false; // Is the function completed?
    let mut inst_buf = [0u8; 16]; // Buffer for modified instructions

    trampoline.patch_above = false;
    trampoline.n_ip = 0;

    // Main disassembly loop (replaces do-while from C)
    loop {
        let p_old_inst = trampoline.target as usize + old_pos as usize;
        let p_new_inst = trampoline.trampoline as usize + new_pos as usize;

        // Read and disassemble instruction
        let code_slice = unsafe { std::slice::from_raw_parts(p_old_inst as *const u8, 16) };
        let hs = decode_instruction(code_slice);

        if (hs.flags & F_ERROR) != 0 {
            return Err(HookError::UnsupportedFunction);
        }

        let mut copy_size = hs.len as usize;
        let mut copy_src = p_old_inst as *const u8;

        // Check if we have enough bytes for the hook (like original)
        if old_pos >= JMP_REL_SIZE as u8 {
            // The trampoline function is long enough.
            // Complete the function with the jump to the target function.
            let mut jmp = jmp_abs;
            jmp.address = p_old_inst as u64;

            unsafe {
                ptr::copy_nonoverlapping(
                    &jmp as *const JmpAbs as *const u8,
                    inst_buf.as_mut_ptr(),
                    size_of::<JmpAbs>(),
                );
            }

            copy_src = inst_buf.as_ptr();
            copy_size = size_of::<JmpAbs>();
            finished = true;
        }
        // Instructions using RIP relative addressing (ModR/M = 00???101B)
        else if (hs.modrm & 0xC7) == 0x05 {
            // Modify the RIP relative address
            unsafe {
                ptr::copy_nonoverlapping(p_old_inst as *const u8, inst_buf.as_mut_ptr(), copy_size);
            }
            copy_src = inst_buf.as_ptr();

            // Calculate relative address offset - avoid misaligned pointer dereference
            let imm_len = ((hs.flags & 0x3C) >> 2) as usize; // Extract immediate length from flags
            let rel_addr_offset = hs.len as usize - imm_len - 4;

            // Read the current relative address using aligned access
            let _current_rel_addr = {
                let bytes = [
                    inst_buf[rel_addr_offset],
                    inst_buf[rel_addr_offset + 1],
                    inst_buf[rel_addr_offset + 2],
                    inst_buf[rel_addr_offset + 3],
                ];
                u32::from_le_bytes(bytes)
            };

            // Calculate new relative address
            let original_target = p_old_inst + hs.len as usize + hs.displacement as usize;
            let new_relative =
                (original_target as i64 - (p_new_inst + hs.len as usize) as i64) as u32;

            // Write the new relative address using aligned access
            let new_bytes = new_relative.to_le_bytes();
            inst_buf[rel_addr_offset] = new_bytes[0];
            inst_buf[rel_addr_offset + 1] = new_bytes[1];
            inst_buf[rel_addr_offset + 2] = new_bytes[2];
            inst_buf[rel_addr_offset + 3] = new_bytes[3];

            // Complete the function if JMP (FF /4)
            if hs.opcode == 0xFF && hs.modrm_reg == 4 {
                finished = true;
            }
        }
        // Direct relative CALL
        else if hs.opcode == 0xE8 {
            let dest = p_old_inst + hs.len as usize + hs.immediate as usize;

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
        // Direct relative JMP (EB or E9)
        else if (hs.opcode & 0xFD) == 0xE9 {
            let mut dest = p_old_inst + hs.len as usize;

            if hs.opcode == 0xEB {
                // Short jump
                dest = dest.wrapping_add((hs.immediate as i8) as usize);
            } else {
                // Long jump
                dest = dest.wrapping_add(hs.immediate as usize);
            }

            // Simply copy an internal jump
            if (trampoline.target as usize) <= dest
                && dest < (trampoline.target as usize + JMP_REL_SIZE)
            {
                if jmp_dest < dest {
                    jmp_dest = dest;
                }
            } else {
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
                finished = p_old_inst >= jmp_dest;
            }
        }
        // Direct relative Jcc
        else if (hs.opcode & 0xF0) == 0x70
            || (hs.opcode & 0xFC) == 0xE0
            || (hs.opcode2 & 0xF0) == 0x80
        {
            let mut dest = p_old_inst + hs.len as usize;

            if (hs.opcode & 0xF0) == 0x70      // Jcc
                || (hs.opcode & 0xFC) == 0xE0
            // LOOPNZ/LOOPZ/LOOP/JECXZ
            {
                dest = dest.wrapping_add((hs.immediate as i8) as usize);
            } else {
                dest = dest.wrapping_add(hs.immediate as usize);
            }

            // Simply copy an internal jump
            if (trampoline.target as usize) <= dest
                && dest < (trampoline.target as usize + JMP_REL_SIZE)
            {
                if jmp_dest < dest {
                    jmp_dest = dest;
                }
            } else if (hs.opcode & 0xFC) == 0xE0 {
                // LOOPNZ/LOOPZ/LOOP/JCXZ/JECXZ to the outside are not supported
                return Err(HookError::UnsupportedFunction);
            } else {
                let cond = if hs.opcode != 0x0F {
                    hs.opcode
                } else {
                    hs.opcode2
                } & 0x0F;

                // Invert the condition in x64 mode to simplify the conditional jump logic
                let mut jcc = jcc_abs;
                jcc.opcode = 0x71 ^ cond;
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
        // RET (C2 or C3)
        else if (hs.opcode & 0xFE) == 0xC2 {
            // Complete the function if not in a branch
            finished = p_old_inst >= jmp_dest;
        }

        // Can't alter the instruction length in a branch
        if p_old_inst < jmp_dest && copy_size != hs.len as usize {
            return Err(HookError::UnsupportedFunction);
        }

        // Trampoline function is too large
        if (new_pos as usize + copy_size) > TRAMPOLINE_MAX_SIZE {
            return Err(HookError::UnsupportedFunction);
        }

        // Trampoline function has too many instructions (ARRAYSIZE(ct->oldIPs) = 8)
        if trampoline.n_ip >= 8 {
            return Err(HookError::UnsupportedFunction);
        }

        // Record instruction boundaries
        trampoline.old_ips[trampoline.n_ip as usize] = old_pos;
        trampoline.new_ips[trampoline.n_ip as usize] = new_pos;
        trampoline.n_ip += 1;

        // Copy instruction (like __movsb in original)
        unsafe {
            ptr::copy_nonoverlapping(
                copy_src,
                (trampoline.trampoline as *mut u8).add(new_pos as usize),
                copy_size,
            );
        }

        new_pos += copy_size as u8;
        old_pos += hs.len;

        if finished {
            break;
        }
    }

    // Is there enough place for a long jump?
    if (old_pos as usize) < JMP_REL_SIZE {
        let remaining = JMP_REL_SIZE - old_pos as usize;
        let padding_slice = unsafe {
            std::slice::from_raw_parts(
                (trampoline.target as *const u8).add(old_pos as usize),
                remaining,
            )
        };

        if !is_code_padding(padding_slice) {
            // Is there enough place for a short jump?
            if (old_pos as usize) < JMP_REL_SHORT_SIZE {
                let short_remaining = JMP_REL_SHORT_SIZE - old_pos as usize;
                let short_padding_slice = unsafe {
                    std::slice::from_raw_parts(
                        (trampoline.target as *const u8).add(old_pos as usize),
                        short_remaining,
                    )
                };

                if !is_code_padding(short_padding_slice) {
                    return Err(HookError::UnsupportedFunction);
                }
            }

            // Can we place the long jump above the function?
            let above_addr =
                unsafe { (trampoline.target as *const u8).sub(JMP_REL_SIZE) as *mut c_void };

            if !is_executable_address(above_addr) {
                return Err(HookError::UnsupportedFunction);
            }

            let above_slice =
                unsafe { std::slice::from_raw_parts(above_addr as *const u8, JMP_REL_SIZE) };

            if !is_code_padding(above_slice) {
                return Err(HookError::UnsupportedFunction);
            }

            trampoline.patch_above = true;
        }
    }

    // Create a relay function (exactly like original)
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

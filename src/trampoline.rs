//! Trampoline function creation for MinHook-rs

use crate::buffer::{MEMORY_SLOT_SIZE, allocate_buffer, is_executable_address};
use crate::disasm::decode_instruction;
use crate::error::{HookError, Result};
use crate::instruction::*;
use std::ffi::c_void;
use std::ptr;

/// Maximum size of a trampoline function
const TRAMPOLINE_MAX_SIZE: usize = MEMORY_SLOT_SIZE - size_of::<JmpAbs>();

/// Create a trampoline function
pub fn create_trampoline(ct: &mut Trampoline) -> Result<()> {
    ct.patch_above = false;
    ct.n_ip = 0;
    ct.old_ips.fill(0);
    ct.new_ips.fill(0);

    let mut old_pos = 0u8;
    let mut new_pos = 0u8;
    let mut jmp_dest = 0usize; // Destination address of an internal jump
    let mut finished = false;

    // Allocate trampoline buffer
    ct.trampoline = allocate_buffer(ct.target)?;

    loop {
        let old_inst = (ct.target as usize + old_pos as usize) as *const u8;
        let new_inst = (ct.trampoline as usize + new_pos as usize) as *mut u8;

        // Get instruction bytes for decoding
        let code_slice =
            unsafe { std::slice::from_raw_parts(old_inst, 16.min(256 - old_pos as usize)) };

        let hs = decode_instruction(code_slice);
        if hs.len == 0 {
            return Err(HookError::UnsupportedFunction);
        }

        let mut copy_size = hs.len;
        let mut temp_buffer = [0u8; 16];

        // Check if we have enough space for the hook
        if old_pos >= size_of::<JmpRel>() as u8 {
            // Complete the function with jump to remaining target
            let jmp = JmpAbs::new(old_inst as u64);
            let jmp_bytes = unsafe {
                std::slice::from_raw_parts(&jmp as *const _ as *const u8, size_of::<JmpAbs>())
            };
            unsafe {
                ptr::copy_nonoverlapping(jmp_bytes.as_ptr(), new_inst, jmp_bytes.len());
            }
            copy_size = size_of::<JmpAbs>() as u8;
            finished = true;
        } else if hs.is_rip_relative() {
            // Handle RIP-relative addressing
            unsafe {
                ptr::copy_nonoverlapping(old_inst, temp_buffer.as_mut_ptr(), hs.len as usize);
            }

            // Calculate new displacement
            let old_target = old_inst as u64 + hs.len as u64 + hs.displacement as u64;
            let new_disp = old_target as i64 - (new_inst as u64 + hs.len as u64) as i64;

            // Update displacement in instruction
            let disp_offset = (hs.len as usize)
                .saturating_sub(4)
                .saturating_sub(hs.immediate_size as usize);
            if disp_offset + 4 <= hs.len as usize {
                let disp_bytes = (new_disp as u32).to_le_bytes();
                temp_buffer[disp_offset..disp_offset + 4].copy_from_slice(&disp_bytes);
            }

            unsafe {
                ptr::copy_nonoverlapping(temp_buffer.as_ptr(), new_inst, hs.len as usize);
            }

            // Complete if indirect jump
            if hs.opcode == 0xFF && hs.modrm_reg() == 4 {
                finished = true;
            }
        } else if hs.opcode == 0xE8 {
            // Direct relative CALL
            let dest = old_inst as u64 + hs.len as u64 + hs.immediate as u64;
            let call = CallAbs::new(dest);
            let call_bytes = unsafe {
                std::slice::from_raw_parts(&call as *const _ as *const u8, size_of::<CallAbs>())
            };
            unsafe {
                ptr::copy_nonoverlapping(call_bytes.as_ptr(), new_inst, call_bytes.len());
            }
            copy_size = size_of::<CallAbs>() as u8;
        } else if hs.opcode == 0xE9 || hs.opcode == 0xEB {
            // Direct relative JMP
            let dest = if hs.opcode == 0xEB {
                old_inst as u64 + hs.len as u64 + hs.immediate as i8 as i64 as u64
            } else {
                old_inst as u64 + hs.len as u64 + hs.immediate as u64
            };

            // Check if it's an internal jump
            let target_start = ct.target as u64;
            let target_end = target_start + size_of::<JmpRel>() as u64;

            if dest >= target_start && dest < target_end {
                // Internal jump - copy as-is and update jump destination
                if dest > jmp_dest as u64 {
                    jmp_dest = dest as usize;
                }
                unsafe {
                    ptr::copy_nonoverlapping(old_inst, new_inst, hs.len as usize);
                }
            } else {
                // External jump - use absolute jump
                let jmp = JmpAbs::new(dest);
                let jmp_bytes = unsafe {
                    std::slice::from_raw_parts(&jmp as *const _ as *const u8, size_of::<JmpAbs>())
                };
                unsafe {
                    ptr::copy_nonoverlapping(jmp_bytes.as_ptr(), new_inst, jmp_bytes.len());
                }
                copy_size = size_of::<JmpAbs>() as u8;
                finished = old_inst as usize >= jmp_dest;
            }
        } else if hs.is_conditional_jump() {
            // Conditional jumps
            let dest = if hs.opcode == 0x0F {
                old_inst as u64 + hs.len as u64 + hs.immediate as u64
            } else {
                old_inst as u64 + hs.len as u64 + hs.immediate as i8 as i64 as u64
            };

            let target_start = ct.target as u64;
            let target_end = target_start + size_of::<JmpRel>() as u64;

            if dest >= target_start && dest < target_end {
                // Internal conditional jump
                if dest > jmp_dest as u64 {
                    jmp_dest = dest as usize;
                }
                unsafe {
                    ptr::copy_nonoverlapping(old_inst, new_inst, hs.len as usize);
                }
            } else {
                // External conditional jump - not supported for LOOP instructions
                if (hs.opcode & 0xFC) == 0xE0 {
                    return Err(HookError::UnsupportedFunction);
                }

                // Use absolute conditional jump
                let condition = if hs.opcode != 0x0F {
                    hs.opcode & 0x0F
                } else {
                    hs.opcode2 & 0x0F
                };

                let jcc = JccAbs::new(condition ^ 1, dest); // Invert condition
                let jcc_bytes = unsafe {
                    std::slice::from_raw_parts(&jcc as *const _ as *const u8, size_of::<JccAbs>())
                };
                unsafe {
                    ptr::copy_nonoverlapping(jcc_bytes.as_ptr(), new_inst, jcc_bytes.len());
                }
                copy_size = size_of::<JccAbs>() as u8;
            }
        } else if hs.opcode == 0xC2 || hs.opcode == 0xC3 {
            // RET instruction - complete if not in branch
            finished = (old_inst as usize) >= jmp_dest;
            unsafe {
                ptr::copy_nonoverlapping(old_inst, new_inst, hs.len as usize);
            }
        } else {
            // Regular instruction - copy as-is
            unsafe {
                ptr::copy_nonoverlapping(old_inst, new_inst, hs.len as usize);
            }
        }

        // Check size limits
        if (old_inst as usize) < jmp_dest && copy_size != hs.len {
            return Err(HookError::UnsupportedFunction);
        }

        if (new_pos as usize + copy_size as usize) > TRAMPOLINE_MAX_SIZE {
            return Err(HookError::UnsupportedFunction);
        }

        if ct.n_ip >= ct.old_ips.len() as u32 {
            return Err(HookError::UnsupportedFunction);
        }

        // Record instruction boundaries
        ct.old_ips[ct.n_ip as usize] = old_pos;
        ct.new_ips[ct.n_ip as usize] = new_pos;
        ct.n_ip += 1;

        new_pos += copy_size;
        old_pos += hs.len;

        if finished {
            break;
        }
    }

    // Check if we have enough space for the hook
    if (old_pos as usize) < size_of::<JmpRel>() {
        let padding_size = size_of::<JmpRel>() - old_pos as usize;
        let padding_start = (ct.target as usize + old_pos as usize) as *const u8;

        // Check if there's padding after the function
        if !is_code_padding(padding_start, padding_size) {
            // Check for short jump space
            if (old_pos as usize) < size_of::<JmpRelShort>() {
                let short_padding_size = size_of::<JmpRelShort>() - old_pos as usize;
                if !is_code_padding(padding_start, short_padding_size) {
                    return Err(HookError::UnsupportedFunction);
                }
            }

            // Try to use hot patch area above the function
            let hot_patch_addr = (ct.target as usize - size_of::<JmpRel>()) as *mut c_void;
            if !is_executable_address(hot_patch_addr) {
                return Err(HookError::UnsupportedFunction);
            }

            let hot_patch_bytes = (ct.target as usize - size_of::<JmpRel>()) as *const u8;
            if !is_code_padding(hot_patch_bytes, size_of::<JmpRel>()) {
                return Err(HookError::UnsupportedFunction);
            }

            ct.patch_above = true;
        }
    }

    // Create relay function
    let jmp = JmpAbs::new(ct.detour as u64);
    ct.relay = ((ct.trampoline as usize) + new_pos as usize) as *mut c_void;

    unsafe {
        let jmp_bytes =
            std::slice::from_raw_parts(&jmp as *const _ as *const u8, size_of::<JmpAbs>());
        ptr::copy_nonoverlapping(jmp_bytes.as_ptr(), ct.relay as *mut u8, jmp_bytes.len());
    }

    Ok(())
}

/// Check if memory region contains only padding bytes
fn is_code_padding(inst: *const u8, size: usize) -> bool {
    if size == 0 {
        return true;
    }

    unsafe {
        let first_byte = *inst;
        if first_byte != 0x00 && first_byte != 0x90 && first_byte != 0xCC {
            return false;
        }

        for i in 1..size {
            if *inst.add(i) != first_byte {
                return false;
            }
        }
    }

    true
}

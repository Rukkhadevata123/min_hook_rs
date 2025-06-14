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

/// Create a trampoline function based on original MinHook logic
pub fn create_trampoline_function(trampoline: &mut Trampoline) -> Result<()> {
    // TODO: Remove debug output - 检查输入参数
    println!(
        "[DEBUG] Creating trampoline for target: {:p}, detour: {:p}, buffer: {:p}",
        trampoline.target, trampoline.detour, trampoline.trampoline
    );

    // TODO: Remove debug output - 检查原始函数代码
    println!("[DEBUG] Original function code dump:");
    unsafe {
        let original_code = std::slice::from_raw_parts(trampoline.target as *const u8, 32);
        for (i, chunk) in original_code.chunks(16).enumerate() {
            print!("[DEBUG] {:04x}: ", i * 16);
            for &byte in chunk {
                print!("{:02x} ", byte);
            }
            println!();
        }
    }

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

    // TODO: Remove debug output - 指令处理循环开始
    println!("[DEBUG] Starting instruction processing loop...");

    loop {
        let old_inst_addr = trampoline.target as usize + old_pos as usize;
        let new_inst_addr = trampoline.trampoline as usize + new_pos as usize;

        // TODO: Remove debug output - 当前指令位置
        println!(
            "[DEBUG] Processing instruction at old_pos: {}, new_pos: {}, old_addr: 0x{:x}, new_addr: 0x{:x}",
            old_pos, new_pos, old_inst_addr, new_inst_addr
        );

        // Read instruction bytes
        let code_slice = unsafe { std::slice::from_raw_parts(old_inst_addr as *const u8, 16) };

        // TODO: Remove debug output - 当前指令字节
        print!("[DEBUG] Current instruction bytes: ");
        for i in 0..16.min(code_slice.len()) {
            print!("{:02x} ", code_slice[i]);
        }
        println!();

        let inst = decode_instruction(code_slice);
        if inst.error {
            // TODO: Remove debug output - 解码错误
            println!("[DEBUG] Instruction decode error!");
            return Err(HookError::UnsupportedFunction);
        }

        // TODO: Remove debug output - 解码结果
        println!(
            "[DEBUG] Decoded instruction: len={}, opcode=0x{:02x}, opcode2=0x{:02x}, modrm=0x{:02x}, immediate=0x{:x}, displacement=0x{:x}",
            inst.len, inst.opcode, inst.opcode2, inst.modrm, inst.immediate, inst.displacement
        );

        let mut copy_size = inst.len as usize;
        let mut copy_src = old_inst_addr as *const u8;

        // Check if we have enough bytes for the hook
        if old_pos >= MIN_HOOK_SIZE as u8 {
            // TODO: Remove debug output - 结束trampoline
            println!(
                "[DEBUG] Enough bytes copied ({}), finishing trampoline with jump back to 0x{:x}",
                old_pos, old_inst_addr
            );

            // Complete the trampoline with jump back to original function
            let mut final_jmp = jmp_abs;
            final_jmp.address = old_inst_addr as u64;

            // TODO: Remove debug output - 最终跳转指令
            let addr = final_jmp.address;
            println!(
                "[DEBUG] Final jump instruction: FF 25 00 00 00 00 {:016x}",
                addr
            );

            unsafe {
                ptr::copy_nonoverlapping(
                    &final_jmp as *const JmpAbs as *const u8,
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
            // TODO: Remove debug output - RIP相对寻址
            println!("[DEBUG] Handling RIP-relative instruction");

            // Copy instruction to buffer and modify RIP-relative address
            unsafe {
                // Avoid using memcpy to reduce footprint (like original)
                for i in 0..inst.len as usize {
                    inst_buf[i] = *((old_inst_addr as *const u8).add(i));
                }
            }

            // Relative address is stored at (instruction length - 4)
            // This matches the original HDE logic for displacement calculation
            let rel_addr_ptr =
                unsafe { inst_buf.as_mut_ptr().add(inst.len as usize - 4) as *mut u32 };

            let original_target = old_inst_addr + inst.len as usize + inst.displacement as usize;
            let new_relative =
                (original_target as i64 - (new_inst_addr + inst.len as usize) as i64) as u32;

            // TODO: Remove debug output - RIP相对地址修正
            println!(
                "[DEBUG] RIP-relative fix: original_target=0x{:x}, original_disp=0x{:x}, new_disp=0x{:x}",
                original_target, inst.displacement as u32, new_relative
            );

            unsafe {
                *rel_addr_ptr = new_relative;
            }

            copy_src = inst_buf.as_ptr();

            // Complete the function if indirect JMP (FF /4)
            if inst.opcode == 0xFF && (inst.modrm >> 3 & 7) == 4 {
                // TODO: Remove debug output - 间接跳转结束
                println!("[DEBUG] Indirect JMP detected, finishing function");
                finished = true;
            }
        }
        // Handle direct relative CALL
        else if inst.opcode == 0xE8 {
            let dest = old_inst_addr + inst.len as usize + inst.immediate as usize;

            // TODO: Remove debug output - 相对调用
            println!(
                "[DEBUG] Converting relative CALL to absolute, dest=0x{:x}",
                dest
            );

            let mut call = call_abs;
            call.address = dest as u64;

            unsafe {
                ptr::copy_nonoverlapping(
                    &call as *const CallAbs as *const u8,
                    inst_buf.as_mut_ptr(),
                    std::mem::size_of::<CallAbs>(),
                );
            }

            copy_src = inst_buf.as_ptr();
            copy_size = std::mem::size_of::<CallAbs>();
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

            // TODO: Remove debug output - 相对跳转
            println!(
                "[DEBUG] Processing relative JMP (0x{:02x}) to 0x{:x}",
                inst.opcode, dest
            );

            // Simply copy internal jumps
            if (trampoline.target as usize) <= dest
                && dest < (trampoline.target as usize + MIN_HOOK_SIZE)
            {
                // TODO: Remove debug output - 内部跳转
                println!("[DEBUG] Internal jump detected, copying as-is");
                if jmp_dest < dest {
                    jmp_dest = dest;
                }
            } else {
                // TODO: Remove debug output - 外部跳转
                println!("[DEBUG] External jump, converting to absolute");

                // External jump - convert to absolute
                let mut jmp = jmp_abs;
                jmp.address = dest as u64;

                unsafe {
                    ptr::copy_nonoverlapping(
                        &jmp as *const JmpAbs as *const u8,
                        inst_buf.as_mut_ptr(),
                        std::mem::size_of::<JmpAbs>(),
                    );
                }

                copy_src = inst_buf.as_ptr();
                copy_size = std::mem::size_of::<JmpAbs>();

                // Exit the function if it is not in the branch
                finished = old_inst_addr >= jmp_dest;

                // TODO: Remove debug output - 是否结束
                println!("[DEBUG] External jump, finished = {}", finished);
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

            // TODO: Remove debug output - 条件跳转
            println!("[DEBUG] Processing conditional jump to 0x{:x}", dest);

            // Simply copy internal jumps
            if (trampoline.target as usize) <= dest
                && dest < (trampoline.target as usize + MIN_HOOK_SIZE)
            {
                // TODO: Remove debug output - 内部条件跳转
                println!("[DEBUG] Internal conditional jump, copying as-is");
                if jmp_dest < dest {
                    jmp_dest = dest;
                }
            } else if (inst.opcode & 0xFC) == 0xE0 {
                // TODO: Remove debug output - LOOP指令
                println!("[DEBUG] External LOOP instruction not supported");
                // LOOPNZ/LOOPZ/LOOP/JCXZ/JECXZ to the outside are not supported
                return Err(HookError::UnsupportedFunction);
            } else {
                // TODO: Remove debug output - 外部条件跳转
                println!("[DEBUG] External conditional jump, converting to absolute");

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

                // TODO: Remove debug output - 条件码反转
                println!(
                    "[DEBUG] Condition inverted: original=0x{:x}, inverted=0x{:02x}",
                    condition, jcc.opcode
                );

                unsafe {
                    ptr::copy_nonoverlapping(
                        &jcc as *const JccAbs as *const u8,
                        inst_buf.as_mut_ptr(),
                        std::mem::size_of::<JccAbs>(),
                    );
                }

                copy_src = inst_buf.as_ptr();
                copy_size = std::mem::size_of::<JccAbs>();
            }
        }
        // Handle RET instructions
        else if (inst.opcode & 0xFE) == 0xC2 {
            // TODO: Remove debug output - RET指令
            println!("[DEBUG] RET instruction detected");
            // Complete the function if not in a branch
            finished = old_inst_addr >= jmp_dest;
            println!("[DEBUG] RET: finished = {}", finished);
        }

        // Can't alter the instruction length in a branch
        if old_inst_addr < jmp_dest && copy_size != inst.len as usize {
            // TODO: Remove debug output - 分支内长度冲突
            println!(
                "[DEBUG] ERROR: Can't alter instruction length in branch! old_addr=0x{:x}, jmp_dest=0x{:x}, copy_size={}, inst_len={}",
                old_inst_addr, jmp_dest, copy_size, inst.len
            );
            return Err(HookError::UnsupportedFunction);
        }

        // Trampoline function is too large
        if new_pos as usize + copy_size > TRAMPOLINE_MAX_SIZE {
            // TODO: Remove debug output - Trampoline太大
            println!(
                "[DEBUG] ERROR: Trampoline too large! new_pos={}, copy_size={}, max_size={}",
                new_pos, copy_size, TRAMPOLINE_MAX_SIZE
            );
            return Err(HookError::UnsupportedFunction);
        }

        // Trampoline function has too many instructions
        if trampoline.n_ip >= 8 {
            // TODO: Remove debug output - 指令过多
            println!(
                "[DEBUG] ERROR: Too many instructions! n_ip={}",
                trampoline.n_ip
            );
            return Err(HookError::UnsupportedFunction);
        }

        // Record instruction boundaries
        trampoline.old_ips[trampoline.n_ip as usize] = old_pos;
        trampoline.new_ips[trampoline.n_ip as usize] = new_pos;
        trampoline.n_ip += 1;

        // TODO: Remove debug output - 指令边界记录
        println!(
            "[DEBUG] Recording boundary: old_ip[{}]={}, new_ip[{}]={}",
            trampoline.n_ip - 1,
            old_pos,
            trampoline.n_ip - 1,
            new_pos
        );

        // TODO: Remove debug output - 复制前的源数据
        print!(
            "[DEBUG] Copying {} bytes from 0x{:x}: ",
            copy_size, copy_src as usize
        );
        unsafe {
            let src_slice = std::slice::from_raw_parts(copy_src, copy_size);
            for &byte in src_slice {
                print!("{:02x} ", byte);
            }
            println!();
        }

        // Copy instruction (avoiding memcpy to reduce footprint like original)
        unsafe {
            for i in 0..copy_size {
                *((trampoline.trampoline as *mut u8).add(new_pos as usize + i)) =
                    *(copy_src.add(i));
            }
        }

        new_pos += copy_size as u8;
        old_pos += inst.len;

        // TODO: Remove debug output - 位置更新
        println!(
            "[DEBUG] Updated positions: old_pos={}, new_pos={}",
            old_pos, new_pos
        );

        if finished {
            // TODO: Remove debug output - 循环结束
            println!("[DEBUG] Trampoline generation finished");
            break;
        }
    }

    // Is there enough place for a long jump?
    if (old_pos as usize) < MIN_HOOK_SIZE {
        let remaining = MIN_HOOK_SIZE - old_pos as usize;
        let padding_addr = unsafe { (trampoline.target as *const u8).add(old_pos as usize) };
        let padding_slice = unsafe { std::slice::from_raw_parts(padding_addr, remaining) };

        // TODO: Remove debug output - 检查填充
        println!(
            "[DEBUG] Not enough space for hook ({}), checking padding at 0x{:x}",
            old_pos, padding_addr as usize
        );
        print!("[DEBUG] Padding bytes: ");
        for &byte in padding_slice {
            print!("{:02x} ", byte);
        }
        println!();

        if !is_code_padding(padding_slice) {
            // Is there enough place for a short jump?
            if (old_pos as usize) < SHORT_JMP_SIZE {
                let short_remaining = SHORT_JMP_SIZE - old_pos as usize;
                let short_padding_slice =
                    unsafe { std::slice::from_raw_parts(padding_addr, short_remaining) };

                if !is_code_padding(short_padding_slice) {
                    // TODO: Remove debug output - 空间不够
                    println!("[DEBUG] ERROR: Not enough space for even short jump");
                    return Err(HookError::UnsupportedFunction);
                }
            }

            // Can we place the long jump above the function?
            let above_addr = unsafe { (trampoline.target as *const u8).sub(MIN_HOOK_SIZE) };

            // TODO: Remove debug output - 检查上方空间
            println!(
                "[DEBUG] Checking patch above at 0x{:x}",
                above_addr as usize
            );

            if !is_executable_address(above_addr as *mut c_void) {
                // TODO: Remove debug output - 上方不可执行
                println!("[DEBUG] ERROR: Above address not executable");
                return Err(HookError::UnsupportedFunction);
            }

            let above_slice = unsafe { std::slice::from_raw_parts(above_addr, MIN_HOOK_SIZE) };

            if !is_code_padding(above_slice) {
                // TODO: Remove debug output - 上方有代码
                println!("[DEBUG] ERROR: Above area contains code");
                return Err(HookError::UnsupportedFunction);
            }

            trampoline.patch_above = true;
            // TODO: Remove debug output - 使用上方补丁
            println!("[DEBUG] Using patch above area");
        }
    }

    // Create relay function (points to detour)
    let mut relay_jmp = jmp_abs;
    relay_jmp.address = trampoline.detour as u64;

    trampoline.relay =
        unsafe { (trampoline.trampoline as *mut u8).add(new_pos as usize) as *mut c_void };

    // TODO: Remove debug output - Relay函数
    println!(
        "[DEBUG] Creating relay function at 0x{:x} pointing to detour 0x{:x}",
        trampoline.relay as usize, trampoline.detour as usize
    );

    unsafe {
        ptr::copy_nonoverlapping(
            &relay_jmp as *const JmpAbs as *const u8,
            trampoline.relay as *mut u8,
            std::mem::size_of::<JmpAbs>(),
        );
    }

    // TODO: Remove debug output - 检查生成的trampoline代码
    println!("[DEBUG] Trampoline code dump:");
    unsafe {
        let code_slice =
            std::slice::from_raw_parts(trampoline.trampoline as *const u8, new_pos as usize + 14);
        for (i, chunk) in code_slice.chunks(16).enumerate() {
            print!("[DEBUG] {:04x}: ", i * 16);
            for &byte in chunk {
                print!("{:02x} ", byte);
            }
            println!();
        }
    }

    // TODO: Remove debug output - 检查relay代码
    println!("[DEBUG] Relay code dump:");
    unsafe {
        let relay_slice = std::slice::from_raw_parts(trampoline.relay as *const u8, 14);
        for &byte in relay_slice {
            print!("{:02x} ", byte);
        }
        println!();
    }

    // TODO: Remove debug output - 最终状态
    println!("[DEBUG] Trampoline creation completed:");
    println!("[DEBUG]   target: {:p}", trampoline.target);
    println!("[DEBUG]   detour: {:p}", trampoline.detour);
    println!("[DEBUG]   trampoline: {:p}", trampoline.trampoline);
    println!("[DEBUG]   relay: {:p}", trampoline.relay);
    println!("[DEBUG]   patch_above: {}", trampoline.patch_above);
    println!("[DEBUG]   n_ip: {}", trampoline.n_ip);
    print!("[DEBUG]   old_ips: [");
    for i in 0..trampoline.n_ip as usize {
        print!("{}", trampoline.old_ips[i]);
        if i < trampoline.n_ip as usize - 1 {
            print!(", ");
        }
    }
    println!("]");
    print!("[DEBUG]   new_ips: [");
    for i in 0..trampoline.n_ip as usize {
        print!("{}", trampoline.new_ips[i]);
        if i < trampoline.n_ip as usize - 1 {
            print!(", ");
        }
    }
    println!("]");

    Ok(())
}

/// Allocate and create a trampoline function
pub fn allocate_trampoline(target: *mut c_void, detour: *mut c_void) -> Result<Trampoline> {
    // TODO: Remove debug output - 分配开始
    println!(
        "[DEBUG] Allocating trampoline for target: {:p}, detour: {:p}",
        target, detour
    );

    // Allocate buffer near the target function
    let buffer = allocate_buffer(target)?;

    // TODO: Remove debug output - 缓冲区分配结果
    println!("[DEBUG] Allocated buffer at: {:p}", buffer);

    // Create trampoline structure
    let mut trampoline = Trampoline::new(target, detour, buffer);

    // Create the trampoline function
    match create_trampoline_function(&mut trampoline) {
        Ok(()) => {
            // TODO: Remove debug output - 成功
            println!("[DEBUG] Trampoline allocation and creation successful");
            Ok(trampoline)
        }
        Err(e) => {
            // TODO: Remove debug output - 失败
            println!("[DEBUG] Trampoline creation failed: {:?}", e);
            // Clean up on error
            crate::buffer::free_buffer(buffer);
            Err(e)
        }
    }
}

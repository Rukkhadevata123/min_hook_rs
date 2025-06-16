//! Genshin Impact FPS Unlocker - Rust version
//!
//! Rewritten from original C version, supports GI v4.8.0+
//!
//! Acknowledge [fpsunlock](https://codeberg.org/mkrsym1/fpsunlock)
//!
//! ## Usage
//! ```bash
//! # Build
//! cargo xwin build --example genshin_fps_unlocker --target x86_64-pc-windows-msvc --release
//!
//! # Usage (game must be already running)
//! wine genshin_fps_unlocker.exe 144
//! wine genshin_fps_unlocker.exe 144 5000  # Write every 5 seconds
//! wine genshin_fps_unlocker.exe 144 -1    # Write only once
//! ```

use std::env;
use std::mem;
use std::thread;
use std::time::Duration;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::SystemServices::*;
use windows_sys::Win32::System::Threading::*;

const GAME_EXES: &[&str] = &["GenshinImpact.exe", "YuanShen.exe"];
const ANY: i16 = -1;

// Pattern: mov ecx, 60; call setter; cmp byte
const SETTER_CALL_PATTERN: &[i16] = &[
    0xB9, 0x3C, 0x00, 0x00, 0x00, // B9 3C000000    mov ecx, 60
    0xE8, ANY, ANY, ANY, ANY,  // E8 ????????    call setter
    0x80, // 80 ?           cmp byte [x], y
];

fn try_read_memory(process: HANDLE, addr: usize, size: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; size];
    unsafe {
        let mut bytes_read = 0;
        if ReadProcessMemory(
            process,
            addr as *const _,
            buf.as_mut_ptr() as *mut _,
            size,
            &mut bytes_read,
        ) == 0
        {
            return Err(format!(
                "ReadProcessMemory failed at 0x{:x}: {}",
                addr,
                GetLastError()
            ));
        }
    }
    Ok(buf)
}

fn find_game_process() -> Result<HANDLE, String> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err("CreateToolhelp32Snapshot failed".to_string());
        }

        let mut entry: PROCESSENTRY32W = mem::zeroed();
        entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) == 0 {
            CloseHandle(snapshot);
            return Err("Process32FirstW failed".to_string());
        }

        loop {
            let exe_name = String::from_utf16_lossy(&entry.szExeFile);
            let exe_name = exe_name.trim_end_matches('\0');

            if GAME_EXES
                .iter()
                .any(|&game_exe| exe_name.eq_ignore_ascii_case(game_exe))
            {
                let process = OpenProcess(PROCESS_ALL_ACCESS, 0, entry.th32ProcessID);
                CloseHandle(snapshot);

                if process.is_null() {
                    return Err("OpenProcess failed".to_string());
                }

                return Ok(process);
            }

            if Process32NextW(snapshot, &mut entry) == 0 {
                break;
            }
        }

        CloseHandle(snapshot);
        Err("Game process not found".to_string())
    }
}

// State machine algorithm matching the C version
fn find_pattern(data: &[u8], pattern: &[i16]) -> Option<usize> {
    let mut current = 0;
    let mut pattern_pos = 0;

    while pattern_pos < pattern.len() && current < data.len() {
        if pattern[pattern_pos] == ANY || pattern[pattern_pos] as u8 == data[current] {
            pattern_pos += 1;
            current += 1;
        } else if pattern_pos != 0 {
            pattern_pos = 0;
        } else {
            current += 1;
        }
    }

    if pattern_pos == pattern.len() {
        Some(current - pattern.len())
    } else {
        None
    }
}

fn find_pattern_ex(
    process: HANDLE,
    address: usize,
    limit: usize,
    pattern: &[i16],
) -> Result<Option<usize>, String> {
    let mut current = address;
    let mut buf = vec![0u8; 0x10000];
    let mut left = limit;

    while left > pattern.len() {
        let count = if left >= buf.len() { buf.len() } else { left };
        left = left.saturating_sub(count - pattern.len());

        let data = try_read_memory(process, current, count)?;
        buf[..data.len()].copy_from_slice(&data);

        if let Some(pattern_pos) = find_pattern(&buf[..data.len()], pattern) {
            return Ok(Some(current + pattern_pos));
        }

        current += count - pattern.len();
    }

    Ok(None)
}

fn find_pattern_ex_in_module(
    process: HANDLE,
    module: usize,
    filter: u32,
    pattern: &[i16],
) -> Result<Option<usize>, String> {
    let header = try_read_memory(process, module, 0x1000)?;

    let dos_header = unsafe { &*(header.as_ptr() as *const IMAGE_DOS_HEADER) };
    let nt_headers = unsafe {
        &*(header.as_ptr().add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64)
    };
    let section_headers = unsafe {
        std::slice::from_raw_parts(
            header
                .as_ptr()
                .add(dos_header.e_lfanew as usize + mem::size_of::<IMAGE_NT_HEADERS64>())
                as *const IMAGE_SECTION_HEADER,
            nt_headers.FileHeader.NumberOfSections as usize,
        )
    };

    for section in section_headers {
        if (section.Characteristics & filter) != filter {
            continue;
        }

        let section_addr = module + section.VirtualAddress as usize;
        if let Some(pattern_pos) = find_pattern_ex(
            process,
            section_addr,
            section.SizeOfRawData as usize,
            pattern,
        )? {
            return Ok(Some(pattern_pos));
        }
    }

    Ok(None)
}

fn find_fps_var(process: HANDLE) -> Result<usize, String> {
    let executable = 0x140000000usize; // Game main module base address

    // Search for setter call pattern in executable section
    let setter_call = find_pattern_ex_in_module(
        process,
        executable,
        IMAGE_SCN_MEM_EXECUTE,
        SETTER_CALL_PATTERN,
    )?
    .ok_or("Could not find setter call")?;

    // Follow call chain
    let mut potential_mov = setter_call + 5; // Skip pattern length

    loop {
        let bytes_at_addr = try_read_memory(process, potential_mov, 6)?;

        if bytes_at_addr[0] == 0xE9 || bytes_at_addr[0] == 0xE8 {
            // jmp/call instruction, follow jump
            let offset = i32::from_le_bytes([
                bytes_at_addr[1],
                bytes_at_addr[2],
                bytes_at_addr[3],
                bytes_at_addr[4],
            ]);
            potential_mov = (potential_mov as i64 + offset as i64 + 5) as usize;
        } else {
            break;
        }
    }

    let bytes_at_addr = try_read_memory(process, potential_mov, 6)?;

    // 890D ????????    mov [fps], ecx
    if bytes_at_addr[0] != 0x89 || bytes_at_addr[1] != 0x0D {
        return Err("Could not find 'mov [fps], ecx'".to_string());
    }

    let fps_offset = i32::from_le_bytes([
        bytes_at_addr[2],
        bytes_at_addr[3],
        bytes_at_addr[4],
        bytes_at_addr[5],
    ]);

    let fps_addr = (potential_mov as i64 + 6 + fps_offset as i64) as usize;
    Ok(fps_addr)
}

fn unlock_fps(target_fps: i32, interval: i64) -> Result<(), String> {
    let game = find_game_process()?;
    let fps_addr = find_fps_var(game)?;

    // Write FPS value
    unsafe {
        let mut bytes_written = 0;
        if WriteProcessMemory(
            game,
            fps_addr as *mut _,
            &target_fps as *const _ as *const _,
            mem::size_of::<i32>(),
            &mut bytes_written,
        ) == 0
        {
            CloseHandle(game);
            return Err(format!("Failed to write FPS: {}", GetLastError()));
        }
    }

    if interval > 0 {
        // Periodic writing
        loop {
            unsafe {
                let mut bytes_written = 0;
                if WriteProcessMemory(
                    game,
                    fps_addr as *mut _,
                    &target_fps as *const _ as *const _,
                    mem::size_of::<i32>(),
                    &mut bytes_written,
                ) == 0
                {
                    // Write failed, game may have closed
                    break;
                }
            }
            thread::sleep(Duration::from_millis(interval as u64));
        }
    }

    unsafe {
        CloseHandle(game);
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let (target_fps, interval) = match args.len() {
        3 => {
            let fps = args[1].parse::<i32>().unwrap_or(0);
            let int = args[2].parse::<i64>().unwrap_or(0);
            (fps, int)
        }
        2 => {
            let fps = args[1].parse::<i32>().unwrap_or(0);
            (fps, 5000i64) // Default 5 seconds
        }
        _ => {
            eprintln!("Usage: wine fpsunlock.exe [FPS] <interval>");
            return;
        }
    };

    if target_fps < 1 {
        eprintln!("Invalid target FPS value");
        return;
    }

    if interval == 0 {
        eprintln!("Invalid interval value. Set a negative value to only write once");
        return;
    }

    match unlock_fps(target_fps, interval) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
}

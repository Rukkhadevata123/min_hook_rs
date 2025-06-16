//! 原神FPS解锁器 - Windows版本 (简化主模块版本)
//!
//! 基于简化后的C语言版本翻译，直接使用主模块
//!
//! > 感谢 https://github.com/xiaonian233/genshin-fps-unlock
//!
//! ## 使用方法
//! ```bash
//! # 编译
//! cargo build --example genshin_fps_unlocker_win --target x86_64-pc-windows-msvc --release
//!
//! # 使用
//! fps_unlocker_win.exe "C:\path\to\YuanShen.exe" 144
//! ```

use std::env;
use std::ffi::OsStr;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::thread;
use std::time::Duration;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::SystemServices::*;
use windows_sys::Win32::System::Threading::*;

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

// 翻译C语言的GetPID函数
fn get_pid_by_name(process_name: &str) -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut entry: PROCESSENTRY32W = mem::zeroed();
        entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) == 0 {
            CloseHandle(snapshot);
            return None;
        }

        loop {
            let exe_name = String::from_utf16_lossy(&entry.szExeFile);
            let exe_name = exe_name.trim_end_matches('\0');

            if exe_name.eq_ignore_ascii_case(process_name) {
                CloseHandle(snapshot);
                return Some(entry.th32ProcessID);
            }

            if Process32NextW(snapshot, &mut entry) == 0 {
                break;
            }
        }

        CloseHandle(snapshot);
        None
    }
}

// 翻译C语言的GetMainModule函数
fn get_main_module(pid: u32, module_name: &str) -> Option<(usize, u32)> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut entry: MODULEENTRY32W = mem::zeroed();
        entry.dwSize = mem::size_of::<MODULEENTRY32W>() as u32;

        if Module32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let current_module_name = String::from_utf16_lossy(&entry.szModule);
                let current_module_name = current_module_name.trim_end_matches('\0');

                if current_module_name.eq_ignore_ascii_case(module_name) {
                    CloseHandle(snapshot);
                    return Some((entry.modBaseAddr as usize, entry.modBaseSize));
                }

                if Module32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
        None
    }
}

// 翻译C语言的模式匹配算法
fn pattern_to_byte(pattern: &str) -> Vec<i32> {
    let mut bytes = Vec::new();
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '?' {
            bytes.push(-1);
            if i + 1 < chars.len() && chars[i + 1] == '?' {
                i += 1; // 跳过第二个?
            }
            i += 1;
        } else if chars[i] != ' ' {
            // 读取十六进制字节
            let mut hex_str = String::new();
            while i < chars.len() && chars[i] != ' ' && chars[i] != '?' {
                hex_str.push(chars[i]);
                i += 1;
            }
            if let Ok(byte_val) = u8::from_str_radix(&hex_str, 16) {
                bytes.push(byte_val as i32);
            }
        } else {
            i += 1; // 跳过空格
        }
    }
    bytes
}

fn pattern_scan_region(start_address: usize, region_size: usize, signature: &str) -> Option<usize> {
    let pattern_bytes = pattern_to_byte(signature);
    let scan_bytes = unsafe { std::slice::from_raw_parts(start_address as *const u8, region_size) };

    if pattern_bytes.is_empty() || pattern_bytes.len() > scan_bytes.len() {
        return None;
    }

    for i in 0..=(scan_bytes.len() - pattern_bytes.len()) {
        let mut found = true;
        for j in 0..pattern_bytes.len() {
            if pattern_bytes[j] != -1 && pattern_bytes[j] as u8 != scan_bytes[i + j] {
                found = false;
                break;
            }
        }
        if found {
            return Some(start_address + i);
        }
    }
    None
}

// 翻译C语言的LaunchGame函数
fn launch_game(game_path: &str) -> Result<(HANDLE, u32), String> {
    let game_path_wide: Vec<u16> = OsStr::new(game_path).encode_wide().chain(Some(0)).collect();
    let work_dir = Path::new(game_path).parent().unwrap();
    let work_dir_wide: Vec<u16> = work_dir.as_os_str().encode_wide().chain(Some(0)).collect();

    unsafe {
        let mut si: STARTUPINFOW = mem::zeroed();
        si.cb = mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = mem::zeroed();

        println!("Starting game...");

        if CreateProcessW(
            game_path_wide.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            0,
            std::ptr::null(),
            work_dir_wide.as_ptr(),
            &mut si,
            &mut pi,
        ) == 0
        {
            return Err(format!("CreateProcess failed: {}", GetLastError()));
        }

        CloseHandle(pi.hThread);
        println!("Game PID: {}", pi.dwProcessId);

        // 设置高优先级
        SetPriorityClass(pi.hProcess, HIGH_PRIORITY_CLASS);

        Ok((pi.hProcess, pi.dwProcessId))
    }
}

// 翻译C语言的FindFPSVariableInMainModule函数
fn find_fps_variable_in_main_module(process: HANDLE, main_base: usize) -> Result<usize, String> {
    println!("Locating FPS variable in main module...");

    // 读取PE头
    let pe_header = try_read_memory(process, main_base, 0x1000)?;

    // 解析DOS头和NT头
    let dos_header = unsafe { &*(pe_header.as_ptr() as *const IMAGE_DOS_HEADER) };
    let nt_headers = unsafe {
        &*(pe_header.as_ptr().add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64)
    };

    if nt_headers.Signature != 0x00004550 {
        return Err("Invalid PE file".to_string());
    }

    // 查找.text段
    let section_headers = unsafe {
        std::slice::from_raw_parts(
            pe_header
                .as_ptr()
                .add(dos_header.e_lfanew as usize + mem::size_of::<IMAGE_NT_HEADERS64>())
                as *const IMAGE_SECTION_HEADER,
            nt_headers.FileHeader.NumberOfSections as usize,
        )
    };

    let mut text_rva = 0;
    let mut text_size = 0;

    for section in section_headers {
        let section_name = unsafe {
            std::str::from_utf8_unchecked(std::slice::from_raw_parts(section.Name.as_ptr(), 8))
        };

        if section_name.starts_with(".text") {
            text_rva = main_base + section.VirtualAddress as usize;
            text_size = unsafe { section.Misc.VirtualSize };
            break;
        }
    }

    if text_rva == 0 {
        return Err(".text section not found".to_string());
    }

    // 读取.text段
    let text_data = try_read_memory(process, text_rva, text_size as usize)?;

    println!("Searching for FPS pattern in main executable...");

    // 在本地内存中搜索FPS模式（与C语言版本相同）
    let local_text_ptr = text_data.as_ptr() as usize;
    if let Some(pattern_offset) = pattern_scan_region(
        local_text_ptr,
        text_data.len(),
        "8B 0D ?? ?? ?? ?? 66 0F 6E C9 0F 5B C9",
    ) {
        println!("Found FPS pattern in main module");

        // 解析相对地址（与C语言版本完全相同）
        let pattern_addr = text_rva + (pattern_offset - local_text_ptr);
        let rip = pattern_addr + 2; // 跳过 mov ecx

        // 读取偏移量
        let offset_start = (pattern_offset - local_text_ptr) + 2;
        let offset_bytes = &text_data[offset_start..offset_start + 4];
        let offset = i32::from_le_bytes([
            offset_bytes[0],
            offset_bytes[1],
            offset_bytes[2],
            offset_bytes[3],
        ]);

        let fps_addr = (rip as i64 + 4 + offset as i64) as usize;
        println!("FPS variable address: 0x{:X}", fps_addr);

        return Ok(fps_addr);
    }

    Err("FPS pattern not found - game version may not be supported".to_string())
}

fn format_current_time() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let total_secs = now.as_secs();
    let local_secs = total_secs % 86400; // 今日秒数
    let hours = (local_secs / 3600) % 24;
    let minutes = (local_secs / 60) % 60;
    let seconds = local_secs % 60;

    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

fn unlock_fps_main_module(game_path: &str, target_fps: i32) -> Result<(), String> {
    // 检查游戏文件是否存在
    if !Path::new(game_path).exists() {
        return Err("Game file not found".to_string());
    }

    let game_exe = Path::new(game_path).file_name().unwrap().to_str().unwrap();

    // 检查游戏是否已经在运行
    if get_pid_by_name(game_exe).is_some() {
        return Err("Game is already running! Please close it first.".to_string());
    }

    // 启动游戏
    let (process_handle, launched_pid) = launch_game(game_path)?;
    thread::sleep(Duration::from_millis(200));

    // 只等待主模块 - 简化逻辑（对照C语言版本）
    println!("Waiting for main module...");
    let mut main_base = None;
    let mut main_size = 0;

    for _ in 0..2000 {
        // 10000 / 5 = 2000次检查
        if let Some((base, size)) = get_main_module(launched_pid, game_exe) {
            main_base = Some(base);
            main_size = size;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    let main_base = main_base.ok_or("Main module timeout")?;

    if main_base == 0 {
        unsafe {
            CloseHandle(process_handle);
        }
        return Err("Invalid main module address".to_string());
    }

    println!(
        "Main module: {} at 0x{:X} (Size: 0x{:X})",
        game_exe, main_base, main_size
    );

    // 直接在主模块中查找FPS变量
    let fps_addr = find_fps_variable_in_main_module(process_handle, main_base)?;
    println!("Target FPS: {}", target_fps);

    // 初始设置FPS
    unsafe {
        let mut bytes_written = 0;
        if WriteProcessMemory(
            process_handle,
            fps_addr as *mut _,
            &target_fps as *const _ as *const _,
            mem::size_of::<i32>(),
            &mut bytes_written,
        ) == 0
        {
            CloseHandle(process_handle);
            return Err(format!("Failed to set FPS: {}", GetLastError()));
        }
    }

    println!("FPS unlocked successfully!");
    println!("Monitoring (Press Ctrl+C to exit):\n");

    // 监控循环（完全对照C语言版本）
    unsafe {
        let mut exit_code = STILL_ACTIVE;
        let mut counter = 0;

        while exit_code == STILL_ACTIVE {
            GetExitCodeProcess(process_handle, &mut exit_code as *mut _ as *mut u32);
            thread::sleep(Duration::from_secs(2));

            counter += 1;

            // 每2秒直接重写FPS值（与C语言版本完全相同）
            let mut bytes_written = 0;
            if WriteProcessMemory(
                process_handle,
                fps_addr as *mut _,
                &target_fps as *const _ as *const _,
                mem::size_of::<i32>(),
                &mut bytes_written,
            ) != 0
            {
                let time_str = format_current_time();
                print!(
                    "[{}] FPS maintained: {} (Check #{})\r",
                    time_str, target_fps, counter
                );
                std::io::Write::flush(&mut std::io::stdout()).unwrap();
            } else {
                println!("\nWarning: Failed to maintain FPS");
            }
        }

        CloseHandle(process_handle);
    }

    println!("\nGame process ended");
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    println!("Genshin Impact FPS Unlocker - Main Module Version");
    println!("Based on simplified C implementation\n");

    if args.len() != 3 {
        eprintln!("Usage: {} <GamePath> <FPS>", args[0]);
        eprintln!("Example: {} \"C:\\Games\\YuanShen.exe\" 144", args[0]);
        return;
    }

    let game_path = &args[1];
    let target_fps = match args[2].parse::<i32>() {
        Ok(f) if f >= 30 && f <= 1000 => f,
        _ => {
            eprintln!("Error: FPS must be between 30-1000");
            return;
        }
    };

    match unlock_fps_main_module(game_path, target_fps) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Error: {}", e);
            eprintln!("Note: This program requires administrator privileges.");
        }
    }
}

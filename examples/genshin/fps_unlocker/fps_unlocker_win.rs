//! Genshin Impact FPS Unlocker - Windows Simple version
//!
//! Simplified version without shellcode injection (first stage only)
//! Based on C++ version with exact behavior replication (stage 1)
//!
//! Acknowledge https://github.com/xiaonian233/genshin-fps-unlock
//! Special thanks to winTEuser for pattern implementation

use std::env;
use std::mem;
use std::path::Path;
use std::ptr;
use std::thread;
use std::time::Duration;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

// Pattern search - credit by winTEuser
fn pattern_scan_region(start_address: usize, region_size: usize, signature: &str) -> Option<usize> {
    let pattern_to_byte = |pattern: &str| -> Vec<i32> {
        let mut bytes = Vec::new();
        let chars: Vec<char> = pattern.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            if chars[i] == '?' {
                bytes.push(-1);
                if i + 1 < chars.len() && chars[i + 1] == '?' {
                    i += 1;
                }
                i += 1;
            } else if chars[i] != ' ' {
                let mut hex_str = String::new();
                while i < chars.len() && chars[i] != ' ' && chars[i] != '?' {
                    hex_str.push(chars[i]);
                    i += 1;
                }
                if let Ok(byte_val) = u8::from_str_radix(&hex_str, 16) {
                    bytes.push(byte_val as i32);
                }
            } else {
                i += 1;
            }
        }
        bytes
    };

    let pattern_bytes = pattern_to_byte(signature);
    let scan_bytes = unsafe { std::slice::from_raw_parts(start_address as *const u8, region_size) };

    for i in 0..=scan_bytes.len().saturating_sub(pattern_bytes.len()) {
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

fn get_last_error_string(error_code: u32) -> String {
    if error_code == 0 {
        return "Success".to_string();
    }

    unsafe {
        let mut buffer: *mut u8 = ptr::null_mut();
        let size = FormatMessageA(
            0x00001000 | 0x00000200, // FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
            ptr::null(),
            error_code,
            0,
            &mut buffer as *mut _ as *mut u8,
            0,
            ptr::null(),
        );

        if size == 0 {
            return format!("Unknown error {}", error_code);
        }

        let slice = std::slice::from_raw_parts(buffer, size as usize);
        let result = String::from_utf8_lossy(slice).trim().to_string();
        LocalFree(buffer as *mut _);
        result
    }
}

// Search process ID by process name
fn get_pid(process_name: &str) -> Option<u32> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut entry: PROCESSENTRY32W = mem::zeroed();
        entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let exe_name = String::from_utf16_lossy(&entry.szExeFile);
                let exe_name = exe_name.trim_end_matches('\0');

                if exe_name == process_name {
                    let pid = entry.th32ProcessID;
                    CloseHandle(snapshot);
                    return Some(pid);
                }

                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);
        None
    }
}

fn get_module(pid: u32, module_name: &str) -> Option<(usize, u32)> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut entry: MODULEENTRY32W = mem::zeroed();
        entry.dwSize = mem::size_of::<MODULEENTRY32W>() as u32;

        if Module32FirstW(snapshot, &mut entry) != 0 {
            loop {
                if entry.th32ProcessID != pid {
                    break;
                }

                let current_module_name = String::from_utf16_lossy(&entry.szModule);
                let current_module_name = current_module_name.trim_end_matches('\0');

                if current_module_name == module_name {
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

fn format_current_time() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let total_secs = now.as_secs();
    let local_secs = total_secs % 86400;
    let hours = (local_secs / 3600) % 24;
    let minutes = (local_secs / 60) % 60;
    let seconds = local_secs % 60;

    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

fn main() {
    let args: Vec<String> = env::args().collect();

    println!("FPS Unlocker(Simple) - If helpful please star the repos!");
    println!("https://github.com/Rukkhadevata123/min_hook_rs");
    println!("https://github.com/xiaonian233/genshin-fps-unlock");

    if args.len() != 3 {
        eprintln!("Usage: {} <GamePath> <FPS>", args[0]);
        eprintln!("Example: {} \"C:\\Games\\YuanShen.exe\" 144", args[0]);
        std::process::exit(1);
    }

    let game_path = &args[1];
    let target_fps = match args[2].parse::<i32>() {
        Ok(f) if (60..=240).contains(&f) => f,
        _ => {
            eprintln!("Error: FPS must be between 60-240");
            std::process::exit(1);
        }
    };

    let process_path = game_path.as_str();
    let process_dir = Path::new(process_path).parent().unwrap().to_str().unwrap();
    let procname = Path::new(process_path)
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();

    if process_path.len() < 8 {
        std::process::exit(1);
    }

    println!("Game path: {}\n", process_path);

    let pid = get_pid(procname);
    if pid.is_some() {
        println!("Game is already running!");
        println!("Manually starting the game will cause it to fail");
        println!("Please manually close the game - unlocker will auto-start the game");
        std::process::exit(1);
    }

    // Start game process
    let process_path_cstr = std::ffi::CString::new(process_path).unwrap();
    let process_dir_cstr = std::ffi::CString::new(process_dir).unwrap();

    unsafe {
        let mut si: STARTUPINFOA = mem::zeroed();
        si.cb = mem::size_of::<STARTUPINFOA>() as u32;
        let mut pi: PROCESS_INFORMATION = mem::zeroed();

        if CreateProcessA(
            process_path_cstr.as_ptr() as *const u8,
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            0, // FALSE
            0,
            ptr::null(),
            process_dir_cstr.as_ptr() as *const u8,
            &si,
            &mut pi,
        ) == 0
        {
            let code = GetLastError();
            println!(
                "CreateProcess failed ({}): {}",
                code,
                get_last_error_string(code)
            );
            std::process::exit(1);
        }

        CloseHandle(pi.hThread);
        println!("Game PID: {}", pi.dwProcessId);
        thread::sleep(Duration::from_millis(200));
        SetPriorityClass(pi.hProcess, HIGH_PRIORITY_CLASS);

        // Wait for main module to load and get module info
        println!("Waiting for main module...");
        let mut h_main_module = None;
        let mut times = 2000;
        while times != 0 {
            if let Some((base, size)) = get_module(pi.dwProcessId, procname) {
                h_main_module = Some((base, size));
                break;
            }
            thread::sleep(Duration::from_millis(50));
            times -= 5;
        }

        let (main_base, main_size) = match h_main_module {
            Some((base, size)) => (base, size),
            None => {
                println!("Main module timeout!");
                CloseHandle(pi.hProcess);
                std::process::exit(-1);
            }
        };

        println!(
            "Main module: {} at 0x{:X} (Size: 0x{:X})",
            procname, main_base, main_size
        );

        let mbase_pe_buffer = VirtualAlloc(
            ptr::null(),
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if mbase_pe_buffer.is_null() {
            println!("VirtualAlloc Failed! (PE_buffer)");
            CloseHandle(pi.hProcess);
            std::process::exit(-1);
        }

        if main_base == 0 {
            std::process::exit(-1);
        }

        let mut bytes_read = 0;
        if ReadProcessMemory(
            pi.hProcess,
            main_base as *const _,
            mbase_pe_buffer,
            0x1000,
            &mut bytes_read,
        ) == 0
        {
            println!("ReadProcessMemory Failed! (PE_buffer)");
            VirtualFree(mbase_pe_buffer, 0, MEM_RELEASE);
            CloseHandle(pi.hProcess);
            std::process::exit(-1);
        }

        // Find .text section
        let search_sec = b".text\0\0\0"; //max 8 byte
        let tar_sec = u64::from_le_bytes([
            search_sec[0],
            search_sec[1],
            search_sec[2],
            search_sec[3],
            search_sec[4],
            search_sec[5],
            search_sec[6],
            search_sec[7],
        ]);

        let win_pe_file_va = (mbase_pe_buffer as usize) + 0x3c; //dos_header
        let pe_fptr = (mbase_pe_buffer as usize) + *(win_pe_file_va as *const u32) as usize; //get_winPE_VA
        let file_pe_nt_header = *(pe_fptr as *const IMAGE_NT_HEADERS64);

        let mut text_remote_rva = 0;
        let mut text_vsize = 0;

        if file_pe_nt_header.Signature == 0x00004550 {
            let sec_num = file_pe_nt_header.FileHeader.NumberOfSections; //Get specified section parameters
            let mut num = sec_num;

            while num > 0 {
                let sec_temp = *((pe_fptr + 264 + (40 * ((sec_num - num) as usize)))
                    as *const IMAGE_SECTION_HEADER);

                if *(sec_temp.Name.as_ptr() as *const u64) == tar_sec {
                    text_remote_rva = main_base + sec_temp.VirtualAddress as usize;
                    text_vsize = sec_temp.Misc.VirtualSize;
                    break;
                }
                num -= 1;
            }
        } else {
            println!("Invalid PE header!");
            VirtualFree(mbase_pe_buffer, 0, MEM_RELEASE);
            CloseHandle(pi.hProcess);
            std::process::exit(-1);
        }

        if text_remote_rva == 0 {
            println!("Invalid PE header!");
            VirtualFree(mbase_pe_buffer, 0, MEM_RELEASE);
            CloseHandle(pi.hProcess);
            std::process::exit(-1);
        }

        // Allocate memory for code section in current process - for pattern search
        let copy_text_va = VirtualAlloc(
            ptr::null(),
            text_vsize as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if copy_text_va.is_null() {
            println!("VirtualAlloc Failed! (Text)");
            CloseHandle(pi.hProcess);
            std::process::exit(-1);
        }

        // Read the entire module
        let mut bytes_read = 0;
        if ReadProcessMemory(
            pi.hProcess,
            text_remote_rva as *const _,
            copy_text_va,
            text_vsize as usize,
            &mut bytes_read,
        ) == 0
        {
            println!("ReadProcessMemory Failed! (text)");
            VirtualFree(copy_text_va, 0, MEM_RELEASE);
            CloseHandle(pi.hProcess);
            std::process::exit(-1);
        }

        println!("Locating FPS variable in main module...");

        //credit by winTEuser
        let address = pattern_scan_region(
            copy_text_va as usize,
            text_vsize as usize,
            "8B 0D ?? ?? ?? ?? 66 0F 6E C9 0F 5B C9",
        );

        if address.is_none() {
            println!("FPS pattern not found - game version may not be supported");
            std::process::exit(1);
        }

        // Calculate relative address (FPS)
        let pfps = {
            let mut rip = address.unwrap();
            rip += 2;
            rip += *(rip as *const i32) as usize + 4;
            rip - (copy_text_va as usize) + text_remote_rva
        };

        println!("FPS variable address: 0x{:X}", pfps);

        // Simple version: No shellcode injection, direct write only
        VirtualFree(mbase_pe_buffer, 0, MEM_RELEASE);
        VirtualFree(copy_text_va, 0, MEM_RELEASE);
        println!("FPS unlocked successfully! (Simple version - direct write only)");
        println!("Monitoring (Press Ctrl+C to exit):\n");

        let mut dw_exit_code = STILL_ACTIVE;
        let mut counter = 0;

        while dw_exit_code == STILL_ACTIVE {
            GetExitCodeProcess(pi.hProcess, &mut dw_exit_code as *mut _ as *mut u32);

            // Check every two seconds
            thread::sleep(Duration::from_secs(2));
            counter += 1;

            let mut fps = 0i32;
            let mut bytes_read = 0;
            if ReadProcessMemory(
                pi.hProcess,
                pfps as *const _,
                &mut fps as *mut _ as *mut _,
                mem::size_of::<i32>(),
                &mut bytes_read,
            ) != 0
            {
                // Successfully read FPS value
                let time_str = format_current_time();

                if fps == -1 {
                    print!("[{}] FPS reading skipped (Check #{})\r", time_str, counter);
                    use std::io::Write;
                    std::io::stdout().flush().unwrap();
                    continue;
                }

                if fps != target_fps {
                    println!(
                        "\n[{}] FPS changed detected ({} -> {}), resetting...",
                        time_str, fps, target_fps
                    );

                    let mut bytes_written = 0;
                    WriteProcessMemory(
                        pi.hProcess,
                        pfps as *mut _,
                        &target_fps as *const _ as *const _,
                        mem::size_of::<i32>(),
                        &mut bytes_written,
                    );
                } else {
                    // Display current FPS status
                    print!(
                        "[{}] FPS maintained: {} (Check #{})\r",
                        time_str, fps, counter
                    );
                    use std::io::Write;
                    std::io::stdout().flush().unwrap();
                }
            } else {
                // Read failure warning
                let time_str = format_current_time();
                println!(
                    "\n[{}] Warning: Failed to read FPS value (Check #{}): {}",
                    time_str,
                    counter,
                    GetLastError()
                );
            }
        }

        println!("\nGame process ended");
        CloseHandle(pi.hProcess);
        TerminateProcess(0xFFFFFFFFFFFFFFFF as HANDLE, 0);
    }
}

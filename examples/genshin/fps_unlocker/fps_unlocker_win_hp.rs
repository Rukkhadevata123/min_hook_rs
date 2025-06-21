//! Genshin Impact FPS Unlocker - Windows High Performance version
//!
//! Enhanced version with dual-write mechanism and shellcode injection
//! Based on C++ version with exact behavior replication
//!
//! Acknowledge https://github.com/xiaonian233/genshin-fps-unlock
//! Special thanks to winTEuser for shellcode implementation

use std::env;
use std::mem;
use std::path::Path;
use std::ptr;
use std::thread;
use std::time::Duration;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

// credit by winTEuser
const SHELLCODE_GENSHIN_CONST: &[u8] = &[
    0x00, 0x00, 0x00, 0x00, //uint32_t unlocker_pid              _shellcode_genshin[0]
    0x00, 0xC0, 0x9C,
    0x66, //uint32_t shellcode_timestamp       _shellcode_genshin[4]  //2024-07-21 16:00:00
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, //uint64_t unlocker_FpsValue_addr    _shellcode_genshin[8]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, //uint64_t API_OpenProcess           _shellcode_genshin[16]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, //uint64_t API_ReadProcessmem        _shellcode_genshin[24]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, //uint64_t API_Sleep                 _shellcode_genshin[32]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, //uint64_t API_MessageBoxA           _shellcode_genshin[40]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, //uint64_t API_CloseHandle           _shellcode_genshin[48]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, //FREE                               _shellcode_genshin[56]
    //int3
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    //int3
    0x48, 0x83, 0xEC,
    0x38, //sub rsp,0x38                              _shellcode_genshin[80] _sync_thread
    0x8B, 0x05, 0xA6, 0xFF, 0xFF, 0xFF, //mov eax,dword[unlocker_pid]
    0x85, 0xC0, //test eax, eax
    0x74, 0x5C, //jz return
    0x41, 0x89, 0xC0, //mov r8d, eax
    0x33, 0xD2, //xor edx, edx
    0xB9, 0xFF, 0xFF, 0x1F, 0x00, //mov ecx,1FFFFF
    0xFF, 0x15, 0xA2, 0xFF, 0xFF, 0xFF, //call [API_OpenProcess]
    0x85, 0xC0, //test eax, eax
    0x74, 0x48, //jz return
    0x89, 0xC6, //mov esi, eax
    0x48, 0x8B, 0x3D, 0x8D, 0xFF, 0xFF, 0xFF, //mov rdi,qword[unlocker_FpsValue_addr]
    0x0F, 0x1F, 0x44, 0x00, 0x00, //nop
    0x89, 0xF1, //mov ecx, esi          //Read_tar_fps
    0x48, 0x89, 0xFA, //mov rdx, rdi
    0x4C, 0x8D, 0x05, 0x08, 0x01, 0x00, 0x00, //lea r8, qword:[Readmem_buffer]
    0x41, 0xB9, 0x04, 0x00, 0x00, 0x00, //mov r9d, 4
    0x31, 0xC0, //xor eax, eax
    0x48, 0x89, 0x44, 0x24, 0x20, //mov qword ptr ss:[rsp+20],rax
    0xFF, 0x15, 0x79, 0xFF, 0xFF, 0xFF, //call [API_ReadProcessmem]
    0x85, 0xC0, //test eax, eax
    0x74, 0x12, //jz Show msg and closehandle
    0xB9, 0xF4, 0x01, 0x00, 0x00, //mov ecx,0x1F4     (500ms)
    0xFF, 0x15, 0x72, 0xFF, 0xFF, 0xFF, //call [API_Sleep]
    0xE8, 0x5D, 0x00, 0x00, 0x00, //call Sync_auto
    0xEB, 0xCB, //jmp Read_tar_fps
    0xE8, 0x76, 0x00, 0x00, 0x00, //call Show Errormsg and CloseHandle
    0x48, 0x83, 0xC4, 0x38, //add rsp,0x38
    0xC3, //return
    //int3
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, //int3
    0x89, 0x0D, 0xBA, 0x00, 0x00,
    0x00, //mov [Game_Current_set], ecx           //hook_fps_set      _shellcode_genshin[0xD0]
    0x31, 0xC0, //xor eax, eax
    0x83, 0xF9, 0x1E, //cmp ecx, 0x1E
    0x74, 0x0E, //je set 60
    0x83, 0xF9, 0x2D, //cmp ecx, 0x2D
    0x74, 0x15, //je Sync_buffer
    0x2E, 0xB9, 0xE8, 0x03, 0x00, 0x00, //mov ecx, 0x3E8
    0xEB, 0x06, //jmp set
    0xCC, //int3
    0xB9, 0x3C, 0x00, 0x00, 0x00, //mov ecx, 0x3C
    0x89, 0x0D, 0x0B, 0x00, 0x00, 0x00, //mov [hook_fps_get+1], ecx        //set
    0xC3, //ret
    0x8B, 0x0D, 0x97, 0x00, 0x00, 0x00, //mov ecx, dword[Readmem_buffer]   //Sync_buffer
    0xEB, 0xF1, //jmp set
    0xCC, //int3
    0xB8, 0x78, 0x00, 0x00,
    0x00, //mov eax,0x78                          //hook_fps_get      _shellcode_genshin[0xF0]
    0xC3, //ret
    //int3
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //int3
    0x8B, 0x05, 0x7A, 0x00, 0x00, 0x00, //mov eax, dword[Game_Current_set]      //Sync_auto
    0x83, 0xF8, 0x2D, //cmp eax, 0x2D
    0x75, 0x0C, //jne return
    0x8B, 0x05, 0x73, 0x00, 0x00, 0x00, //mov eax, dword[Readmem_buffer]
    0x89, 0x05, 0xDA, 0xFF, 0xFF, 0xFF, //mov dword[hook_fps_get + 1], eax
    0xC3, //ret
    //int3
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, //int3
    0x48, 0x83, 0xEC,
    0x28, //sub rsp, 0x28                        //Show Errormsg and closehandle
    0x31, 0xC9, //xor ecx, ecx
    0x48, 0x8D, 0x15, 0x33, 0x00, 0x00, 0x00, //lea rdx, qword:["Sync failed!"]
    0x4C, 0x8D, 0x05, 0x3C, 0x00, 0x00, 0x00, //lea r8, qword:["Error"]
    0x41, 0xB9, 0x10, 0x00, 0x00, 0x00, //mov r9d, 0x10
    0xFF, 0x15, 0xD8, 0xFE, 0xFF, 0xFF, //call [API_MessageBoxA]
    0x89, 0xF1, //mov ecx, esi
    0xFF, 0x15, 0xD8, 0xFE, 0xFF, 0xFF, //call [API_CloseHandle]
    0x48, 0x83, 0xC4, 0x28, //add rsp, 0x28
    0xC3, //ret
    //int3
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, b'S', b'y', b'n', b'c', b' ', b'f', b'a', b'i', b'l', b'e', b'd', b'!', 0x00,
    0x00, 0x00, 0x00, b'E', b'r', b'r', b'o', b'r', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //uint32_t Game_Current_set
    0x00, 0x00, 0x00, 0x00, //uint32_t Readmem_buffer
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

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
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;

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
        entry.dwSize = size_of::<MODULEENTRY32W>() as u32;

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

//Hotpatch
fn inject_patch(
    text_buffer: *const u8,
    text_size: u32,
    text_baseaddr: usize,
    ptr_fps: usize,
    tar_handle: HANDLE,
    fps_value: &i32,
) -> usize {
    if text_buffer.is_null()
        || text_size == 0
        || text_baseaddr == 0
        || ptr_fps == 0
        || tar_handle.is_null()
    {
        return 0;
    }

    unsafe {
        let shellcode_buffer = VirtualAlloc(
            ptr::null(),
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if shellcode_buffer.is_null() {
            println!("Buffer Alloc Fail!");
            return 0;
        }

        ptr::copy_nonoverlapping(
            SHELLCODE_GENSHIN_CONST.as_ptr(),
            shellcode_buffer as *mut u8,
            SHELLCODE_GENSHIN_CONST.len(),
        );

        let addr_open_process = OpenProcess as *const () as u64;
        let addr_read_process_mem = ReadProcessMemory as *const () as u64;
        let addr_sleep = Sleep as *const () as u64;
        let addr_message_box_a = {
            let user32 = LoadLibraryA(b"user32.dll\0".as_ptr());
            if !user32.is_null() {
                let addr = GetProcAddress(user32, b"MessageBoxA\0".as_ptr());
                FreeLibrary(user32);
                addr.map(|a| a as *const () as u64).unwrap_or(0)
            } else {
                0u64
            }
        };
        let addr_close_handle = CloseHandle as *const () as u64;

        *(shellcode_buffer as *mut u32) = GetCurrentProcessId(); //unlocker PID
        *((shellcode_buffer as usize + 8) as *mut u64) = fps_value as *const i32 as u64; //unlocker fps ptr
        *((shellcode_buffer as usize + 16) as *mut u64) = addr_open_process;
        *((shellcode_buffer as usize + 24) as *mut u64) = addr_read_process_mem;
        *((shellcode_buffer as usize + 32) as *mut u64) = addr_sleep;
        *((shellcode_buffer as usize + 40) as *mut u64) = addr_message_box_a;
        *((shellcode_buffer as usize + 48) as *mut u64) = addr_close_handle;
        *((shellcode_buffer as usize + 0xE4) as *mut u32) = 1000;
        *((shellcode_buffer as usize + 0xEC) as *mut u32) = 60;

        *((shellcode_buffer as usize + 0x110) as *mut u64) = 0xB848; //mov rax, game_pfps
        *((shellcode_buffer as usize + 0x118) as *mut u64) = 0x741D8B0000; //mov ebx, dword[Readmem_buffer]
        *((shellcode_buffer as usize + 0x120) as *mut u64) = 0xCCCCCCCCCCC31889; //mov [rax], ebx 
        *((shellcode_buffer as usize + 0x112) as *mut u64) = ptr_fps as u64; //ret
        *((shellcode_buffer as usize + 0x15C) as *mut u64) = 0x5C76617E8834858; //keep thread
        *((shellcode_buffer as usize + 0x164) as *mut u64) = 0xE0FF21EBFFFFFF16;

        let tar_proc_buffer = VirtualAllocEx(
            tar_handle,
            ptr::null(),
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if !tar_proc_buffer.is_null() {
            let mut bytes_written = 0;
            if WriteProcessMemory(
                tar_handle,
                tar_proc_buffer,
                shellcode_buffer,
                SHELLCODE_GENSHIN_CONST.len(),
                &mut bytes_written,
            ) != 0
            {
                VirtualFree(shellcode_buffer, 0, MEM_RELEASE);
                let temp = CreateRemoteThread(
                    tar_handle,
                    ptr::null(),
                    0,
                    Some(std::mem::transmute(
                        (tar_proc_buffer as usize + 0x50) as *const (),
                    )),
                    ptr::null(),
                    0,
                    ptr::null_mut(),
                );
                if !temp.is_null() {
                    CloseHandle(temp);
                } else {
                    println!("Create InGame SyncThread Fail!");
                    return 0;
                }
                return tar_proc_buffer as usize + 0x194;
            }
            println!("Inject shellcode Fail!");
            VirtualFree(shellcode_buffer, 0, MEM_RELEASE);
            return 0;
        } else {
            println!("Alloc shellcode space Fail!");
            return 0;
        }
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

    println!("FPS Unlocker - If helpful please star the repos!");
    println!("https://github.com/Rukkhadevata123/min_hook_rs");
    println!("https://github.com/xiaonian233/genshin-fps-unlock");
    println!("Special thanks to winTEuser\n");

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
                break; // goto __get_procbase_ok;
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
                    break; // goto __Get_target_sec;
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

        let patch_ptr = inject_patch(
            copy_text_va as *const u8,
            text_vsize,
            text_remote_rva,
            pfps,
            pi.hProcess,
            &target_fps,
        ); //patch inject 

        if patch_ptr == 0 {
            println!("Inject Patch Fail!\n");
        }

        VirtualFree(mbase_pe_buffer, 0, MEM_RELEASE);
        VirtualFree(copy_text_va, 0, MEM_RELEASE);
        println!("FPS unlocked successfully!");
        println!("Monitoring (Press Ctrl+C to exit):\n");

        let mut dw_exit_code = STILL_ACTIVE;
        let mut counter = 0; // Add counter

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
                // Successfully read FPS value - add timestamp display
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
                    //Hot patch loop
                    WriteProcessMemory(
                        pi.hProcess,
                        patch_ptr as *mut _,
                        &target_fps as *const _ as *const _,
                        4,
                        &mut bytes_written,
                    );
                } else {
                    // Display current FPS status (similar to C version)
                    print!(
                        "[{}] FPS maintained: {} (Check #{})\r",
                        time_str, fps, counter
                    );
                    use std::io::Write;
                    std::io::stdout().flush().unwrap();
                }
            } else {
                // Read failure warning (similar to C version)
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

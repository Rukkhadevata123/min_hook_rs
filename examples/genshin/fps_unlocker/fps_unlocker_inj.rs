//! Genshin Impact FPS Unlocker - DLL injection version (injector)
//!
//! Uses SetWindowsHookEx injection, completely based on C# version logic
//!
//! Acknowledge https://github.com/34736384/genshin-fps-unlock

use std::env;
use std::ffi::{CString, OsStr};
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::thread;
use std::time::Duration;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::SystemServices::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;
use windows_sys::core::BOOL;

// IPC data structure (completely consistent with C#)
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy)]
struct IpcData {
    address: u64,
    value: i32,
    status: i32,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum IpcStatus {
    Error = -1,
    #[allow(dead_code)]
    None = 0,
    HostAwaiting = 1,
    ClientReady = 2,
    ClientExit = 3,
    HostExit = 4,
}

const IPC_GUID: &str = "2DE95FDC-6AB7-4593-BFE6-760DD4AB422B";

// Launch game process
fn launch_game(game_path: &str) -> Result<(HANDLE, u32, HANDLE), String> {
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
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            0,
            CREATE_SUSPENDED,
            ptr::null(),
            work_dir_wide.as_ptr(),
            &si,
            &mut pi,
        ) == 0
        {
            return Err(format!("CreateProcess failed: {}", GetLastError()));
        }

        println!("Game PID: {}", pi.dwProcessId);
        Ok((pi.hProcess, pi.dwProcessId, pi.hThread))
    }
}

// Get main module
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

// Wait for main module to load
fn wait_for_main_module(pid: u32, game_exe: &str) -> Result<(usize, u32), String> {
    println!("Waiting for main module...");

    for _ in 0..2000 {
        if let Some((base, size)) = get_main_module(pid, game_exe) {
            if base != 0 {
                println!(
                    "Main module: {} at 0x{:X} (Size: 0x{:X})",
                    game_exe, base, size
                );
                return Ok((base, size));
            }
        }
        thread::sleep(Duration::from_millis(50));
    }

    Err("Main module timeout".to_string())
}

// Memory reading
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

// Pattern search
fn pattern_to_byte(pattern: &str) -> Vec<i32> {
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

// Find FPS variable
fn find_fps_variable_in_main_module(process: HANDLE, main_base: usize) -> Result<usize, String> {
    println!("Locating FPS variable in main module...");

    // Read PE header
    let pe_header = try_read_memory(process, main_base, 0x1000)?;
    let dos_header = unsafe { &*(pe_header.as_ptr() as *const IMAGE_DOS_HEADER) };
    let nt_headers = unsafe {
        &*(pe_header.as_ptr().add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64)
    };

    if nt_headers.Signature != 0x00004550 {
        return Err("Invalid PE file".to_string());
    }

    // Find .text section
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

    // Read .text section and search for FPS pattern
    let text_data = try_read_memory(process, text_rva, text_size as usize)?;
    println!("Searching for FPS pattern in main executable...");

    let local_text_ptr = text_data.as_ptr() as usize;
    if let Some(pattern_offset) = pattern_scan_region(
        local_text_ptr,
        text_data.len(),
        "8B 0D ?? ?? ?? ?? 66 0F 6E C9 0F 5B C9",
    ) {
        println!("Found FPS pattern in main module");

        // Parse relative address
        let pattern_addr = text_rva + (pattern_offset - local_text_ptr);
        let rip = pattern_addr + 2; // Skip mov ecx

        // Read offset
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

// Create IPC shared memory
fn create_ipc(fps_addr: u64, target_fps: i32) -> Result<HANDLE, String> {
    let ipc_guid = CString::new(IPC_GUID).unwrap();

    unsafe {
        let file_mapping = CreateFileMappingA(
            INVALID_HANDLE_VALUE,
            ptr::null(),
            PAGE_READWRITE,
            0,
            4096,
            ipc_guid.as_ptr() as *const u8,
        );

        if file_mapping.is_null() {
            return Err(format!("CreateFileMapping failed: {}", GetLastError()));
        }

        let view = MapViewOfFile(file_mapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if view.Value.is_null() {
            CloseHandle(file_mapping);
            return Err(format!("MapViewOfFile failed: {}", GetLastError()));
        }

        // Initialize IPC data
        let ipc_data = IpcData {
            address: fps_addr,
            value: target_fps,
            status: IpcStatus::HostAwaiting as i32,
        };

        ptr::copy_nonoverlapping(&ipc_data, view.Value as *mut IpcData, 1);
        UnmapViewOfFile(view);

        println!("IPC created successfully");
        Ok(file_mapping)
    }
}

// Wait for game window (with process monitoring)
fn wait_for_game_window(process_id: u32, process_handle: HANDLE) -> Result<HWND, String> {
    println!("Waiting for game window...");

    for attempt in 1..=300 {
        // 30 second timeout
        unsafe {
            let mut exit_code = STILL_ACTIVE as u32;
            if GetExitCodeProcess(process_handle, &mut exit_code) != 0
                && exit_code != STILL_ACTIVE as u32
            {
                return Err("Game process exited while waiting for window".to_string());
            }

            let mut context = WindowSearchContext {
                target_pid: process_id,
                found_window: ptr::null_mut(),
            };

            EnumWindows(Some(enum_windows_proc), &mut context as *mut _ as isize);

            if !context.found_window.is_null() {
                println!(
                    "Found game window on attempt {}: 0x{:X}",
                    attempt, context.found_window as usize
                );
                return Ok(context.found_window);
            }

            if attempt % 30 == 0 {
                println!("Still waiting for window... (attempt {})", attempt);
            }

            thread::sleep(Duration::from_millis(100));
        }
    }

    Err("Game window not found after 30 seconds".to_string())
}

#[repr(C)]
struct WindowSearchContext {
    target_pid: u32,
    found_window: HWND,
}

unsafe extern "system" fn enum_windows_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let context = unsafe { &mut *(lparam as *mut WindowSearchContext) };

    let mut pid = 0u32;
    unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };

    if pid == context.target_pid {
        // Find Unity game window (visible or hidden, as it will become visible)
        let mut class_name = [0u16; 256];
        let len = unsafe { GetClassNameW(hwnd, class_name.as_mut_ptr(), class_name.len() as i32) };
        if len > 0 {
            let class_str = String::from_utf16_lossy(&class_name[..len as usize]);
            if class_str == "UnityWndClass" {
                context.found_window = hwnd;
                return FALSE; // Stop enumeration
            }
        }
    }

    TRUE // Continue enumeration
}

fn inject_dll_with_hook(
    process_id: u32,
    process_handle: HANDLE,
    dll_path: &str,
) -> Result<(HMODULE, HHOOK), String> {
    unsafe {
        // 1. Load DLL into current process
        let dll_path_wide: Vec<u16> = OsStr::new(dll_path).encode_wide().chain(Some(0)).collect();
        let stub_module = LoadLibraryW(dll_path_wide.as_ptr());
        if stub_module.is_null() {
            return Err(format!("Failed to load stub module: {}", GetLastError()));
        }

        // 2. Get WndProc function address
        let stub_wnd_proc = GetProcAddress(stub_module, c"WndProc".as_ptr() as *const u8);
        if stub_wnd_proc.is_none() {
            FreeLibrary(stub_module);
            return Err("Failed to get WndProc address".to_string());
        }

        // 3. Wait for game window
        let target_window = wait_for_game_window(process_id, process_handle)?;

        // 4. Get window thread ID
        let thread_id = GetWindowThreadProcessId(target_window, ptr::null_mut());
        if thread_id == 0 {
            FreeLibrary(stub_module);
            return Err("Failed to get window thread ID".to_string());
        }

        println!("Game window found, thread ID: {}", thread_id);

        // 5. Set window hook
        let wnd_hook = SetWindowsHookExW(
            WH_GETMESSAGE,
            Some(std::mem::transmute::<
                unsafe extern "system" fn() -> isize,
                unsafe extern "system" fn(i32, usize, isize) -> isize,
            >(stub_wnd_proc.unwrap())),
            stub_module,
            thread_id,
        );

        if wnd_hook.is_null() {
            let error = GetLastError();
            FreeLibrary(stub_module);
            return Err(format!("Failed to set window hook: {}", error));
        }

        // 6. Send message to trigger hook
        if PostThreadMessageW(thread_id, WM_NULL, 0, 0) == 0 {
            let error = GetLastError();
            UnhookWindowsHookEx(wnd_hook);
            FreeLibrary(stub_module);
            return Err(format!("Failed to post thread message: {}", error));
        }

        println!("DLL injected successfully with SetWindowsHookEx");
        Ok((stub_module, wnd_hook))
    }
}

fn monitor_ipc(
    file_mapping: HANDLE,
    target_fps: i32,
    stub_module: HMODULE,
    wnd_hook: HHOOK,
    process_handle: HANDLE,
) -> Result<(), String> {
    unsafe {
        let view = MapViewOfFile(file_mapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if view.Value.is_null() {
            return Err("MapViewOfFile failed for monitoring".to_string());
        }

        let ipc_data = view.Value as *mut IpcData;

        // Wait for DLL to be ready
        println!("Waiting for DLL to be ready...");
        let mut retry_count = 0;
        loop {
            let mut exit_code = STILL_ACTIVE as u32;
            if GetExitCodeProcess(process_handle, &mut exit_code) != 0
                && exit_code != STILL_ACTIVE as u32
            {
                println!("Game process exited during DLL initialization");
                UnmapViewOfFile(view);
                return Ok(()); // Normal exit
            }

            let status = (*ipc_data).status;
            if status == IpcStatus::ClientReady as i32 {
                break;
            }
            if status == IpcStatus::Error as i32 {
                UnmapViewOfFile(view);
                return Err("DLL reported error".to_string());
            }
            if retry_count >= 10 {
                UnmapViewOfFile(view);
                return Err("DLL startup timeout".to_string());
            }

            retry_count += 1;
            thread::sleep(Duration::from_millis(1000));
        }

        println!("DLL is ready! FPS unlocked to {}", target_fps);
        println!("Monitoring... (Press Ctrl+C to exit)");

        // Monitoring loop
        loop {
            let mut exit_code = STILL_ACTIVE as u32;
            if GetExitCodeProcess(process_handle, &mut exit_code) != 0
                && exit_code != STILL_ACTIVE as u32
            {
                println!("Game process exited (exit code: {})", exit_code);
                break;
            }

            (*ipc_data).value = target_fps;
            (*ipc_data).status = IpcStatus::None as i32;

            thread::sleep(Duration::from_secs(1));

            let status = (*ipc_data).status;
            if status == IpcStatus::ClientExit as i32 {
                println!("Game process ended (reported by DLL)");
                break;
            }
        }

        // Notify DLL to exit
        (*ipc_data).status = IpcStatus::HostExit as i32;
        thread::sleep(Duration::from_millis(200));

        // Clean up hook and module
        UnhookWindowsHookEx(wnd_hook);
        FreeLibrary(stub_module);

        UnmapViewOfFile(view);
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    println!("Genshin Impact FPS Unlocker - DLL Injection Version");
    println!("https://github.com/Rukkhadevata123/min_hook_rs");
    println!("https://github.com/34736384/genshin-fps-unlock");
    println!("Using SetWindowsHookEx injection like C# version\n");

    if args.len() != 4 {
        eprintln!("Usage: {} <GamePath> <DllPath> <FPS>", args[0]);
        eprintln!(
            "Example: {} \"C:\\Games\\YuanShen.exe\" \"fps_unlocker_dll.dll\" 144",
            args[0]
        );
        return;
    }

    let game_path = &args[1];
    let dll_path = &args[2];
    let target_fps = match args[3].parse::<i32>() {
        Ok(f) if (60..=240).contains(&f) => f,
        _ => {
            eprintln!("Error: FPS must be between 60-240");
            return;
        }
    };

    // Check file existence
    if !Path::new(game_path).exists() {
        eprintln!("Error: Game file not found: {}", game_path);
        return;
    }
    if !Path::new(dll_path).exists() {
        eprintln!("Error: DLL file not found: {}", dll_path);
        return;
    }

    match run_fps_unlocker(game_path, dll_path, target_fps) {
        Ok(_) => println!("FPS unlocker finished successfully"),
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn run_fps_unlocker(game_path: &str, dll_path: &str, target_fps: i32) -> Result<(), String> {
    let game_exe = Path::new(game_path).file_name().unwrap().to_str().unwrap();

    // 1. Launch game (suspended state)
    let (process_handle, process_id, thread_handle) = launch_game(game_path)?;

    // 2. Resume game process
    unsafe {
        ResumeThread(thread_handle);
        CloseHandle(thread_handle);
    }

    // 3. Wait for main module to load
    let (main_base, _main_size) = wait_for_main_module(process_id, game_exe)?;

    // 4. Find FPS variable
    let fps_addr = find_fps_variable_in_main_module(process_handle, main_base)?;

    // 5. Create IPC
    let file_mapping = create_ipc(fps_addr as u64, target_fps)?;

    // 6. Use SetWindowsHookEx to inject DLL
    let (stub_module, wnd_hook) = inject_dll_with_hook(process_id, process_handle, dll_path)?;

    // 7. Monitor IPC
    let result = monitor_ipc(
        file_mapping,
        target_fps,
        stub_module,
        wnd_hook,
        process_handle,
    );

    // Clean up
    unsafe {
        CloseHandle(file_mapping);
        CloseHandle(process_handle);
    }

    result
}

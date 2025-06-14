//! Simple DLL Injector
//!
//! Used to inject Hook DLL into target process

use std::env;
use std::ffi::CString;
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

fn inject_dll(process_id: u32, dll_path: &str) -> Result<(), String> {
    if !Path::new(dll_path).exists() {
        return Err(format!("DLL file does not exist: {}", dll_path));
    }

    let dll_path_c = CString::new(dll_path).map_err(|_| "Invalid DLL path")?;

    unsafe {
        // Open target process
        let process = OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_VM_WRITE,
            FALSE,
            process_id,
        );

        if process.is_null() {
            return Err(format!("Cannot open process ID: {}", process_id));
        }

        // Allocate memory in target process
        let mem = VirtualAllocEx(
            process,
            ptr::null(),
            dll_path.len() + 1,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        );

        if mem.is_null() {
            CloseHandle(process);
            return Err(format!("VirtualAllocEx failed: {}", GetLastError()));
        }

        // Write DLL path
        let mut bytes_written = 0;
        let write_result = WriteProcessMemory(
            process,
            mem,
            dll_path_c.as_ptr() as *const std::ffi::c_void,
            dll_path.len() + 1,
            &mut bytes_written,
        );

        if write_result == 0 {
            VirtualFreeEx(process, mem, 0, MEM_RELEASE);
            CloseHandle(process);
            return Err(format!("WriteProcessMemory failed: {}", GetLastError()));
        }

        // Get LoadLibraryA address
        let kernel32 = GetModuleHandleA("kernel32\0".as_ptr());
        let load_library = GetProcAddress(kernel32, "LoadLibraryA\0".as_ptr());

        if load_library.is_none() {
            VirtualFreeEx(process, mem, 0, MEM_RELEASE);
            CloseHandle(process);
            return Err("Cannot get LoadLibraryA address".to_string());
        }

        // Create remote thread
        let thread = CreateRemoteThread(
            process,
            ptr::null(),
            0,
            Some(std::mem::transmute(load_library.unwrap())),
            mem,
            0,
            ptr::null_mut(),
        );

        if thread.is_null() {
            VirtualFreeEx(process, mem, 0, MEM_RELEASE);
            CloseHandle(process);
            return Err(format!("CreateRemoteThread failed: {}", GetLastError()));
        }

        // Wait for injection to complete
        WaitForSingleObject(thread, INFINITE);

        // Cleanup
        VirtualFreeEx(process, mem, 0, MEM_RELEASE);
        CloseHandle(thread);
        CloseHandle(process);
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <ProcessID> <DLLPath>", args[0]);
        eprintln!("Example: {} 1234 simple_messagebox_hook.dll", args[0]);
        return;
    }

    let process_id = match args[1].parse::<u32>() {
        Ok(id) => id,
        Err(_) => {
            eprintln!("Invalid process ID: {}", args[1]);
            return;
        }
    };

    let dll_path = &args[2];

    println!("Injecting DLL...");
    println!("Process ID: {}", process_id);
    println!("DLL Path: {}", dll_path);

    match inject_dll(process_id, dll_path) {
        Ok(()) => println!("DLL injection successful!"),
        Err(e) => eprintln!("DLL injection failed: {}", e),
    }
}

//! Notepad DLL Injector
//!
//! This program injects our hook DLL into a specific notepad.exe process by PID.
//!
//! Usage: notepad_injector.exe <PID> <DLL_PATH>
//!
//! To find notepad PID: tasklist | findstr notepad

use std::env;
use std::ffi::CString;
use std::ptr;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

// Inject DLL into target process
fn inject_dll(process_id: u32, dll_path: &str) -> Result<()> {
    println!("Injecting DLL into PID {process_id}");
    println!("DLL Path: {dll_path}");

    unsafe {
        // Open target process
        let process_handle = OpenProcess(
            PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_VM_READ,
            FALSE,
            process_id,
        );

        if process_handle.is_null() {
            return Err(format!(
                "Failed to open process {process_id} (insufficient privileges or process not found)"
            )
            .into());
        }

        println!("Process opened successfully");

        // Convert to absolute path
        let dll_path_absolute = std::path::Path::new(dll_path)
            .canonicalize()
            .map_err(|_| "Failed to get absolute DLL path")?;
        let dll_path_str = dll_path_absolute.to_string_lossy();

        // Allocate memory in target process for DLL path
        let dll_path_cstring = CString::new(dll_path_str.as_ref())?;
        let dll_path_len = dll_path_cstring.as_bytes_with_nul().len();

        let remote_memory = VirtualAllocEx(
            process_handle,
            ptr::null(),
            dll_path_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_memory.is_null() {
            CloseHandle(process_handle);
            return Err("Failed to allocate memory in target process".into());
        }

        println!("Memory allocated at 0x{:x}", remote_memory as usize);

        // Write DLL path to target process
        let mut bytes_written: usize = 0;
        let write_result = WriteProcessMemory(
            process_handle,
            remote_memory,
            dll_path_cstring.as_ptr() as *const std::ffi::c_void,
            dll_path_len,
            &mut bytes_written as *mut usize,
        );

        if write_result == 0 {
            VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return Err("Failed to write DLL path to target process".into());
        }

        println!("DLL path written ({bytes_written} bytes)");

        // Get LoadLibraryA address
        let kernel32_handle = GetModuleHandleA(c"kernel32".as_ptr() as *const u8);
        if kernel32_handle.is_null() {
            VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return Err("Failed to get kernel32 handle".into());
        }

        let load_library_addr =
            GetProcAddress(kernel32_handle, c"LoadLibraryA".as_ptr() as *const u8);
        if load_library_addr.is_none() {
            VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return Err("Failed to get LoadLibraryA address".into());
        }

        println!(
            "LoadLibraryA address: 0x{:x}",
            load_library_addr.unwrap() as usize
        );

        // Create remote thread to load DLL
        let thread_handle = CreateRemoteThread(
            process_handle,
            ptr::null(),
            0,
            Some(std::mem::transmute::<
                unsafe extern "system" fn() -> isize,
                unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
            >(load_library_addr.unwrap())),
            remote_memory,
            0,
            ptr::null_mut(),
        );

        if thread_handle.is_null() {
            VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return Err("Failed to create remote thread".into());
        }

        println!("Remote thread created, waiting for completion...");

        // Wait for thread to complete
        let wait_result = WaitForSingleObject(thread_handle, 10000); // 10 second timeout
        if wait_result != WAIT_OBJECT_0 {
            CloseHandle(thread_handle);
            VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
            CloseHandle(process_handle);
            return Err("Remote thread timed out or failed".into());
        }

        // Get thread exit code (LoadLibrary return value)
        let mut exit_code = 0;
        GetExitCodeThread(thread_handle, &mut exit_code);

        // Cleanup
        CloseHandle(thread_handle);
        VirtualFreeEx(process_handle, remote_memory, 0, MEM_RELEASE);
        CloseHandle(process_handle);

        if exit_code == 0 {
            return Err(
                "LoadLibrary failed in target process (DLL not found or failed to load)".into(),
            );
        }

        println!("DLL injected successfully! LoadLibrary returned: 0x{exit_code:x}");
        Ok(())
    }
}

fn main() -> Result<()> {
    println!("Notepad Hook Injector");
    println!("=====================");

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} <PID> <DLL_PATH>", args[0]);
        println!();
        println!("Examples:");
        println!("  {} 1234 hook.dll", args[0]);
        println!(
            "  {} 1234 target/release/examples/notepad_hook_dll.dll",
            args[0]
        );
        println!();
        println!("To find notepad PID:");
        println!("  tasklist | findstr notepad");
        return Err("Invalid arguments".into());
    }

    let process_id: u32 = args[1]
        .parse()
        .map_err(|_| "Invalid PID: must be a number")?;

    let dll_path = &args[2];

    // Check if DLL exists
    if !std::path::Path::new(dll_path).exists() {
        return Err(format!("DLL not found: {dll_path}").into());
    }

    println!("Target PID: {process_id}");
    println!("DLL file: {dll_path}");
    println!();

    // Inject DLL
    match inject_dll(process_id, dll_path) {
        Ok(()) => {
            println!();
            println!("Hook injection completed successfully!");
            println!();
            println!("Test the hook:");
            println!("1. Go to the notepad window (PID: {process_id})");
            println!("2. Type some text in notepad");
            println!("3. Try to close the window WITHOUT saving");
            println!("4. You should see a custom hook message instead of the normal save dialog");
        }
        Err(e) => {
            println!();
            println!("Injection failed: {e}");
            println!();
            println!("Troubleshooting:");
            println!("1. Make sure the PID is correct and notepad.exe is running");
            println!("2. Run this program as Administrator if needed");
            println!("3. Check that the DLL file exists and was built correctly");
            return Err(e);
        }
    }

    Ok(())
}

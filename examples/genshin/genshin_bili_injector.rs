//! Genshin Impact Bilibili DLL Injector
//!
//! ## Correct file structure
//! ```
//! /run/media/yoimiya/Data/Program Files/Genshin Impact/
//! ├── genshin_bili_dll.dll           # Hook DLL (place here to avoid game data issues)
//! ├── genshin_bili_injector.exe      # Injector (place here)
//! └── Genshin Impact Game/
//!     ├── YuanShen.exe               # Genshin Impact main program
//!     ├── login.json                 # Login data (place here)
//!     └── YuanShen_Data/
//!         └── Plugins/
//!             └── PCGameSDK.dll      # Target DLL to be hooked
//! ```
//!
//! ## Usage
//! ```bash
//! # Enter game directory
//! cd "/run/media/yoimiya/Data/Program Files/Genshin Impact/Genshin Impact Game/"
//!
//! # Run injector (using relative path to reference parent directory files)
//! start ..\genshin_bili_injector.exe YuanShen.exe ..\genshin_bili_dll.dll
//! ```

use std::env;
use std::ffi::CString;
use std::path::Path;
use std::ptr;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Environment::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

fn inject_library(process: HANDLE, dll_path: &str) -> Result<(), String> {
    let dll_path_c = CString::new(dll_path).map_err(|_| "Invalid DLL path")?;

    unsafe {
        let loadlibrary_addr = LoadLibraryA as *mut std::ffi::c_void;

        let mem = VirtualAllocEx(
            process,
            ptr::null(),
            dll_path.len() + 1,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        );

        if mem.is_null() {
            return Err(format!("VirtualAllocEx failed: {}", GetLastError()));
        }

        let mut bytes_written = 0;
        WriteProcessMemory(
            process,
            mem,
            dll_path_c.as_ptr() as *const std::ffi::c_void,
            dll_path.len() + 1,
            &mut bytes_written,
        );

        let new_thread = CreateRemoteThread(
            process,
            ptr::null(),
            0,
            Some(std::mem::transmute::<
                *mut std::ffi::c_void,
                unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
            >(loadlibrary_addr)),
            mem,
            0,
            ptr::null_mut(),
        );

        if new_thread.is_null() {
            VirtualFreeEx(process, mem, 0, MEM_RELEASE);
            return Err(format!("CreateRemoteThread failed: {}", GetLastError()));
        }

        WaitForSingleObject(new_thread, INFINITE);

        VirtualFreeEx(process, mem, 0, MEM_RELEASE);
        CloseHandle(new_thread);
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} <game_command> <dll_path>", args[0]);
        eprintln!(
            "Example: {} \"YuanShen.exe\" ..\\genshin_bili_dll.dll",
            args[0]
        );
        eprintln!();
        eprintln!("Note: Must run in game directory, DLL file placed in parent directory");
        return;
    }

    let game_command = &args[1];
    let dll_path = &args[2];

    if !Path::new(dll_path).exists() {
        eprintln!("DLL file does not exist: {}", dll_path);
        return;
    }

    if !Path::new("login.json").exists() {
        eprintln!("login.json file does not exist (should be in current directory)");
        return;
    }

    unsafe {
        let env_name = "__COMPAT_LAYER\0".encode_utf16().collect::<Vec<u16>>();
        let env_value = "RunAsInvoker\0".encode_utf16().collect::<Vec<u16>>();
        SetEnvironmentVariableW(env_name.as_ptr(), env_value.as_ptr());
    }

    let mut startup_info: STARTUPINFOA = unsafe { std::mem::zeroed() };
    startup_info.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

    let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let command = CString::new(game_command.as_str()).unwrap();

    let created = unsafe {
        CreateProcessA(
            ptr::null(),
            command.as_ptr() as *mut u8,
            ptr::null(),
            ptr::null(),
            0,
            CREATE_SUSPENDED,
            ptr::null(),
            ptr::null(),
            &startup_info,
            &mut process_info,
        )
    };

    if created == 0 {
        eprintln!("Failed to create process: {}", unsafe { GetLastError() });
        return;
    }

    match inject_library(process_info.hProcess, dll_path) {
        Ok(_) => {
            unsafe {
                if ResumeThread(process_info.hThread) == u32::MAX {
                    eprintln!("Failed to resume thread: {}", GetLastError());
                    return;
                }
            }
            println!("Injection successful, Genshin Impact started");
        }
        Err(e) => {
            eprintln!("Injection failed: {}", e);
            unsafe {
                TerminateProcess(process_info.hProcess, 1);
            }
        }
    }

    unsafe {
        CloseHandle(process_info.hProcess);
        CloseHandle(process_info.hThread);
    }
}

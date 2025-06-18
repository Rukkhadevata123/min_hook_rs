//! Genshin Impact FPS Unlocker - DLL part
//!
//! Completely based on C# version implementation, injected into game process to perform FPS writing
//!
//! Acknowledge https://github.com/34736384/genshin-fps-unlock

use std::ffi::c_void;
use std::ptr;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::SystemServices::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

// IPC data structure (completely consistent with injector and C#)
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
    #[allow(dead_code)]
    HostAwaiting = 1,
    ClientReady = 2,
    ClientExit = 3,
    HostExit = 4,
}

const IPC_GUID: &[u8] = b"2DE95FDC-6AB7-4593-BFE6-760DD4AB422B\0";

// Value range limitation (based on c# Clamp function)
fn clamp<T: PartialOrd>(val: T, min: T, max: T) -> T {
    if val < min {
        min
    } else if val > max {
        max
    } else {
        val
    }
}

// FPS writing thread (completely based on c# ThreadProc)
unsafe extern "system" fn thread_proc(_: *mut c_void) -> u32 {
    unsafe {
        // Increase module reference count (based on c# LdrAddRefDll)
        // Note: Rust has no direct equivalent, but DLL is already loaded

        // Open IPC file mapping
        let file_mapping = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, 0, IPC_GUID.as_ptr());
        if file_mapping.is_null() {
            return 0;
        }

        let view = MapViewOfFile(file_mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
        if view.Value.is_null() {
            CloseHandle(file_mapping);
            return 0;
        }

        let ipc_data = view.Value as *mut IpcData;
        let fps_addr = (*ipc_data).address as *mut i32;

        // Validate address validity (based on c# VirtualQuery check)
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        if VirtualQuery(
            fps_addr as *const c_void,
            &mut mbi,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        ) == 0
            || mbi.Protect != PAGE_READWRITE
        {
            (*ipc_data).status = IpcStatus::Error as i32;
            UnmapViewOfFile(view);
            CloseHandle(file_mapping);
            return 0;
        }

        // Notify main program ready
        (*ipc_data).status = IpcStatus::ClientReady as i32;

        // FPS writing loop (based on c# while loop)
        // Tell compiler this is memory that might be modified externally
        while ptr::read_volatile(&(*ipc_data).status) != IpcStatus::HostExit as i32 {
            let target_fps = ptr::read_volatile(&(*ipc_data).value);
            let clamped_fps = clamp(target_fps, 1, 1000);
            *fps_addr = clamped_fps;
            Sleep(62);
        }

        // Notify main program about to exit
        (*ipc_data).status = IpcStatus::ClientExit as i32;

        UnmapViewOfFile(view);
        CloseHandle(file_mapping);
        0
    }
}

// DLL main entry point (completely based on c# DllMain)
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    hinst_dll: HINSTANCE,
    fdw_reason: u32,
    _lpv_reserved: *mut c_void,
) -> i32 {
    unsafe {
        if !hinst_dll.is_null() {
            // Based on c# DisableThreadLibraryCalls
            DisableThreadLibraryCalls(hinst_dll);
        }

        // Check if in game process (based on c# GetModuleHandleA("mhypbase.dll"))
        if GetModuleHandleA(c"mhypbase.dll".as_ptr() as *const u8).is_null() {
            return 1; // Not game process, safe exit
        }

        if fdw_reason == DLL_PROCESS_ATTACH {
            // Create FPS writing thread (based on c# CreateThread)
            let thread_handle = CreateThread(
                ptr::null(),
                0,
                Some(thread_proc),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
            );

            if !thread_handle.is_null() {
                CloseHandle(thread_handle);
            }
        }

        1 // TRUE
    }
}

// Exported window procedure (based on c# WndProc, used for SetWindowsHookEx injection)
#[unsafe(no_mangle)]
pub unsafe extern "system" fn WndProc(code: i32, wparam: usize, lparam: isize) -> isize {
    unsafe { CallNextHookEx(ptr::null_mut(), code, wparam, lparam) }
}

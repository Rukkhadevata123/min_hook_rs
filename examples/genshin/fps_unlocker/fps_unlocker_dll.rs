//! 原神FPS解锁器 - DLL部分
//!
//! 完全对照C++版本实现，注入到游戏进程中执行FPS写入

use std::ffi::c_void;
use std::ptr;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::SystemServices::*;
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

// IPC数据结构（与注入器和C++完全一致）
#[repr(C, align(8))]
#[derive(Debug, Clone, Copy)]
struct IpcData {
    address: u64,
    value: i32,
    status: i32,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // 允许未使用的变体
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

// 值范围限制（对照C++ Clamp函数）
fn clamp<T: PartialOrd>(val: T, min: T, max: T) -> T {
    if val < min {
        min
    } else if val > max {
        max
    } else {
        val
    }
}

// FPS写入线程（完全对照C++ ThreadProc）
unsafe extern "system" fn thread_proc(_: *mut c_void) -> u32 {
    unsafe {
        // 增加模块引用计数（对照C++ LdrAddRefDll）
        // 注：Rust没有直接等价物，但DLL已经被加载了

        // 打开IPC文件映射
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

        // 验证地址有效性（对照C++ VirtualQuery检查）
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        if VirtualQuery(
            fps_addr as *const c_void,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        ) == 0
            || mbi.Protect != PAGE_READWRITE
        {
            (*ipc_data).status = IpcStatus::Error as i32;
            UnmapViewOfFile(view);
            CloseHandle(file_mapping);
            return 0;
        }

        // 通知主程序准备就绪
        (*ipc_data).status = IpcStatus::ClientReady as i32;

        // FPS写入循环（对照C++的while循环）
        while (*ipc_data).status != IpcStatus::HostExit as i32 {
            let target_fps = (*ipc_data).value;
            let clamped_fps = clamp(target_fps, 1, 1000);

            // 直接写入FPS值
            *fps_addr = clamped_fps;

            Sleep(62); // 对照C++的Sleep(62)，约16Hz更新频率
        }

        // 通知主程序即将退出
        (*ipc_data).status = IpcStatus::ClientExit as i32;

        UnmapViewOfFile(view);
        CloseHandle(file_mapping);
        0
    }
}

// DLL主入口点（完全对照C++ DllMain）
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    hinst_dll: HINSTANCE,
    fdw_reason: u32,
    _lpv_reserved: *mut c_void,
) -> i32 {
    unsafe {
        if !hinst_dll.is_null() {
            // 对照C++ DisableThreadLibraryCalls
            DisableThreadLibraryCalls(hinst_dll);
        }

        // 检查是否在游戏进程中（对照C++ GetModuleHandleA("mhypbase.dll")）
        if GetModuleHandleA(b"mhypbase.dll\0".as_ptr()).is_null() {
            return 1; // 不是游戏进程，安全退出
        }

        if fdw_reason == DLL_PROCESS_ATTACH {
            // 创建FPS写入线程（对照C++ CreateThread）
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

// 导出的窗口过程（对照C++ WndProc，用于SetWindowsHookEx注入）
#[unsafe(no_mangle)]
pub unsafe extern "system" fn WndProc(code: i32, wparam: usize, lparam: isize) -> isize {
    unsafe { CallNextHookEx(ptr::null_mut(), code, wparam, lparam) }
}

//! 原神B服DLL注入器
//!
//! ## 正确的文件结构
//! ```
//! /run/media/yoimiya/Data/Program Files/Genshin Impact/
//! ├── genshin_bili_dll.dll           # Hook DLL (放在这里，避免游戏数据异常)
//! ├── genshin_bili_injector.exe      # 注入器 (放在这里)
//! └── Genshin Impact Game/
//!     ├── YuanShen.exe               # 原神主程序
//!     ├── login.json                 # 登录数据 (放在这里)
//!     └── YuanShen_Data/
//!         └── Plugins/
//!             └── PCGameSDK.dll      # 被Hook的目标DLL
//! ```
//!
//! ## 使用方法
//! ```bash
//! # 进入游戏目录
//! cd "/run/media/yoimiya/Data/Program Files/Genshin Impact/Genshin Impact Game/"
//!
//! # 运行注入器 (使用相对路径引用上级目录的文件)
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
        eprintln!("用法: {} <游戏命令> <DLL路径>", args[0]);
        eprintln!(
            "示例: {} \"YuanShen.exe\" ..\\genshin_bili_dll.dll",
            args[0]
        );
        eprintln!();
        eprintln!("注意: 必须在游戏目录下运行，DLL文件放在上级目录");
        return;
    }

    let game_command = &args[1];
    let dll_path = &args[2];

    if !Path::new(dll_path).exists() {
        eprintln!("DLL文件不存在: {}", dll_path);
        return;
    }

    if !Path::new("login.json").exists() {
        eprintln!("login.json文件不存在 (应该在当前目录)");
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
        eprintln!("创建进程失败: {}", unsafe { GetLastError() });
        return;
    }

    match inject_library(process_info.hProcess, dll_path) {
        Ok(_) => {
            unsafe {
                if ResumeThread(process_info.hThread) == u32::MAX {
                    eprintln!("恢复线程失败: {}", GetLastError());
                    return;
                }
            }
            println!("注入成功，原神已启动");
        }
        Err(e) => {
            eprintln!("注入失败: {}", e);
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

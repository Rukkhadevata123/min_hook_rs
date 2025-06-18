//! Simple MessageBox Hook DLL Example
//!
//! This DLL hooks MessageBoxA function and replaces all popup content with custom content
//!
//! ## Build Method
//! ```bash
//! cargo xwin build --example simple_messagebox_hook --target x86_64-pc-windows-msvc --release
//! ```
//!
//! ## Usage
//! 1. Inject the compiled DLL into target process
//! 2. When target process calls MessageBoxA, it will show hooked content

use min_hook_rs::*;
use std::ffi::{CString, c_char, c_void};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::LibraryLoader::*;

// MessageBoxA function type definition
type MessageBoxAFn = unsafe extern "system" fn(HWND, *const c_char, *const c_char, u32) -> i32;

// Store original function pointer
static mut ORIGINAL_MESSAGEBOX_A: Option<MessageBoxAFn> = None;

// Hook function - replace MessageBox content
unsafe extern "system" fn hooked_messagebox_a(
    hwnd: HWND,
    _text: *const c_char,
    _caption: *const c_char,
    utype: u32,
) -> i32 {
    // Custom message content (English to avoid encoding issues)
    let hooked_text = CString::new("MinHook-rs successfully hooked this message box!").unwrap();
    let hooked_caption = CString::new("MinHook-rs Demo").unwrap();

    // Call original function with our content
    if let Some(original) = unsafe { ORIGINAL_MESSAGEBOX_A } {
        unsafe { original(hwnd, hooked_text.as_ptr(), hooked_caption.as_ptr(), utype) }
    } else {
        0
    }
}

// DLL initialization function
fn setup_hook() -> Result<()> {
    // Initialize MinHook
    initialize()?;

    // Get MessageBoxA address
    let module_name = CString::new("user32").unwrap();
    let function_name = CString::new("MessageBoxA").unwrap();

    let user32_handle = unsafe { LoadLibraryA(module_name.as_ptr() as *const u8) };
    if user32_handle.is_null() {
        return Err(HookError::ModuleNotFound);
    }

    let messagebox_addr =
        unsafe { GetProcAddress(user32_handle, function_name.as_ptr() as *const u8) };
    if messagebox_addr.is_none() {
        return Err(HookError::FunctionNotFound);
    }

    let target = messagebox_addr.unwrap() as *mut c_void;

    // Create Hook
    let trampoline = create_hook(target, hooked_messagebox_a as *mut c_void)?;

    // Store original function pointer
    unsafe {
        ORIGINAL_MESSAGEBOX_A = Some(std::mem::transmute::<
            *mut c_void,
            unsafe extern "system" fn(*mut c_void, *const i8, *const i8, u32) -> i32,
        >(trampoline));
    }

    // Enable Hook
    enable_hook(target)?;

    Ok(())
}

// DLL cleanup function
fn cleanup_hook() {
    let _ = uninitialize();
}

// DLL entry point
#[unsafe(no_mangle)]
pub extern "system" fn DllMain(_module: HMODULE, reason: u32, _reserved: *mut c_void) -> i32 {
    match reason {
        1 => {
            // DLL_PROCESS_ATTACH
            match setup_hook() {
                Ok(()) => 1,
                Err(_) => 0,
            }
        }
        0 => {
            // DLL_PROCESS_DETACH
            cleanup_hook();
            1
        }
        _ => 1,
    }
}

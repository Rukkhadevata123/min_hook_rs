//! Notepad MessageBox Hook DLL
//!
//! This DLL hooks into notepad.exe to intercept and modify the exit confirmation dialog.
//! When you try to close an unsaved document in notepad, it will show our custom message.

use min_hook_rs::*;
use std::ffi::c_void;
use std::ptr;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;
use windows_sys::core::*;

// MessageBoxW function signature (notepad uses Unicode)
type MessageBoxWFn = unsafe extern "system" fn(HWND, PCWSTR, PCWSTR, u32) -> i32;

// Store original function pointer
static mut ORIGINAL_MESSAGEBOX_W: Option<MessageBoxWFn> = None;
static mut HOOK_INSTALLED: bool = false;

// Convert UTF-8 string to wide string
fn utf8_to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// Hook function - intercept notepad's exit confirmation
unsafe extern "system" fn hooked_messagebox_w(
    hwnd: HWND,
    text: PCWSTR,
    caption: PCWSTR,
    utype: u32,
) -> i32 {
    // Read original text to detect if this is the exit confirmation
    let original_text = if !text.is_null() {
        unsafe { read_wide_string(text) }
    } else {
        String::new()
    };

    let original_caption = if !caption.is_null() {
        unsafe { read_wide_string(caption) }
    } else {
        String::new()
    };

    // Check if this looks like notepad's exit confirmation dialog
    let is_exit_dialog = original_text.contains("save")
        || original_text.contains("Save")
        || original_text.contains("保存")
        || original_caption.contains("Notepad")
        || original_caption.contains("记事本");

    if is_exit_dialog {
        println!("[HOOK] Intercepted exit confirmation dialog");
        println!("Original Caption: {}", original_caption);
        println!("Original Text: {}", original_text);

        // Create our custom message
        let custom_text = utf8_to_wide(
            "MinHook-rs has intercepted this dialog!\n\n\
            This was originally a Notepad exit confirmation.\n\n\
            Original message: \"Do you want to save changes?\"\n\n\
            Choose wisely! (Hook is working perfectly)",
        );

        let custom_caption = utf8_to_wide("MinHook-rs Notepad Demo");

        // Call original function with our modified content
        unsafe {
            let original_ptr = ptr::addr_of!(ORIGINAL_MESSAGEBOX_W).read();
            match original_ptr {
                Some(original_fn) => original_fn(
                    hwnd,
                    custom_text.as_ptr(),
                    custom_caption.as_ptr(),
                    MB_YESNOCANCEL | MB_ICONQUESTION, // Keep the same button style
                ),
                None => IDCANCEL, // Fixed: use IDCANCEL instead of MB_CANCEL
            }
        }
    } else {
        // For other MessageBox calls, just pass through
        unsafe {
            let original_ptr = ptr::addr_of!(ORIGINAL_MESSAGEBOX_W).read();
            match original_ptr {
                Some(original_fn) => original_fn(hwnd, text, caption, utype),
                None => 0,
            }
        }
    }
}

// Helper function to read wide string
unsafe fn read_wide_string(ptr: PCWSTR) -> String {
    let mut len = 0;
    let mut current = ptr;

    // Find length
    unsafe {
        while *current != 0 {
            len += 1;
            current = current.add(1);
            if len > 1000 {
                // Safety limit
                break;
            }
        }
    }

    if len == 0 {
        return String::new();
    }

    // Convert to string
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(slice)
}

// Install the hook
unsafe fn install_hook() -> bool {
    unsafe {
        if HOOK_INSTALLED {
            return true;
        }

        println!("[HOOK] Installing MessageBoxW hook...");

        // Initialize MinHook
        if let Err(e) = initialize() {
            println!("[HOOK] Failed to initialize MinHook: {:?}", e);
            return false;
        }

        // Create hook for MessageBoxW (Unicode version used by notepad)
        match create_hook_api("user32", "MessageBoxW", hooked_messagebox_w as *mut c_void) {
            Ok((trampoline, target)) => {
                // Store original function
                ORIGINAL_MESSAGEBOX_W = Some(std::mem::transmute::<
                    *mut c_void,
                    unsafe extern "system" fn(*mut c_void, *const u16, *const u16, u32) -> i32,
                >(trampoline));

                // Enable hook
                match enable_hook(target) {
                    Ok(()) => {
                        HOOK_INSTALLED = true;
                        println!("[HOOK] MessageBoxW hook installed successfully");
                        true
                    }
                    Err(e) => {
                        println!("[HOOK] Failed to enable hook: {:?}", e);
                        false
                    }
                }
            }
            Err(e) => {
                println!("[HOOK] Failed to create hook: {:?}", e);
                false
            }
        }
    }
}

// Uninstall the hook
unsafe fn uninstall_hook() {
    unsafe {
        if !HOOK_INSTALLED {
            return;
        }

        println!("[NOTEPAD HOOK] Uninstalling MessageBoxW hook...");

        if let Err(e) = uninitialize() {
            println!("[NOTEPAD HOOK] Failed to uninitialize MinHook: {:?}", e);
        } else {
            println!("[NOTEPAD HOOK] Hook uninstalled successfully!");
        }

        HOOK_INSTALLED = false;
    }
}

// DLL entry point
#[unsafe(no_mangle)]
pub extern "system" fn DllMain(
    _hmodule: HINSTANCE,
    fdw_reason: u32,
    _lpv_reserved: *mut c_void,
) -> BOOL {
    unsafe {
        match fdw_reason {
            1 => {
                // DLL_PROCESS_ATTACH
                // Allocate console for debug output
                #[cfg(debug_assertions)]
                {
                    use windows_sys::Win32::System::Console::*;
                    AllocConsole();
                }

                println!("[HOOK] DLL injected into notepad.exe");

                // Install hook
                if install_hook() {
                    println!("[HOOK] Ready to intercept exit confirmation dialogs");
                    TRUE
                } else {
                    println!("[HOOK] Failed to install hooks");
                    FALSE
                }
            }
            0 => {
                // DLL_PROCESS_DETACH
                println!("[HOOK] DLL being unloaded from notepad.exe");
                uninstall_hook();
                TRUE
            }
            2 | 3 => TRUE, // DLL_THREAD_ATTACH | DLL_THREAD_DETACH
            _ => TRUE,
        }
    }
}

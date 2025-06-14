//! Basic MessageBox Hook Example
//!
//! Simple MessageBoxA Hook demonstration showing before/after comparison

use min_hook_rs::*;
use std::ffi::c_void;
use std::ptr;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;
use windows_sys::core::PCSTR;

// MessageBoxA function signature
type MessageBoxAFn = unsafe extern "system" fn(HWND, PCSTR, PCSTR, u32) -> i32;

// Store original function pointer
static mut ORIGINAL_MESSAGEBOX: Option<MessageBoxAFn> = None;

// Hook function - modify message content
#[unsafe(no_mangle)]
pub unsafe extern "system" fn hooked_messagebox(
    hwnd: HWND,
    _text: PCSTR,
    _caption: PCSTR,
    _utype: u32,
) -> i32 {
    println!("[HOOK] MessageBoxA intercepted!");

    // Modified message content
    let new_text = "MinHook-rs intercepted this message!\0";
    let new_caption = "[HOOKED] Demo\0";

    // Call original function
    unsafe {
        let original_ptr = ptr::addr_of!(ORIGINAL_MESSAGEBOX).read();

        match original_ptr {
            Some(original_fn) => original_fn(
                hwnd,
                new_text.as_ptr(),
                new_caption.as_ptr(),
                MB_ICONWARNING,
            ),
            None => {
                // Fallback to system MessageBoxA
                MessageBoxA(
                    hwnd,
                    new_text.as_ptr(),
                    new_caption.as_ptr(),
                    MB_ICONWARNING,
                )
            }
        }
    }
}

// Test MessageBox call
fn show_test_message(title: &str, message: &str, description: &str) {
    println!("{}", description);

    let title_c = format!("{}\0", title);
    let message_c = format!("{}\0", message);

    unsafe {
        MessageBoxA(
            ptr::null_mut(),
            message_c.as_ptr(),
            title_c.as_ptr(),
            MB_ICONINFORMATION,
        );
    }
}

fn main() -> Result<()> {
    println!("MinHook-rs MessageBox Hook Demo");
    println!("================================");

    if !is_supported() {
        eprintln!("Error: Only supports x64 Windows!");
        return Ok(());
    }

    // Phase 1: Test original behavior
    println!("\n[PHASE 1] Testing original MessageBox behavior");
    show_test_message(
        "Original Behavior",
        "This is the original MessageBoxA call.\nNo hook is active.",
        "Showing original MessageBox...",
    );

    // Phase 2: Initialize and create hook
    println!("\n[PHASE 2] Installing hook");
    println!("Initializing MinHook...");
    initialize()?;

    println!("Creating MessageBoxA hook...");
    let (trampoline, target) =
        create_hook_api("user32", "MessageBoxA", hooked_messagebox as *mut c_void)?;

    unsafe {
        ORIGINAL_MESSAGEBOX = Some(std::mem::transmute(trampoline));
    }

    println!("Enabling hook...");
    enable_hook(target)?;
    println!("Hook activated successfully!");

    // Phase 3: Test hook effect
    println!("\n[PHASE 3] Testing hook effect");
    show_test_message(
        "Test Message",
        "This message should be intercepted and modified!",
        "Showing hooked MessageBox...",
    );

    // Phase 4: Multiple tests for stability
    println!("\n[PHASE 4] Testing hook stability");
    show_test_message("Second Test", "Second call test", "Second hook test...");
    show_test_message("Third Test", "Third call test", "Third hook test...");

    // Phase 5: Disable hook
    println!("\n[PHASE 5] Disabling hook");
    disable_hook(target)?;
    println!("Hook disabled");

    // Phase 6: Verify hook is disabled
    println!("\n[PHASE 6] Verifying hook is disabled");
    show_test_message(
        "Hook Disabled",
        "This message should show normal content.\nHook has been disabled.",
        "Showing normal MessageBox after disable...",
    );

    // Phase 7: Cleanup
    println!("\n[PHASE 7] Cleanup");
    remove_hook(target)?;
    uninitialize()?;
    println!("Cleanup completed");

    println!("\nDemo completed successfully!");
    println!("\nSummary:");
    println!("- Original behavior: Normal MessageBox");
    println!("- Hook active: Message intercepted and modified");
    println!("- Hook disabled: Normal behavior restored");
    println!("- Complete cleanup: System returned to initial state");

    Ok(())
}

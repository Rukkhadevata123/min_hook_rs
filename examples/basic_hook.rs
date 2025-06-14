//! Basic hook example demonstrating MessageBoxW hooking
//!
//! This example shows how to:
//! 1. Initialize MinHook-rs
//! 2. Create a hook for a Windows API function
//! 3. Enable the hook
//! 4. Test the hook by calling the original function
//! 5. Clean up properly

use min_hook_rs::*;
use std::ffi::c_void;
use std::ptr;

// Define the MessageBoxW function signature
type MessageBoxWFn = unsafe extern "system" fn(
    hwnd: *mut c_void,
    text: *const u16,
    caption: *const u16,
    utype: u32,
) -> i32;

// Global variable to store the original function
static mut ORIGINAL_MESSAGEBOX: Option<MessageBoxWFn> = None;

// Our detour function that will be called instead of the original
unsafe extern "system" fn detour_messagebox(
    hwnd: *mut c_void,
    text: *const u16,
    caption: *const u16,
    utype: u32,
) -> i32 {
    println!("MessageBoxW hook called!");

    // Convert the text and caption to Rust strings for display
    let text_str = wide_ptr_to_string(text);
    let caption_str = wide_ptr_to_string(caption);

    println!("  Caption: {}", caption_str);
    println!("  Text: {}", text_str);
    println!("  Type: 0x{:X}", utype);

    // Call the original function
    unsafe {
        if let Some(original) = ORIGINAL_MESSAGEBOX {
            println!("Calling original MessageBoxW...");
            original(hwnd, text, caption, utype)
        } else {
            println!("Original MessageBoxW not available!");
            0
        }
    }
}

// Helper function to convert wide string pointer to Rust String
fn wide_ptr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }

    unsafe {
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }

        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf16_lossy(slice)
    }
}

// Helper function to convert Rust string to wide string
fn string_to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// Declare the MessageBoxW function for testing
unsafe extern "system" {
    fn MessageBoxW(hwnd: *mut c_void, text: *const u16, caption: *const u16, utype: u32) -> i32;
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    println!("MinHook-rs Basic Hook Example");
    println!("=============================");

    // Check if platform is supported
    if !is_supported() {
        eprintln!("This example only works on x64 Windows!");
        return Ok(());
    }

    println!("Platform supported: {}", is_supported());
    println!("Library version: {}", get_version());

    // Initialize MinHook
    println!("\n1. Initializing MinHook-rs...");
    initialize().map_err(|e| format!("Failed to initialize: {}", e))?;
    println!("   ✓ MinHook-rs initialized successfully");

    // Create hook for MessageBoxW
    println!("\n2. Creating hook for MessageBoxW...");
    let (trampoline, target) =
        create_hook_api("user32", "MessageBoxW", detour_messagebox as *mut c_void)
            .map_err(|e| format!("Failed to create hook: {}", e))?;

    println!("   ✓ Hook created successfully");
    println!("   Target address: {:p}", target);
    println!("   Trampoline address: {:p}", trampoline);

    // Store the original function pointer
    unsafe {
        ORIGINAL_MESSAGEBOX = Some(std::mem::transmute(trampoline));
    }

    // Enable the hook
    println!("\n3. Enabling hook...");
    enable_hook(target).map_err(|e| format!("Failed to enable hook: {}", e))?;
    println!("   ✓ Hook enabled successfully");

    // Test the hook by calling MessageBoxW
    println!("\n4. Testing the hook...");
    println!("   Calling MessageBoxW - this should trigger our hook!");

    let title = string_to_wide("MinHook-rs Test");
    let message = string_to_wide(
        "This message box was intercepted by MinHook-rs!\n\nOriginal function called successfully.",
    );

    unsafe {
        MessageBoxW(
            ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            0x40, // MB_ICONINFORMATION
        );
    }

    println!("   ✓ Hook test completed");

    // Disable the hook
    println!("\n5. Disabling hook...");
    disable_hook(target).map_err(|e| format!("Failed to disable hook: {}", e))?;
    println!("   ✓ Hook disabled successfully");

    // Test that the hook is disabled
    println!("\n6. Testing with hook disabled...");
    println!("   Calling MessageBoxW again - should NOT trigger our hook");

    let title2 = string_to_wide("Hook Disabled");
    let message2 = string_to_wide("This message should appear normally without hook interception.");

    unsafe {
        MessageBoxW(
            ptr::null_mut(),
            message2.as_ptr(),
            title2.as_ptr(),
            0x30, // MB_ICONWARNING
        );
    }

    // Remove the hook
    println!("\n7. Removing hook...");
    remove_hook(target).map_err(|e| format!("Failed to remove hook: {}", e))?;
    println!("   ✓ Hook removed successfully");

    // Uninitialize MinHook
    println!("\n8. Uninitializing MinHook-rs...");
    uninitialize().map_err(|e| format!("Failed to uninitialize: {}", e))?;
    println!("   ✓ MinHook-rs uninitialized successfully");

    println!("\n✓ All tests completed successfully!");
    println!("\nPress Enter to exit...");

    // Wait for user input
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();

    Ok(())
}

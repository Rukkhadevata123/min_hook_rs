//! MessageBox Test Program
//!
//! This program will display several MessageBox dialogs for testing Hook effects
//!
//! ## Usage
//! ```bash
//! # Build test program
//! cargo xwin build --example messagebox_test --target x86_64-pc-windows-msvc --release
//!
//! # Build Hook DLL
//! cargo xwin build --example simple_messagebox_hook --target x86_64-pc-windows-msvc --release
//!
//! # Run test program, then inject DLL to observe effects
//! ```

use std::ffi::CString;
use std::ptr;
use std::thread;
use std::time::Duration;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

fn show_messagebox(title: &str, message: &str, icon: u32) {
    let title_c = CString::new(title).unwrap();
    let message_c = CString::new(message).unwrap();

    println!("Showing MessageBox: {title} - {message}");

    unsafe {
        MessageBoxA(
            ptr::null_mut(),
            message_c.as_ptr() as *const u8,
            title_c.as_ptr() as *const u8,
            icon,
        );
    }
}

fn main() {
    println!("MessageBox Hook Test Program");
    println!("============================");
    println!("This program will display several MessageBox dialogs");
    println!("If Hook DLL is injected, content will be replaced");
    println!();

    // Wait a moment for DLL injection
    println!("Starting test in 5 seconds...");
    thread::sleep(Duration::from_secs(5));

    // Test different types of MessageBox
    show_messagebox(
        "Test 1",
        "This is the first test message",
        MB_ICONINFORMATION,
    );

    thread::sleep(Duration::from_secs(2));
    show_messagebox("Test 2", "This is the second test message", MB_ICONWARNING);

    thread::sleep(Duration::from_secs(2));
    show_messagebox("Test 3", "This is the third test message", MB_ICONERROR);

    thread::sleep(Duration::from_secs(2));
    show_messagebox("Test Complete", "All tests completed", MB_ICONQUESTION);

    println!("Program finished!");
    println!("If you saw custom Hook messages, the Hook was successful!");
}

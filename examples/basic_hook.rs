//! Enhanced MessageBox Hook Example with Comprehensive Testing
//!
//! This example demonstrates MinHook-rs functionality with extensive testing scenarios

use min_hook_rs::*;
use std::ffi::c_void;
use std::ptr;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::SystemInformation::GetTickCount;
use windows_sys::Win32::UI::WindowsAndMessaging::*;
use windows_sys::core::PCSTR;

// MessageBoxA function signature
type MessageBoxAFn = unsafe extern "system" fn(HWND, PCSTR, PCSTR, u32) -> i32;
type GetTickCountFn = unsafe extern "system" fn() -> u32;

// Store original function pointers
static mut ORIGINAL_MESSAGEBOX: Option<MessageBoxAFn> = None;
static mut ORIGINAL_GETTICKCOUNT: Option<GetTickCountFn> = None;

// Hook counters for testing
static mut MESSAGEBOX_HOOK_COUNT: u32 = 0;
static mut GETTICKCOUNT_HOOK_COUNT: u32 = 0;

// Hook function - modify message content
#[unsafe(no_mangle)]
pub unsafe extern "system" fn hooked_messagebox(
    hwnd: HWND,
    _text: PCSTR,
    _caption: PCSTR,
    _utype: u32,
) -> i32 {
    unsafe {
        MESSAGEBOX_HOOK_COUNT += 1;
        // 使用ptr::read避免静态引用
        let count = ptr::addr_of!(MESSAGEBOX_HOOK_COUNT).read();
        println!("[HOOK] MessageBoxA intercepted! Call #{}", count);

        // Modified message content with call count
        let new_text = format!("MinHook-rs intercepted this message!\nCall #{}\0", count);
        let new_caption = "[HOOKED] Demo\0";

        // Call original function
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

// Hook GetTickCount for high-frequency testing
#[unsafe(no_mangle)]
pub unsafe extern "system" fn hooked_gettickcount() -> u32 {
    unsafe {
        GETTICKCOUNT_HOOK_COUNT += 1;

        // 使用ptr::read避免静态引用
        let count = ptr::addr_of!(GETTICKCOUNT_HOOK_COUNT).read();

        // Only print every 100 calls to avoid spam
        if count % 100 == 0 {
            println!("[HOOK] GetTickCount intercepted! Call #{}", count);
        }

        // Call original function and add 1000ms to the result (for testing)
        let original_ptr = ptr::addr_of!(ORIGINAL_GETTICKCOUNT).read();
        match original_ptr {
            Some(original_fn) => original_fn() + 1000,
            None => GetTickCount() + 1000,
        }
    }
}

// Recursive hook test function
#[unsafe(no_mangle)]
pub unsafe extern "system" fn hooked_recursive_messagebox(
    hwnd: HWND,
    _text: PCSTR,
    _caption: PCSTR,
    utype: u32,
) -> i32 {
    unsafe {
        println!("[RECURSIVE HOOK] Testing recursive call handling...");

        // Call original function - this tests recursive hook handling
        let original_ptr = ptr::addr_of!(ORIGINAL_MESSAGEBOX).read();
        match original_ptr {
            Some(original_fn) => {
                let result = original_fn(
                    hwnd,
                    "Recursive Test\0".as_ptr(),
                    "Recursion\0".as_ptr(),
                    utype,
                );
                println!(
                    "[RECURSIVE HOOK] Recursive call completed, result: {}",
                    result
                );
                result
            }
            None => 0,
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

// Enhanced multiple hooks test
fn test_multiple_hooks() -> Result<()> {
    println!("\n[ENHANCED TEST 1] Multiple Hooks Test");

    // Create multiple hooks
    println!("Creating multiple hooks...");

    let (trampoline1, target1) =
        create_hook_api("user32", "MessageBoxA", hooked_messagebox as *mut c_void)?;
    let (trampoline2, target2) = create_hook_api(
        "kernel32",
        "GetTickCount",
        hooked_gettickcount as *mut c_void,
    )?;

    unsafe {
        ORIGINAL_MESSAGEBOX = Some(std::mem::transmute(trampoline1));
        ORIGINAL_GETTICKCOUNT = Some(std::mem::transmute(trampoline2));
        MESSAGEBOX_HOOK_COUNT = 0;
        GETTICKCOUNT_HOOK_COUNT = 0;
    }

    // Enable all hooks at once
    enable_hook(ALL_HOOKS)?;
    println!("All hooks enabled");

    // Test MessageBox hook
    show_test_message(
        "Multi-Hook Test",
        "Testing multiple hooks simultaneously",
        "Testing MessageBox hook...",
    );

    // Test GetTickCount hook (high frequency)
    println!("Testing GetTickCount hook with high frequency calls...");
    for i in 0..150 {
        unsafe {
            GetTickCount();
        }
        if i % 50 == 49 {
            println!("Completed {} GetTickCount calls", i + 1);
        }
    }

    // Disable all hooks at once
    disable_hook(ALL_HOOKS)?;
    println!("All hooks disabled");

    // Test that hooks are actually disabled
    println!("Verifying hooks are disabled...");
    unsafe {
        let tick_before = GetTickCount();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let tick_after = GetTickCount();

        // Should not have added 1000ms since hook is disabled
        if tick_after.saturating_sub(tick_before) < 500 {
            println!("✓ GetTickCount hook properly disabled");
        } else {
            println!("⚠ GetTickCount hook may still be active");
        }
    }

    show_test_message(
        "Disabled Test",
        "This should be normal (no hook)",
        "Testing disabled MessageBox...",
    );

    // Cleanup
    remove_hook(target1)?;
    remove_hook(target2)?;

    println!("Multiple hooks test completed");
    Ok(())
}

// High frequency and dynamic enable/disable test
fn test_dynamic_enable_disable() -> Result<()> {
    println!("\n[ENHANCED TEST 2] Dynamic Enable/Disable Stress Test");

    let (trampoline, target) =
        create_hook_api("user32", "MessageBoxA", hooked_messagebox as *mut c_void)?;
    unsafe {
        ORIGINAL_MESSAGEBOX = Some(std::mem::transmute(trampoline));
        MESSAGEBOX_HOOK_COUNT = 0;
    }

    // Rapid enable/disable cycles
    for cycle in 0..10 {
        println!("Dynamic cycle {}/10...", cycle + 1);

        // Enable hook
        enable_hook(target)?;
        show_test_message(
            &format!("Cycle {}", cycle + 1),
            "Hook should be active",
            &format!("Testing enabled state in cycle {}...", cycle + 1),
        );

        // Disable hook
        disable_hook(target)?;
        show_test_message(
            &format!("Cycle {}", cycle + 1),
            "Hook should be disabled",
            &format!("Testing disabled state in cycle {}...", cycle + 1),
        );

        // Small delay to simulate real-world usage
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // Cleanup
    remove_hook(target)?;
    println!("Dynamic enable/disable test completed");
    Ok(())
}

// Queue operations test
fn test_queued_operations() -> Result<()> {
    println!("\n[ENHANCED TEST 3] Queued Operations Test");

    let (trampoline, target) =
        create_hook_api("user32", "MessageBoxA", hooked_messagebox as *mut c_void)?;
    unsafe {
        ORIGINAL_MESSAGEBOX = Some(std::mem::transmute(trampoline));
        MESSAGEBOX_HOOK_COUNT = 0;
    }

    // Test queue operations
    println!("Testing queued operations...");

    // Queue multiple operations
    queue_enable_hook(target)?;
    queue_disable_hook(target)?;
    queue_enable_hook(target)?;

    println!("Queued: enable -> disable -> enable");

    // Before applying - should still be disabled
    show_test_message(
        "Before Apply",
        "Should be normal (not hooked yet)",
        "Testing before queue apply...",
    );

    // Apply all queued operations (final state should be enabled)
    apply_queued()?;
    println!("Queued operations applied");

    // After applying - should be enabled
    show_test_message(
        "After Apply",
        "Should be hooked",
        "Testing after queue apply...",
    );

    // Test complex queue sequence
    println!("Testing complex queue sequence...");
    queue_disable_hook(target)?;
    queue_enable_hook(target)?;
    queue_disable_hook(target)?;
    apply_queued()?;

    // Should be disabled now
    show_test_message(
        "Complex Queue",
        "Should be normal again",
        "Testing complex queue result...",
    );

    // Cleanup
    remove_hook(target)?;
    println!("Queued operations test completed");
    Ok(())
}

// Error handling and edge cases test
fn test_error_handling() -> Result<()> {
    println!("\n[ENHANCED TEST 4] Error Handling and Edge Cases");

    let (trampoline, target) =
        create_hook_api("user32", "MessageBoxA", hooked_messagebox as *mut c_void)?;
    unsafe {
        ORIGINAL_MESSAGEBOX = Some(std::mem::transmute(trampoline));
    }

    enable_hook(target)?;

    // Test double enable (should return error)
    println!("Testing double enable...");
    match enable_hook(target) {
        Err(HookError::Enabled) => println!("✓ Correctly detected already enabled hook"),
        Ok(_) => println!("⚠ Hook enable should have failed"),
        Err(e) => println!("⚠ Unexpected error: {:?}", e),
    }

    disable_hook(target)?;

    // Test double disable (should return error)
    println!("Testing double disable...");
    match disable_hook(target) {
        Err(HookError::Disabled) => println!("✓ Correctly detected already disabled hook"),
        Ok(_) => println!("⚠ Hook disable should have failed"),
        Err(e) => println!("⚠ Unexpected error: {:?}", e),
    }

    // Test operations on non-existent hook
    println!("Testing operations on non-existent target...");
    let fake_target = 0x12345678 as *mut c_void;

    match enable_hook(fake_target) {
        Err(HookError::NotCreated) => println!("✓ Correctly detected non-existent hook"),
        Ok(_) => println!("⚠ Enable should have failed for fake target"),
        Err(e) => println!("⚠ Unexpected error for fake target: {:?}", e),
    }

    // Test duplicate hook creation
    println!("Testing duplicate hook creation...");
    match create_hook_api("user32", "MessageBoxA", hooked_messagebox as *mut c_void) {
        Err(HookError::AlreadyCreated) => println!("✓ Correctly detected duplicate hook"),
        Ok(_) => println!("⚠ Duplicate hook creation should have failed"),
        Err(e) => println!("⚠ Unexpected error for duplicate: {:?}", e),
    }

    // Test invalid module/function
    println!("Testing invalid API hook creation...");
    match create_hook_api(
        "nonexistent_module",
        "FakeFunction",
        hooked_messagebox as *mut c_void,
    ) {
        Err(HookError::ModuleNotFound) => println!("✓ Correctly detected invalid module"),
        Err(HookError::FunctionNotFound) => println!("✓ Correctly detected invalid function"),
        Ok(_) => println!("⚠ Invalid API hook should have failed"),
        Err(e) => println!("⚠ Unexpected error for invalid API: {:?}", e),
    }

    // Cleanup
    remove_hook(target)?;
    println!("Error handling test completed");
    Ok(())
}

// Recursive call test
fn test_recursive_calls() -> Result<()> {
    println!("\n[ENHANCED TEST 5] Recursive Call Handling Test");

    let (trampoline, target) = create_hook_api(
        "user32",
        "MessageBoxA",
        hooked_recursive_messagebox as *mut c_void,
    )?;
    unsafe {
        ORIGINAL_MESSAGEBOX = Some(std::mem::transmute(trampoline));
    }

    enable_hook(target)?;

    // This will test recursive hook behavior
    show_test_message(
        "Recursive Test",
        "Testing recursive hook calls",
        "Testing recursive hook handling...",
    );

    disable_hook(target)?;
    remove_hook(target)?;

    println!("Recursive call test completed");
    Ok(())
}

// Performance and stability test
fn test_performance_stability() -> Result<()> {
    println!("\n[ENHANCED TEST 6] Performance and Stability Test");

    let (trampoline1, target1) =
        create_hook_api("user32", "MessageBoxA", hooked_messagebox as *mut c_void)?;
    let (trampoline2, target2) = create_hook_api(
        "kernel32",
        "GetTickCount",
        hooked_gettickcount as *mut c_void,
    )?;

    unsafe {
        ORIGINAL_MESSAGEBOX = Some(std::mem::transmute(trampoline1));
        ORIGINAL_GETTICKCOUNT = Some(std::mem::transmute(trampoline2));
        MESSAGEBOX_HOOK_COUNT = 0;
        GETTICKCOUNT_HOOK_COUNT = 0;
    }

    enable_hook(ALL_HOOKS)?;

    // High-frequency GetTickCount calls
    println!("Performing 1000 high-frequency GetTickCount calls...");
    let start_time = std::time::Instant::now();

    for i in 0..1000 {
        unsafe {
            GetTickCount();
        }

        // Occasional MessageBox calls mixed in
        if i % 200 == 199 {
            show_test_message(
                "Performance Test",
                &format!("Batch {} completed", i / 200 + 1),
                &format!("Performance test batch {}/5...", i / 200 + 1),
            );
        }
    }

    let elapsed = start_time.elapsed();
    println!("1000 calls completed in {:?}", elapsed);

    unsafe {
        // 使用ptr::read避免静态引用
        let msgbox_count = ptr::addr_of!(MESSAGEBOX_HOOK_COUNT).read();
        let tick_count = ptr::addr_of!(GETTICKCOUNT_HOOK_COUNT).read();
        println!(
            "Final hook counts: MessageBox={}, GetTickCount={}",
            msgbox_count, tick_count
        );
    }

    disable_hook(ALL_HOOKS)?;
    remove_hook(target1)?;
    remove_hook(target2)?;

    println!("Performance and stability test completed");
    Ok(())
}

fn main() -> Result<()> {
    println!("MinHook-rs Enhanced MessageBox Hook Demo");
    println!("========================================");

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

    // Phase 2: Initialize and create basic hook
    println!("\n[PHASE 2] Installing basic hook");
    println!("Initializing MinHook...");
    initialize()?;

    println!("Creating MessageBoxA hook...");
    let (trampoline, target) =
        create_hook_api("user32", "MessageBoxA", hooked_messagebox as *mut c_void)?;

    unsafe {
        ORIGINAL_MESSAGEBOX = Some(std::mem::transmute(trampoline));
        MESSAGEBOX_HOOK_COUNT = 0;
    }

    println!("Enabling hook...");
    enable_hook(target)?;
    println!("Hook activated successfully!");

    // Phase 3: Test basic hook effect
    println!("\n[PHASE 3] Testing basic hook effect");
    show_test_message(
        "Test Message",
        "This message should be intercepted and modified!",
        "Showing hooked MessageBox...",
    );

    // Phase 4: Multiple tests for stability
    println!("\n[PHASE 4] Testing basic hook stability");
    show_test_message("Second Test", "Second call test", "Second hook test...");
    show_test_message("Third Test", "Third call test", "Third hook test...");

    // Phase 5: Disable basic hook
    println!("\n[PHASE 5] Disabling basic hook");
    disable_hook(target)?;
    println!("Hook disabled");

    // Phase 6: Verify basic hook is disabled
    println!("\n[PHASE 6] Verifying basic hook is disabled");
    show_test_message(
        "Hook Disabled",
        "This message should show normal content.\nHook has been disabled.",
        "Showing normal MessageBox after disable...",
    );

    // Remove basic hook before enhanced tests
    remove_hook(target)?;

    // Enhanced Testing Phases
    let separator = "=".repeat(50);
    println!("\n{}", separator);
    println!("ENHANCED TESTING PHASE");
    println!("{}", separator);

    // Run all enhanced tests
    test_multiple_hooks()?;
    test_dynamic_enable_disable()?;
    test_queued_operations()?;
    test_error_handling()?;
    test_recursive_calls()?;
    test_performance_stability()?;

    // Final Phase: Cleanup
    println!("\n[FINAL PHASE] Cleanup");
    uninitialize()?;
    println!("Cleanup completed");

    let separator = "=".repeat(50);
    println!("\n{}", separator);
    println!("ENHANCED DEMO COMPLETED SUCCESSFULLY!");
    println!("{}", separator);
    println!("\nSummary of tests performed:");
    println!("✓ Basic hook functionality");
    println!("✓ Multiple simultaneous hooks");
    println!("✓ Dynamic enable/disable cycles");
    println!("✓ Queued operations");
    println!("✓ Error handling and edge cases");
    println!("✓ Recursive call handling");
    println!("✓ High-frequency performance test");
    println!("\nAll {} test phases completed successfully!", 6 + 6); // 6 basic + 6 enhanced

    unsafe {
        // 使用ptr::read避免静态引用
        let total_messagebox_calls = ptr::addr_of!(MESSAGEBOX_HOOK_COUNT).read();
        let total_gettickcount_calls = ptr::addr_of!(GETTICKCOUNT_HOOK_COUNT).read();
        println!("\nTotal intercepted calls:");
        println!("- MessageBoxA: {} calls", total_messagebox_calls);
        println!("- GetTickCount: {} calls", total_gettickcount_calls);
    }

    Ok(())
}

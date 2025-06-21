# MinHook-rs

[![Crates.io](https://img.shields.io/crates/v/min_hook_rs)](https://crates.io/crates/min_hook_rs)
[![Documentation](https://docs.rs/min_hook_rs/badge.svg)](https://docs.rs/min_hook_rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Rust implementation of the MinHook library for Windows x64 function hooking.

## Installation

```toml
[dependencies]
min_hook_rs = "1.2"
windows-sys = { version = "0.60", features = [
    "Win32_UI_WindowsAndMessaging", 
    "Win32_Foundation"
] }
```

## Quick Start

```rust
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
```

The output may be

```plaintext
MinHook-rs MessageBox Hook Demo                                                                                                                                     
================================

[PHASE 1] Testing original MessageBox behavior
Showing original MessageBox...

[PHASE 2] Installing hook
Initializing MinHook...
Creating MessageBoxA hook...
Enabling hook...
Hook activated successfully!

[PHASE 3] Testing hook effect
Showing hooked MessageBox...
[HOOK] MessageBoxA intercepted!

[PHASE 4] Testing hook stability
Second hook test...
[HOOK] MessageBoxA intercepted!
Third hook test...
[HOOK] MessageBoxA intercepted!

[PHASE 5] Disabling hook
Hook disabled

[PHASE 6] Verifying hook is disabled
Showing normal MessageBox after disable...

[PHASE 7] Cleanup
Cleanup completed

Demo completed successfully!

Summary:
- Original behavior: Normal MessageBox
- Hook active: Message intercepted and modified
- Hook disabled: Normal behavior restored
- Complete cleanup: System returned to initial state
```

## Examples

### Basic Hook Example

Run the comprehensive demonstration example:

```bash
cargo run --example basic_hook
```

This example demonstrates all MinHook-rs features including basic hooks, multiple simultaneous hooks, dynamic enable/disable cycles, queued operations, error handling, and performance testing with detailed output.

### DLL Hook Examples

Complete DLL hooking workflow with injector and target programs:

```bash
# Build hook DLL and test programs
cargo build --example simple_messagebox_hook --target x86_64-pc-windows-msvc --release
cargo build --example simple_injector --target x86_64-pc-windows-msvc --release  
cargo build --example messagebox_test --target x86_64-pc-windows-msvc --release

# Start test program (displays several MessageBox dialogs)
start target/x86_64-pc-windows-msvc/release/examples/messagebox_test.exe

# Find process ID and inject hook DLL
tasklist | findstr messagebox_test
target/x86_64-pc-windows-msvc/release/examples/simple_injector.exe <PID> target/x86_64-pc-windows-msvc/release/examples/simple_messagebox_hook.dll
```

### Notepad Hook Example

Real-world application hooking - intercepts Notepad's exit confirmation dialog:

```bash
# Build Notepad hook DLL and injector
cargo build --example notepad_hook_dll --target x86_64-pc-windows-msvc --release
cargo build --example notepad_injector --target x86_64-pc-windows-msvc --release

# Start Notepad and inject hook
notepad.exe &
tasklist | findstr notepad
target/x86_64-pc-windows-msvc/release/examples/notepad_injector.exe <PID> target/x86_64-pc-windows-msvc/release/examples/notepad_hook_dll.dll

# Test: Type text in Notepad, try to close without saving
# You'll see a custom hook message instead of normal save dialog
```

## API Reference

### Library Management

```rust
initialize() -> Result<()>              // Initialize once at startup
uninitialize() -> Result<()>            // Cleanup at shutdown
is_supported() -> bool                  // Check platform compatibility
```

### Hook Creation

```rust
// Hook by function address
create_hook(target: *mut c_void, detour: *mut c_void) -> Result<*mut c_void>

// Hook by API name (returns trampoline and target)
create_hook_api(module: &str, func: &str, detour: *mut c_void) 
    -> Result<(*mut c_void, *mut c_void)>

// Remove hook
remove_hook(target: *mut c_void) -> Result<()>
```

### Hook Control

```rust
enable_hook(target: *mut c_void) -> Result<()>    // Use ALL_HOOKS for all
disable_hook(target: *mut c_void) -> Result<()>   // Use ALL_HOOKS for all

// Atomic batch operations
queue_enable_hook(target: *mut c_void) -> Result<()>
queue_disable_hook(target: *mut c_void) -> Result<()>
apply_queued() -> Result<()>
```

### Instruction Analysis

```rust
decode_instruction(code: &[u8]) -> HookInstruction
can_hook_safely(code: &[u8], hook_size: usize) -> bool
status_to_string(error: HookError) -> &'static str
```

## Usage Patterns

### Hook by Address

```rust
use min_hook_rs::*;
use std::ffi::c_void;

unsafe extern "system" fn my_hook() -> i32 { 42 }

fn main() -> Result<()> {
    initialize()?;
    let target = 0x12345678 as *mut c_void;
    let trampoline = create_hook(target, my_hook as *mut c_void)?;
    enable_hook(target)?;
    disable_hook(target)?;
    remove_hook(target)?;
    uninitialize()?;
    Ok(())
}
```

### Multiple Hooks

```rust
unsafe extern "system" fn hook1() {}
unsafe extern "system" fn hook2() {}

fn main() -> Result<()> {
    initialize()?;
    
    let (_, target1) = create_hook_api("user32", "MessageBoxA", hook1 as *mut c_void)?;
    let (_, target2) = create_hook_api("kernel32", "GetTickCount", hook2 as *mut c_void)?;
    
    enable_hook(ALL_HOOKS)?;   // Enable all at once
    disable_hook(ALL_HOOKS)?;  // Disable all at once
    
    remove_hook(target1)?;
    remove_hook(target2)?;
    uninitialize()?;
    Ok(())
}
```

### Queued Operations

```rust
fn main() -> Result<()> {
    let target = std::ptr::null_mut(); // Your target
    
    queue_enable_hook(target)?;
    queue_disable_hook(target)?;
    queue_enable_hook(target)?;
    apply_queued()?;  // Apply all operations atomically
    Ok(())
}
```

### Error Handling

```rust
match create_hook_api("user32", "MessageBoxA", hook_fn as *mut c_void) {
    Ok((trampoline, target)) => println!("Hook created at {:p}", target),
    Err(HookError::ModuleNotFound) => println!("Module not loaded"),
    Err(HookError::FunctionNotFound) => println!("Function not found"),
    Err(e) => println!("Error: {}", status_to_string(e)),
}
```

## x86_64 Instruction Format

x86_64 instructions have variable-length encoding:

```
[Prefixes] [REX] [Opcode] [ModR/M] [SIB] [Displacement] [Immediate]
   0-4      0-1    1-3      0-1     0-1      0-8          0-8     (bytes)
```

### Critical Instructions for Hooking

**RIP-relative addressing** (requires relocation):

```asm
mov rax, [rip + offset]      ; 48 8B 05 xx xx xx xx
lea rax, [rip + offset]      ; 48 8D 05 xx xx xx xx
call [rip + offset]          ; FF 15 xx xx xx xx
```

**Control flow instructions**:

```asm
call rel32                  ; E8 xx xx xx xx
jmp rel32                   ; E9 xx xx xx xx
jz rel32                    ; 0F 84 xx xx xx xx
```

### Instruction Analysis

```rust
let code = &[0x48, 0x8B, 0x05, 0x12, 0x34, 0x56, 0x78];
let inst = decode_instruction(code);

println!("Length: {}", inst.len);
println!("RIP-relative: {}", inst.is_rip_relative());
println!("Displacement: 0x{:08X}", inst.displacement);

if can_hook_safely(&[0x48, 0x83, 0xEC, 0x28], 5) {
    println!("Safe to install 5-byte hook");
}
```

## Hook Implementation

Function hooking works by code patching:

```
Original: [Target] -> [Function Body] -> [Return]
Hooked:   [Target] -> [Hook] -> [Trampoline] -> [Original Body] -> [Return]
```

Process:

1. **Analysis**: Decode instructions at hook location
2. **Trampoline**: Allocate memory, copy displaced instructions
3. **Relocation**: Fix RIP-relative addresses
4. **Installation**: Replace function start with jump to hook
5. **Thread Safety**: Suspend threads during patching

## Error Types

| Error | Description |
|-------|-------------|
| `NotInitialized` | Call `initialize()` first |
| `AlreadyCreated` | Hook already exists |
| `NotCreated` | Hook doesn't exist |
| `Enabled/Disabled` | Hook already in requested state |
| `ModuleNotFound` | Module not loaded |
| `FunctionNotFound` | Function not exported |
| `UnsupportedFunction` | Cannot hook this function |
| `MemoryAlloc/MemoryProtect` | Memory operation failed |

## Best Practices

### Hook Functions

- Match exact signatures including calling convention
- Use `ptr::addr_of!` for thread-safe static access
- Keep hook logic minimal for performance
- Handle edge cases gracefully

### Memory Management

```rust
fn main() -> Result<()> {
    initialize()?;                    // 1. Initialize
    let (trampoline, target) = create_hook_api(...)?;  // 2. Create
    enable_hook(target)?;             // 3. Enable
    // ... use hooks ...
    disable_hook(target)?;            // 4. Disable
    remove_hook(target)?;             // 5. Remove
    uninitialize()?;                  // 6. Cleanup
    Ok(())
}
```

### Safety

- Run as Administrator for system hooks
- Validate target function addresses
- Use correct calling conventions (`extern "system"`)
- Proper cleanup to avoid crashes

## Requirements

- Architecture: x86_64
- OS: Windows
- Rust: 1.85.0+

## License

MIT License

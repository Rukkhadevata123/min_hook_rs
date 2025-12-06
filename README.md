# MinHook-rs

[![Crates.io](https://img.shields.io/crates/v/min_hook_rs)](https://crates.io/crates/min_hook_rs)
[![Documentation](https://docs.rs/min_hook_rs/badge.svg)](https://docs.rs/min_hook_rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Rust implementation of the MinHook library for Windows x64 function hooking.

## Installation

```toml
[dependencies]
min_hook_rs = "2.1"
windows-sys = { version = "0.61", features = [
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

Expected output:

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

// Queued (deferred) operations
queue_enable_hook(target: *mut c_void) -> Result<()>
queue_disable_hook(target: *mut c_void) -> Result<()>
apply_queued() -> Result<()>   // Apply all queued enable/disable requests in one step
```

> **Note:** Queued operations do not take effect until you call `apply_queued()`. This allows you to schedule multiple enable/disable changes and apply them atomically and safely.

### Instruction Analysis

```rust
decode_instruction(code: &[u8]) -> HookInstruction
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

## x86_64 Instruction Structure

x86_64 instructions use variable-length encoding (1-15 bytes):

```
[Prefixes] [REX] [Opcode] [ModR/M] [SIB] [Displacement] [Immediate]
   0-4      0-1    1-3      0-1     0-1      0-8          0-8     (bytes)
```

### Instruction Components

**Legacy Prefixes (0-4 bytes):**

- `F0` - LOCK prefix
- `F2/F3` - REP/REPE/REPNE prefixes  
- `2E/36/3E/26/64/65` - Segment override
- `66` - Operand size override (16-bit)
- `67` - Address size override

**REX Prefix (0-1 byte, x64 only):**

```
4     3     2     1     0
W     R     X     B
```

- W: 64-bit operand size
- R: Extension of ModR/M reg field
- X: Extension of SIB index field  
- B: Extension of ModR/M r/m or SIB base field

**ModR/M Byte:**

```
7   6     5   3     2   0
mod       reg       r/m
```

- `mod`: Addressing mode (00/01/10/11)
- `reg`: Register or opcode extension
- `r/m`: Register or memory operand

**SIB Byte (if ModR/M indicates):**

```
7   6     5   3     2   0
scale     index     base
```

- `scale`: 1, 2, 4, or 8 times multiplier
- `index`: Index register
- `base`: Base register

### Critical Instructions for Hooking

**RIP-relative addressing** (requires relocation):

```asm
mov rax, [rip + offset]      ; 48 8B 05 xx xx xx xx
lea rax, [rip + offset]      ; 48 8D 05 xx xx xx xx
call [rip + offset]          ; FF 15 xx xx xx xx
```

**Direct relative jumps/calls:**

```asm
call rel32                  ; E8 xx xx xx xx
jmp rel32                   ; E9 xx xx xx xx
jz rel32                    ; 0F 84 xx xx xx xx
```

### Instruction Analysis Example

```rust
let code = &[0x48, 0x8B, 0x05, 0x12, 0x34, 0x56, 0x78];
let inst = decode_instruction(code);

println!("Length: {}", inst.len);            // 7
println!("RIP-relative: {}", inst.is_rip_relative()); // true
println!("Displacement: 0x{:08X}", inst.displacement); // 0x78563412
```

## Hook Implementation

Function hooking replaces the target function's prologue with a jump to the detour:

```
Original: [Function Prologue] -> [Function Body] -> [Return]
Hooked:   [JMP to Relay] -> [Detour] -> [Trampoline] -> [Original Body] -> [Return]
```

### Process Steps

1. **Disassemble**: Decode instructions at target location
2. **Relocate**: Fix RIP-relative addresses in copied instructions  
3. **Trampoline**: Create executable memory with original code + jump back
4. **Relay**: Create x64 absolute jump to detour function
5. **Patch**: Atomically replace target prologue with jump to relay
6. **Thread Safety**: Suspend/resume threads during patching

### Memory Layout

```
Target Function:     [E9 xx xx xx xx] -> Jump to Relay
                     [Original bytes backed up]

Trampoline Buffer:   [Relocated original instructions]
                     [JMP back to Target+5]
                     [Relay: JMP to Detour]
```

## Error Types

| Error | Description |
|-------|-------------|
| `NotInitialized` | Call `initialize()` first |
| `AlreadyCreated` | Hook already exists for target |
| `NotCreated` | Hook doesn't exist for target |
| `Enabled/Disabled` | Hook already in requested state |
| `ModuleNotFound` | Specified module not loaded |
| `FunctionNotFound` | Function not exported by module |
| `UnsupportedFunction` | Cannot hook this function safely |
| `MemoryAlloc/MemoryProtect` | Memory operation failed |

## Best Practices

### Function Signatures

- Match exact calling conventions (`extern "system"` for Windows APIs)
- Use proper parameter types and return values
- Handle edge cases and error conditions

### Memory Management

```rust
fn main() -> Result<()> {
    initialize()?;                    // 1. Initialize library
    let (trampoline, target) = create_hook_api(...)?;  // 2. Create hook
    enable_hook(target)?;             // 3. Enable hook
    // ... application logic ...
    disable_hook(target)?;            // 4. Disable hook
    remove_hook(target)?;             // 5. Remove hook
    uninitialize()?;                  // 6. Cleanup library
    Ok(())
}
```

### Safety Guidelines

- Run as Administrator for system-level hooks
- Validate function addresses before hooking
- Use thread-safe access patterns for hook data
- Proper cleanup prevents crashes and memory leaks

## Requirements

- **Architecture**: x86_64 only
- **Operating System**: Windows
- **Rust Version**: 1.85.0+
- **Privileges**: Administrator for system hooks

## License

MIT License - see LICENSE file for details.

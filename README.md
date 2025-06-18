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
use min_hook_rs::*;
use std::ffi::c_void;
use std::ptr;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;
use windows_sys::core::PCSTR;

type MessageBoxAFn = unsafe extern "system" fn(HWND, PCSTR, PCSTR, u32) -> i32;
static mut ORIGINAL_MESSAGEBOX: Option<MessageBoxAFn> = None;

unsafe extern "system" fn hooked_messagebox(
    hwnd: HWND, _text: PCSTR, _caption: PCSTR, utype: u32
) -> i32 {
    let new_text = "Hooked by MinHook-rs!\0";
    let new_caption = "Hook Demo\0";
    
    let original = ptr::addr_of!(ORIGINAL_MESSAGEBOX).read().unwrap();
    original(hwnd, new_text.as_ptr(), new_caption.as_ptr(), utype)
}

fn main() -> Result<()> {
    initialize()?;

    let (trampoline, target) = create_hook_api(
        "user32", 
        "MessageBoxA", 
        hooked_messagebox as *mut c_void
    )?;

    unsafe {
        ORIGINAL_MESSAGEBOX = Some(std::mem::transmute(trampoline));
    }

    enable_hook(target)?;

    unsafe {
        MessageBoxA(ptr::null_mut(), "Test\0".as_ptr(), "Title\0".as_ptr(), MB_OK);
    }

    disable_hook(target)?;
    remove_hook(target)?;
    uninitialize()?;
    Ok(())
}
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

## Examples

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

## Running Examples

```bash
# Windows native
cargo run --example basic_hook

# Cross-compilation
cargo build --example basic_hook --target x86_64-pc-windows-msvc --release
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

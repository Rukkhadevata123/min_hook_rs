# MinHook-rs

[![Crates.io](https://img.shields.io/crates/v/min_hook_rs)](https://crates.io/crates/min_hook_rs)
[![Documentation](https://docs.rs/min_hook_rs/badge.svg)](https://docs.rs/min_hook_rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Rust implementation of the MinHook library for Windows x64 function hooking.

## Features

- **Precise instruction decoder** - Custom x64 disassembler optimized for hook creation
- **Thread-safe operations** - All APIs are thread-safe with proper synchronization  
- **Memory efficient** - Minimal memory footprint with optimized data structures
- **Comprehensive error handling** - Detailed error reporting for all edge cases
- **Production ready** - Extensively tested with multiple hook scenarios
- **Zero-copy design** - Efficient instruction processing without unnecessary allocations

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
min_hook_rs = "1.2.0"
windows-sys = { version = "0.60", features = ["Win32_UI_WindowsAndMessaging"] }
```

Basic usage:

```rust
use min_hook_rs::*;
use std::ffi::c_void;
use std::ptr;

// Define original function type
type MessageBoxAFn = unsafe extern "system" fn(HWND, PCSTR, PCSTR, u32) -> i32;
static mut ORIGINAL_MESSAGEBOX: Option<MessageBoxAFn> = None;

// Your hook function
unsafe extern "system" fn my_hook_function(
    hwnd: HWND, _text: PCSTR, _caption: PCSTR, _utype: u32
) -> i32 {
    let new_text = "Hooked by MinHook-rs!\0";
    let new_caption = "Hook Demo\0";
    
    // Call original function
    let original = ptr::addr_of!(ORIGINAL_MESSAGEBOX).read().unwrap();
    original(hwnd, new_text.as_ptr(), new_caption.as_ptr(), MB_ICONINFORMATION)
}

fn main() -> Result<()> {
    // 1. Initialize
    initialize()?;

    // 2. Create hook  
    let (trampoline, target) = create_hook_api(
        "user32", 
        "MessageBoxA", 
        my_hook_function as *mut c_void
    )?;

    // 3. Store original function for calling later
    unsafe {
        ORIGINAL_MESSAGEBOX = Some(std::mem::transmute(trampoline));
    }

    // 4. Enable hook
    enable_hook(target)?;

    // 5. Test the hook
    unsafe {
        MessageBoxA(ptr::null_mut(), "Test\0".as_ptr(), "Title\0".as_ptr(), MB_OK);
    }

    // 6. Cleanup
    disable_hook(target)?;
    remove_hook(target)?;
    uninitialize()?;

    Ok(())
}
```

## Examples

### Basic Hook Example

Run our comprehensive example that demonstrates all MinHook-rs features:

```bash
cargo run --example basic_hook
```

This example includes:

- Basic hook functionality with MessageBoxA interception
- Multiple simultaneous hooks (MessageBoxA + GetTickCount)
- Dynamic enable/disable cycles for stress testing
- Queued operations with batch application
- Comprehensive error handling and edge cases
- Recursive call handling and safety verification
- High-frequency performance testing with 1000+ calls
- Memory safety verification under stress conditions

The example runs 12 test phases covering all functionality aspects with detailed output and performance metrics.

### MessageBox Hook Examples

The `examples/messagebox/` directory contains comprehensive MessageBox hooking examples:

- **`simple_messagebox_hook.rs`**: DLL that hooks MessageBoxA to replace all message content
- **`simple_injector.rs`**: Generic DLL injector for testing hooks
- **`messagebox_test.rs`**: Test program that displays multiple MessageBox dialogs

Build and test:

```bash
# Build all components
cargo xwin build --example simple_messagebox_hook --target x86_64-pc-windows-msvc --release
cargo xwin build --example simple_injector --target x86_64-pc-windows-msvc --release
cargo xwin build --example messagebox_test --target x86_64-pc-windows-msvc --release

# Start test program
wine target/x86_64-pc-windows-msvc/release/examples/messagebox_test.exe &

# Find PID and inject DLL
wine tasklist | wine findstr messagebox_test
wine target/x86_64-pc-windows-msvc/release/examples/simple_injector.exe <PID> <DLL_PATH>
```

### Notepad Hook Examples

The `examples/notepad/` directory demonstrates real-world application hooking:

- **`notepad_hook_dll.rs`**: Hooks Notepad's exit confirmation dialog
- **`notepad_injector.rs`**: Specialized injector for Notepad processes

Build and test:

```bash
# Build and inject into Notepad
cargo xwin build --example notepad_hook_dll --target x86_64-pc-windows-msvc --release
cargo xwin build --example notepad_injector --target x86_64-pc-windows-msvc --release

wine notepad.exe &
wine tasklist | wine findstr notepad
wine target/x86_64-pc-windows-msvc/release/examples/notepad_injector.exe <PID> target/x86_64-pc-windows-msvc/release/examples/notepad_hook_dll.dll
```

## x86_64 Instruction Format and Disassembler

Understanding x86_64 instruction encoding is crucial for reliable function hooking. MinHook-rs includes a custom instruction decoder designed specifically for hook creation.

### Instruction Structure

x86_64 instructions use variable-length encoding with up to 7 components:

```
[Prefixes] [REX] [Opcode] [ModR/M] [SIB] [Displacement] [Immediate]
   0-4      0-1    1-3      0-1     0-1      0-8          0-8
```

**Components:**

- **Prefixes**: Operation size, segment, repeat behavior overrides
- **REX Prefix**: 64-bit extensions for registers and operand size
- **Opcode**: 1-3 bytes defining the instruction operation
- **ModR/M**: Addressing mode and register selection
- **SIB**: Scale-Index-Base for complex memory addressing
- **Displacement**: Memory offset values (8/16/32-bit)
- **Immediate**: Constant operand data (8/16/32/64-bit)

### Hook-Critical Instructions

**RIP-Relative Addressing:**

```asm
mov rax, [rip + 0x12345678]  ; Requires address relocation in trampolines
lea rax, [rip + 0x1000]      ; PC-relative memory references
call [rip + offset]          ; Indirect calls through memory
```

**Control Flow Instructions:**

```asm
call relative_addr           ; Direct relative calls
jmp short_offset            ; Short jumps (8-bit offset)
jcc long_offset             ; Conditional jumps (32-bit offset)
ret                         ; Return instructions
```

**Complex Addressing:**

```asm
mov rax, [rbp + rsi*2 + 8]  ; Scale-index-base with displacement
mov [rsp + 0x100], rbx      ; Stack operations with large offsets
```

### Decoder Features

MinHook-rs provides a specialized decoder optimized for hooking:

```rust
pub struct HookInstruction {
    pub len: u8,           // Precise instruction length
    pub opcode: u8,        // Primary opcode
    pub opcode2: u8,       // Secondary opcode (0F xx instructions)
    pub modrm: u8,         // ModR/M byte for addressing analysis
    pub immediate: i32,    // Immediate values (unified type)
    pub displacement: i32, // Displacement for RIP-relative addressing
    pub flags: u32,        // HDE64-compatible instruction flags
    pub error: bool,       // Parse error indicator
}
```

**Key Methods:**

- `is_rip_relative()` - Detect instructions requiring address relocation
- `is_call()`, `is_jmp()`, `is_conditional()` - Control flow classification
- `immediate_size()` - Calculate immediate field length for relocation
- `modrm_reg()` - Extract register fields for indirect jump detection

### HDE64 Compatibility

The decoder maintains full compatibility with the proven HDE64 algorithm:

- **Table-driven approach**: Uses comprehensive opcode lookup tables
- **Multi-stage parsing**: Prefix → REX → Opcode → ModR/M → Operands
- **Error handling**: Graceful handling of malformed instructions
- **Length accuracy**: 100% accurate instruction length calculation

## API Reference

### Core Functions

| Function | Description |
|----------|-------------|
| `initialize()` | Initialize the library |
| `uninitialize()` | Cleanup and uninitialize |
| `create_hook(target, detour)` | Create a hook for a function |
| `create_hook_api(module, func, detour)` | Create a hook by module/function name |
| `enable_hook(target)` | Enable a hook |
| `disable_hook(target)` | Disable a hook |
| `remove_hook(target)` | Remove a hook |

### Batch Operations

| Function | Description |
|----------|-------------|
| `enable_hook(ALL_HOOKS)` | Enable all hooks |
| `disable_hook(ALL_HOOKS)` | Disable all hooks |
| `queue_enable_hook(target)` | Queue hook for enable |
| `queue_disable_hook(target)` | Queue hook for disable |
| `apply_queued()` | Apply all queued operations |

### Disassembler API

| Function | Description |
|----------|-------------|
| `decode_instruction(code)` | Decode a single instruction |
| `can_hook_safely(code, len)` | Check if code region can be safely hooked |

### Utility Functions

| Function | Description |
|----------|-------------|
| `is_supported()` | Check if current platform is supported |
| `status_to_string(error)` | Convert error to string description |

## Error Handling

MinHook-rs provides comprehensive error handling:

```rust
pub enum HookError {
    Unknown,
    AlreadyInitialized,
    NotInitialized,
    AlreadyCreated,
    NotCreated,
    Enabled,
    Disabled,
    NotExecutable,
    UnsupportedFunction,
    MemoryAlloc,
    MemoryProtect,
    ModuleNotFound,
    FunctionNotFound,
}
```

## Architecture

MinHook-rs works by patching target functions and redirecting execution:

```
Original: [Target Function] → [Function Body] → [Return]
Hooked:   [Target Function] → [Hook Function] → [Trampoline] → [Original Body] → [Return]
```

**Hook Installation Process:**

1. **Analysis**: Decode instructions at target address for safe hook points
2. **Trampoline**: Allocate nearby memory and copy original instructions
3. **Relocation**: Fix RIP-relative addresses for new trampoline location
4. **Installation**: Replace target function start with jump to detour
5. **Execution**: Detour function calls original via trampoline

## Platform Support

- **Windows x64**: Full support
- **Windows x86**: Not supported  
- **Linux/macOS**: Windows-specific

## Performance

MinHook-rs is optimized for production use:

- **Low overhead**: Minimal impact on hooked function performance
- **Fast decoding**: Optimized instruction parsing with table lookups
- **Memory efficient**: Small trampoline footprint and optimized data structures
- **Thread safety**: Lock-free operations where possible

Benchmarks show excellent performance characteristics:

- **Hook creation**: Sub-millisecond trampoline generation
- **Runtime overhead**: Near-zero impact on function execution
- **Memory usage**: Minimal footprint with efficient instruction decoding

## Best Practices

### Hook Function Design

```rust
// Always match the exact signature of the target function
type TargetFn = unsafe extern "system" fn(arg1: Type1, arg2: Type2) -> RetType;
static mut ORIGINAL: Option<TargetFn> = None;

unsafe extern "system" fn hook_function(arg1: Type1, arg2: Type2) -> RetType {
    // Your hook logic here
    
    // Call original function safely
    let original = ptr::addr_of!(ORIGINAL).read().unwrap();
    original(arg1, arg2)
}
```

### Error Handling

```rust
// Handle all possible error conditions
match create_hook_api("user32", "MessageBoxA", hook_fn as *mut c_void) {
    Ok((trampoline, target)) => { /* success */ },
    Err(HookError::ModuleNotFound) => { /* handle missing module */ },
    Err(HookError::FunctionNotFound) => { /* handle missing function */ },
    Err(e) => { /* handle other errors */ },
}
```

### Cleanup

```rust
// Always cleanup in reverse order
disable_hook(target)?;
remove_hook(target)?;
uninitialize()?;
```

## License

MIT License - see [LICENSE](LICENSE) file.

## Acknowledgments

- Original [MinHook](https://github.com/TsudaKageyu/minhook) by Tsuda Kageyu
- [HDE64](https://github.com/Cerbersec/HDE64) disassembler engine by Vyacheslav Patkov
- Intel x86-64 Architecture Software Developer's Manual
- Microsoft Windows API documentation

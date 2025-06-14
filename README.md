# MinHook-rs

A Rust port of the MinHook API hooking library for Windows x64.

## Features

- **Simple**: Easy to use with just a few API calls
- **Thread-safe**: All APIs are thread-safe  
- **Memory efficient**: Minimal memory footprint
- **x64 optimized**: Full support for 64-bit Windows
- **Rust safety**: Memory-safe implementation with error handling

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
min_hook_rs = "0.1.0"
windows-sys = { version = "0.60", features = ["Win32_UI_WindowsAndMessaging"] }
```

Basic usage:

```rust
use min_hook_rs::*;
use std::ffi::c_void;

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
    // (see examples/basic_hook.rs for complete implementation)

    // 4. Enable hook
    enable_hook(target)?;

    // 5. Your code here - all calls will be intercepted

    // 6. Cleanup
    disable_hook(target)?;
    remove_hook(target)?;
    uninitialize()?;

    Ok(())
}
```

## Examples and Testing

### Basic Hook Example

```bash
cargo xwin build --example basic_hook --target x86_64-pc-windows-msvc --release
wine target/x86_64-pc-windows-msvc/release/examples/basic_hook.exe
```

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

# Find PID
wine tasklist | wine findstr messagebox_test

# Inject DLL
wine target/x86_64-pc-windows-msvc/release/examples/simple_injector.exe <PID> <DLL_PATH>
```

### Notepad Hook Examples

The `examples/notepad/` directory demonstrates real-world application hooking:

- **`notepad_hook_dll.rs`**: Hooks Notepad's exit confirmation dialog
- **`notepad_injector.rs`**: Specialized injector for Notepad processes

Build and test:

```bash
# Build components
cargo xwin build --example notepad_hook_dll --target x86_64-pc-windows-msvc --release
cargo xwin build --example notepad_injector --target x86_64-pc-windows-msvc --release

# Start Notepad
wine notepad.exe &

# Find PID
wine tasklist | wine findstr notepad

# Inject hook
wine target/x86_64-pc-windows-msvc/release/examples/notepad_injector.exe <PID> target/x86_64-pc-windows-msvc/release/examples/notepad_hook_dll.dll

# Test: Type text in Notepad, then close without saving to see custom dialog
```

Each example demonstrates different aspects of the hooking process, from simple function replacement to complex real-world application scenarios.

## x86_64 Hook Implementation

MinHook-rs uses a simplified x86_64 instruction decoder optimized for hook creation.

### Instruction Encoding Format

```
[Prefixes] [REX] [Opcode] [ModR/M] [SIB] [Displacement] [Immediate]
  0-4 bytes 0-1   1-3      0-1      0-1    0-8          0-8
```

### REX Prefix (x64 Extension)

```
0100 WRXB
     ││││
     │││└─ B: Extend base/rm register
     ││└── X: Extend SIB index register  
     │└─── R: Extend ModR/M reg field
     └──── W: 64-bit operand size
```

### ModR/M Byte Structure

```
  7 6   5 4 3   2 1 0
┌─────┬───────┬───────┐
│ mod │  reg  │  rm   │
└─────┴───────┴───────┘
```

| mod | Meaning | Example |
|-----|---------|---------|
| 00  | `[reg]` or `[RIP+disp32]` (when rm=101) | `[RAX]`, `[RIP+1234h]` |
| 01  | `[reg+disp8]` | `[RAX+12h]` |
| 10  | `[reg+disp32]` | `[RAX+12345678h]` |
| 11  | Direct register | `RAX` |

### Hook-Critical Instructions

#### RIP-Relative Addressing (`ModR/M = 00???101`)

```assembly
8B 05 12 34 56 78   ; MOV EAX, [RIP+12345678h]
```

**Hook challenge**: After copying to trampoline, RIP changes, breaking address calculation.
**Solution**: Recalculate displacement for new RIP location.

#### Relative Jumps and Calls

```assembly
E8 xx xx xx xx      ; CALL rel32    → Convert to absolute CALL
E9 xx xx xx xx      ; JMP rel32     → Convert to absolute JMP  
EB xx               ; JMP rel8      → Convert to absolute JMP
7x xx               ; Jcc rel8      → Convert to absolute conditional
0F 8x xx xx xx xx   ; Jcc rel32     → Convert to absolute conditional
```

### Trampoline Generation Process

1. **Decode**: Parse instructions to determine length and type
2. **Copy**: Regular instructions copied unchanged
3. **Relocate**: Fix RIP-relative addresses for new location  
4. **Convert**: Transform relative jumps/calls to absolute form
5. **Link**: Add final jump back to original function continuation

#### Example Transformation

Original function:

```assembly
48 83 EC 78         ; SUB RSP, 78h               (regular)
8B 05 12 34 56 78   ; MOV EAX, [RIP+12345678h]   (RIP-relative)
E8 AB CD EF 12      ; CALL rel32                 (relative call)
```

Generated trampoline:

```assembly
48 83 EC 78         ; SUB RSP, 78h               (copied unchanged)
8B 05 xx xx xx xx   ; MOV EAX, [RIP+xxxxxxxx]    (displacement fixed)
FF 15 02 00 00 00   ; CALL [RIP+8]               (absolute call)
EB 08               ; JMP +8
xx xx xx xx xx xx xx xx ; Call target address
FF 25 00 00 00 00   ; JMP [RIP+6]                (return to original)
yy yy yy yy yy yy yy yy ; Return address
```

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
| `apply_queued()` | Apply queued operations |

## Platform Support

- **Windows x64**: ✅ Full support
- **Windows x86**: ❌ Not supported  
- **Linux/macOS**: ❌ Windows-specific

## Architecture

MinHook-rs works by patching target functions and redirecting execution:

```
Original: [Target Function] → [Function Body] → [Return]
Hooked:   [Target Function] → [Hook Function] → [Trampoline] → [Original Body] → [Return]
```

The trampoline preserves the original function's behavior while allowing interception.

## License

MIT License - see [LICENSE](LICENSE) file.

## Acknowledgments

- Original [MinHook](https://github.com/TsudaKageyu/minhook) by Tsuda Kageyu
- Intel x86-64 Architecture documentation

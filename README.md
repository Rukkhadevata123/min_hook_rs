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

## Examples

### Basic Hook Example

Run the complete example:

```bash
cargo run --example basic_hook --target x86_64-pc-windows-msvc --release
```

### MessageBox Hook Examples

The `examples/messagebox/` directory contains comprehensive MessageBox hooking examples:

- **`simple_messagebox_hook.rs`**: DLL that hooks MessageBoxA to replace all message content
- **`simple_injector.rs`**: Generic DLL injector for testing hooks
- **`messagebox_test.rs`**: Test program that displays multiple MessageBox dialogs

Build and test:

```bash
# Build the hook DLL
cargo xwin build --example simple_messagebox_hook --target x86_64-pc-windows-msvc --release

# Build the injector
cargo xwin build --example simple_injector --target x86_64-pc-windows-msvc --release

# Build test program
cargo xwin build --example messagebox_test --target x86_64-pc-windows-msvc --release

# Usage: inject DLL into test program
wine target/x86_64-pc-windows-msvc/release/examples/simple_injector.exe <PID> <DLL_PATH>
```

### Notepad Hook Examples

The `examples/notepad/` directory demonstrates real-world application hooking:

- **`notepad_hook_dll.rs`**: Hooks Notepad's exit confirmation dialog
- **`notepad_injector.rs`**: Specialized injector for Notepad processes

Build and test:

```bash
# Build the Notepad hook DLL
cargo xwin build --example notepad_hook_dll --target x86_64-pc-windows-msvc --release

# Build the injector
cargo xwin build --example notepad_injector --target x86_64-pc-windows-msvc --release

# Start Notepad
wine notepad.exe &

# Find Notepad PID
ps aux | grep notepad

# Inject hook
wine target/x86_64-pc-windows-msvc/release/examples/notepad_injector.exe <PID> target/x86_64-pc-windows-msvc/release/examples/notepad_hook_dll.dll

# Test: Type text in Notepad, then try to close without saving
# You should see a custom dialog instead of the normal save confirmation
```

## Testing

The library includes comprehensive test examples:

1. **Basic Hook**: Simple MessageBoxA interception (`basic_hook.rs`)
2. **MessageBox Examples**: Complete DLL injection workflow (`examples/messagebox/`)
3. **Real Application Hook**: Notepad dialog interception (`examples/notepad/`)

Each example demonstrates different aspects of the hooking process, from simple function replacement to complex real-world application scenarios.

## x86_64 Instruction Format

MinHook-rs uses a simplified x86_64 instruction decoder specifically designed for hook creation. Understanding the instruction format helps explain how the library works:

### Instruction Structure

```
[Legacy Prefixes] [REX] [Opcode] [ModR/M] [SIB] [Displacement] [Immediate]
     0-4 bytes    0-1   1-3 bytes  0-1     0-1    0-8 bytes     0-8 bytes
```

### Key Components for Hooking

#### 1. REX Prefix (x64 Extension)

```
0100 WRXB
  │   ││││
  │   │││└─ B: Extend base register
  │   ││└── X: Extend index register  
  │   │└─── R: Extend reg field
  │   └──── W: 64-bit operand
  └──────── Fixed 0100 pattern
```

#### 2. ModR/M Byte

```
  7 6   5 4 3   2 1 0
┌─────┬───────┬───────┐
│ mod │  reg  │  rm   │
└─────┴───────┴───────┘
```

| mod | Addressing Mode | Example |
|-----|-----------------|---------|
| 00  | `[reg]` | `[RAX]` |
| 01  | `[reg+disp8]` | `[RAX+12h]` |
| 10  | `[reg+disp32]` | `[RAX+12345678h]` |
| 11  | `reg` | `RAX` (direct) |

#### 3. Critical for Hooks: RIP-Relative Addressing

When `ModR/M = 00???101`, the instruction uses RIP-relative addressing:

```assembly
8B 05 12 34 56 78   ; MOV EAX, [RIP+12345678h]
```

**Why this matters for hooks:**

- Original address: `RIP + displacement`
- After copying to trampoline: Address calculation breaks
- MinHook-rs automatically fixes these addresses

### Hook-Relevant Instructions

#### Jump and Call Instructions

```assembly
E8 xx xx xx xx      ; CALL rel32    - Converted to absolute CALL
E9 xx xx xx xx      ; JMP rel32     - Converted to absolute JMP  
EB xx               ; JMP rel8      - Converted to absolute JMP
7x xx               ; Jcc rel8      - Conditional jumps
0F 8x xx xx xx xx   ; Jcc rel32     - Long conditional jumps
```

#### Return Instructions

```assembly
C2 xx xx           ; RET imm16     - Function end marker
C3                  ; RET           - Function end marker
```

### How MinHook-rs Processes Instructions

1. **Decode**: Parse instruction components (length, type, operands)
2. **Classify**: Identify instruction type (regular, RIP-relative, jump, call, return)
3. **Copy**: Regular instructions copied as-is
4. **Convert**: Relative instructions converted to absolute addressing
5. **Relocate**: RIP-relative addresses recalculated for new location

### Example: Trampoline Generation

Original function:

```assembly
48 83 EC 78         ; SUB RSP, 78h
8B 05 12 34 56 78   ; MOV EAX, [RIP+12345678h]  <- RIP-relative!
E8 AB CD EF 12      ; CALL 12EFCDABh            <- Relative call!
```

Generated trampoline:

```assembly
48 83 EC 78         ; SUB RSP, 78h             (copied as-is)
8B 05 xx xx xx xx   ; MOV EAX, [RIP+xxxxxxxx]  (address fixed)
FF 15 02 00 00 00   ; CALL [RIP+8]             (converted to absolute)
EB 08               ; JMP +8
xx xx xx xx xx xx xx xx ; Original call target address
FF 25 00 00 00 00   ; JMP [RIP+6]             (back to original)
yy yy yy yy yy yy yy yy ; Return address
```

This ensures the trampoline behaves identically to the original function while allowing hook interception.

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

## Testing

The library includes comprehensive test examples:

1. **Basic Hook**: Simple MessageBoxA interception (`basic_hook.rs`)
2. **MessageBox Examples**: Complete DLL injection workflow (`examples/messagebox/`)
3. **Real Application Hook**: Notepad dialog interception (`examples/notepad/`)

Each example demonstrates different aspects of the hooking process, from simple function replacement to complex real-world application scenarios.

## License

MIT License - see [LICENSE](LICENSE) file.

## Acknowledgments

- Original [MinHook](https://github.com/TsudaKageyu/minhook) by Tsuda Kageyu
- Intel x86-64 Architecture

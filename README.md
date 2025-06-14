# min_hook_rs

A Rust port of the MinHook API hooking library for Windows x64.

MinHook-rs is a minimalistic, thread-safe API hooking library that provides a simple interface for intercepting Win32 functions. It's designed for x64 Windows applications with full compatibility with the original MinHook C library.

## Features

- **Simple**: Extremely easy to use with just a few API calls
- **Thread-safe**: All APIs are thread-safe and can be called from multiple threads
- **Memory efficient**: Minimal memory footprint with smart buffer management
- **x64 optimized**: Full support for 64-bit Windows applications
- **Rust safety**: Memory-safe implementation with error handling
- **Compatible**: Drop-in replacement for original MinHook C library

## Architecture Overview

MinHook-rs implements function hooking through code patching and trampolines:

1. **Target Function**: The original function to be hooked
2. **Detour Function**: Your replacement function
3. **Trampoline**: A dynamically generated function containing the original prologue
4. **Hook**: A jump instruction that redirects execution to the detour

```
Original Function Flow:
[Target] → [Function Body] → [Return]

Hooked Function Flow:
[Target] → [Jump to Detour] → [Detour Function] → [Call Trampoline] → [Original Body] → [Return]
```

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
min_hook_rs = "0.1.0"
windows-sys = { version = "0.60", features = ["Win32_UI_WindowsAndMessaging"] }
```

Basic hooking example:

```rust
use min_hook_rs::*;
use std::ffi::c_void;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

// Function signature type
type MessageBoxWFn = unsafe extern "system" fn(
    hwnd: *mut c_void,
    text: *const u16,
    caption: *const u16,
    utype: u32,
) -> i32;

// Store the original function
static mut ORIGINAL_MESSAGEBOX: Option<MessageBoxWFn> = None;

// Our detour function
unsafe extern "system" fn detour_messagebox(
    hwnd: *mut c_void,
    text: *const u16,
    caption: *const u16,
    utype: u32,
) -> i32 {
    // Modify behavior or call original
    if let Some(original) = ORIGINAL_MESSAGEBOX {
        original(hwnd, text, caption, utype)
    } else {
        0
    }
}

fn main() -> Result<(), HookError> {
    // Initialize MinHook
    initialize()?;

    // Create hook for MessageBoxW
    let (trampoline, target) = create_hook_api(
        "user32",
        "MessageBoxW", 
        detour_messagebox as *mut c_void,
    )?;

    // Store the trampoline (original function)
    unsafe {
        ORIGINAL_MESSAGEBOX = Some(std::mem::transmute(trampoline));
    }

    // Enable the hook
    enable_hook(target)?;

    // Your application code here...
    // All calls to MessageBoxW will now go through your detour

    // Cleanup
    disable_hook(target)?;
    remove_hook(target)?;
    uninitialize()?;

    Ok(())
}
```

## API Reference

### Core Functions

| Function | Description |
|----------|-------------|
| `initialize()` | Initialize the MinHook library |
| `uninitialize()` | Uninitialize and cleanup |
| `create_hook(target, detour)` | Create a hook for a function |
| `create_hook_api(module, func, detour)` | Create a hook by module/function name |
| `enable_hook(target)` | Enable a created hook |
| `disable_hook(target)` | Disable an enabled hook |
| `remove_hook(target)` | Remove a hook completely |

### Batch Operations

| Function | Description |
|----------|-------------|
| `enable_hook(ALL_HOOKS)` | Enable all created hooks |
| `disable_hook(ALL_HOOKS)` | Disable all hooks |
| `queue_enable_hook(target)` | Queue hook for enable |
| `queue_disable_hook(target)` | Queue hook for disable |
| `apply_queued()` | Apply all queued operations |

### Error Handling

```rust
use min_hook_rs::{HookError, Result};

match create_hook(target, detour) {
    Ok(trampoline) => {
        // Success
    }
    Err(HookError::AlreadyCreated) => {
        // Hook already exists
    }
    Err(HookError::NotExecutable) => {
        // Invalid target address
    }
    Err(e) => {
        println!("Hook error: {}", e);
    }
}
```

## Internal Architecture

### Module Structure

```
min_hook_rs/
├── src/
│   ├── lib.rs              # Public API exports
│   ├── error.rs            # Error types and handling
│   ├── hook.rs             # Main hook management
│   ├── trampoline.rs       # Trampoline generation
│   ├── instruction.rs      # x64 instruction structures
│   ├── disasm.rs           # Instruction disassembly
│   └── buffer.rs           # Memory management
└── examples/
    └── basic_hook.rs       # Basic usage example
```

### Dependency Graph

```
error.rs (base types)
    ↓
instruction.rs (x64 structures)
    ↓
disasm.rs (instruction parsing)
    ↓
buffer.rs (memory management)
    ↓
trampoline.rs (code generation)
    ↓
hook.rs (main logic)
    ↓
lib.rs (public API)
```

## x86-64 Instruction Format

Understanding x86-64 instruction encoding is crucial for implementing hooks correctly. MinHook-rs includes a specialized disassembler for analyzing target functions.

### Instruction Structure

x86-64 instructions use variable-length encoding (1-15 bytes):

```
[Legacy Prefixes] [REX] [Opcode] [ModR/M] [SIB] [Displacement] [Immediate]
     0-4 bytes    0-1   1-3 bytes  0-1     0-1    0-8 bytes     0-8 bytes
```

### Legacy Prefixes

Prefixes modify instruction behavior and are grouped into 4 categories:

| Group | Purpose | Prefixes | Description |
|-------|---------|----------|-------------|
| 1 | Lock/Repeat | `F0` `F2` `F3` | LOCK, REPNE, REP |
| 2 | Segment | `26` `2E` `36` `3E` `64` `65` | ES, CS, SS, DS, FS, GS |
| 3 | Operand Size | `66` | 16-bit operand override |
| 4 | Address Size | `67` | 32-bit address override |

Examples:

```assembly
F3 A4           ; REP MOVSB (repeat string operation)
F0 83 00 01     ; LOCK ADD DWORD PTR [EAX], 1 (atomic operation)
66 B8 34 12     ; MOV AX, 1234h (16-bit operand)
```

### REX Prefix (x64 Extension)

REX prefix enables 64-bit operations and extended registers:

```
0100 WRXB
  │   ││││
  │   │││└─ B: Extend ModR/M.rm or SIB.base
  │   ││└── X: Extend SIB.index  
  │   │└─── R: Extend ModR/M.reg
  │   └──── W: 64-bit operand size
  └──────── Fixed 0100 pattern
```

Examples:

```assembly
48 89 C0        ; MOV RAX, RAX (REX.W=1, 64-bit operation)
44 89 C0        ; MOV EAX, R8D (REX.R=1, extended source register)
41 89 00        ; MOV [R8], EAX (REX.B=1, extended destination register)
```

### ModR/M Byte

ModR/M specifies addressing modes and registers:

```
  7 6   5 4 3   2 1 0
┌─────┬───────┬───────┐
│ mod │  reg  │  rm   │
└─────┴───────┴───────┘
```

#### MOD Field (Addressing Mode)

| mod | Meaning | Example |
|-----|---------|---------|
| 00  | `[reg]` | `[EAX]` |
| 01  | `[reg+disp8]` | `[EAX+12h]` |
| 10  | `[reg+disp32]` | `[EAX+12345678h]` |
| 11  | `reg` | `EAX` (register direct) |

#### REG/RM Fields (Register Encoding)

| Value | 8-bit | 16-bit | 32-bit | 64-bit | Extended (REX) |
|-------|-------|--------|--------|--------|----------------|
| 000   | AL    | AX     | EAX    | RAX    | R8B/R8W/R8D/R8 |
| 001   | CL    | CX     | ECX    | RCX    | R9B/R9W/R9D/R9 |
| 010   | DL    | DX     | EDX    | RDX    | R10B/R10W/R10D/R10 |
| 011   | BL    | BX     | EBX    | RBX    | R11B/R11W/R11D/R11 |
| 100   | AH/SPL| SP     | ESP    | RSP    | R12B/R12W/R12D/R12 |
| 101   | CH/BPL| BP     | EBP    | RBP    | R13B/R13W/R13D/R13 |
| 110   | DH/SIL| SI     | ESI    | RSI    | R14B/R14W/R14D/R14 |
| 111   | BH/DIL| DI     | EDI    | RDI    | R15B/R15W/R15D/R15 |

Examples:

```assembly
89 C0           ; MOV EAX, EAX (mod=11, reg=000, rm=000)
89 00           ; MOV [EAX], EAX (mod=00, reg=000, rm=000)
89 40 12        ; MOV [EAX+12h], EAX (mod=01, reg=000, rm=000)
```

### SIB Byte (Scale-Index-Base)

Required when ModR/M.rm = 100 and mod ≠ 11:

```
  7 6   5 4 3   2 1 0
┌─────┬───────┬───────┐
│scale│ index │ base  │
└─────┴───────┴───────┘
```

- **Scale**: Scaling factor (00=×1, 01=×2, 10=×4, 11=×8)
- **Index**: Index register (100 = no index)
- **Base**: Base register

Examples:

```assembly
8B 04 08        ; MOV EAX, [EAX+ECX] (scale=00, index=001, base=000)
8B 04 88        ; MOV EAX, [EAX+ECX*4] (scale=10, index=001, base=000)
8B 04 25 78 56 34 12 ; MOV EAX, [12345678h] (base=101, disp32)
```

### Special Addressing Cases

#### RIP-Relative Addressing (x64)

When ModR/M = 00???101, address is calculated as:

```
Effective Address = RIP + disp32
```

Example:

```assembly
8B 05 12 34 56 78   ; MOV EAX, [RIP+12345678h]
```

This is crucial for hook generation as it requires address adjustment when copying instructions.

#### Displacement and Immediate Values

| Size | Usage |
|------|-------|
| disp8 | 8-bit displacement (mod=01) |
| disp32 | 32-bit displacement (mod=10 or special cases) |
| imm8 | 8-bit immediate value |
| imm16 | 16-bit immediate value |
| imm32 | 32-bit immediate value |
| imm64 | 64-bit immediate value (limited instructions) |

## Hook Implementation Details

### Trampoline Generation

1. **Instruction Analysis**: Parse target function prologue
2. **Length Calculation**: Ensure minimum 5 bytes for hook
3. **Relocation**: Fix RIP-relative addresses and jumps
4. **Code Generation**: Create trampoline with original instructions
5. **Jump Installation**: Patch target with jump to detour

### Memory Management

- **Proximity Allocation**: Buffers allocated within ±2GB of target
- **Executable Pages**: All code pages have execute permissions
- **Smart Cleanup**: Automatic memory management with reference counting

### Thread Safety

- **Suspended Execution**: All threads suspended during hook operations
- **Context Preservation**: Thread contexts updated for active instructions
- **Atomic Operations**: Hook state changes are atomic

## Testing

Run the test suite:

```bash
cargo test
```

Test with a real application:

```bash
cargo run --example basic_hook
```

## Safety Considerations

⚠️ **Important**: This library performs low-level memory manipulation and code patching. Use with caution:

- Always validate target function addresses
- Ensure detour functions have matching signatures and calling conventions
- Test thoroughly in isolated environments
- Be aware of anti-virus software detection
- Follow responsible disclosure for security research

## Platform Support

- **Windows x64**: Full support
- **Windows x86**: Not supported (use original MinHook)
- **Linux/macOS**: Not supported (Windows-specific)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Original [MinHook](https://github.com/TsudaKageyu/minhook) by Tsuda Kageyu
- [HDE64](https://github.com/Cerbersec/HDE64) disassembly engine
- Intel x86-64 Architecture documentation
- Microsoft Windows SDK documentation

## Related Projects

- [MinHook](https://github.com/TsudaKageyu/minhook) - Original C implementation
- [Detours](https://github.com/microsoft/Detours) - Microsoft's hooking library
- [EasyHook](https://easyhook.github.io/) - .NET hooking framework

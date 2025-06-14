//! x64 instruction structures for MinHook-rs
//!
//! This module defines packed structures that represent x64 instructions
//! used for code patching and trampolines.

#[cfg(not(target_arch = "x86_64"))]
compile_error!("This instruction module only supports x86_64 architecture");

use std::ffi::c_void;

/// 8-bit relative jump instruction
#[repr(C, packed)]
pub struct JmpRelShort {
    /// Opcode: EB xx (JMP +2+xx)
    pub opcode: u8,
    /// Relative offset (-128 to +127)
    pub operand: u8,
}

/// 32-bit relative jump/call instruction
#[repr(C, packed)]
pub struct JmpRel {
    /// Opcode: E9 (JMP) or E8 (CALL)
    pub opcode: u8,
    /// Relative destination address
    pub operand: u32,
}

/// 64-bit indirect absolute jump instruction
#[repr(C, packed)]
pub struct JmpAbs {
    /// First opcode byte: FF
    pub opcode0: u8,
    /// Second opcode byte: 25
    pub opcode1: u8,
    /// RIP offset: 00000000
    pub dummy: u32,
    /// Absolute destination address
    pub address: u64,
}

/// 64-bit indirect absolute call instruction
#[repr(C, packed)]
pub struct CallAbs {
    /// First opcode byte: FF
    pub opcode0: u8,
    /// Second opcode byte: 15
    pub opcode1: u8,
    /// RIP offset to skip the JMP
    pub dummy0: u32,
    /// Short jump opcode: EB
    pub dummy1: u8,
    /// Short jump operand: 08
    pub dummy2: u8,
    /// Absolute destination address
    pub address: u64,
}

/// 32-bit relative conditional jump instruction
#[repr(C, packed)]
pub struct JccRel {
    /// First opcode byte: 0F
    pub opcode0: u8,
    /// Second opcode byte: 8x (condition)
    pub opcode1: u8,
    /// Relative destination address
    pub operand: u32,
}

/// 64-bit indirect absolute conditional jump
#[repr(C, packed)]
pub struct JccAbs {
    /// Conditional jump opcode: 7x
    pub opcode: u8,
    /// Jump length to skip to indirect jump
    pub dummy0: u8,
    /// Indirect jump opcode: FF
    pub dummy1: u8,
    /// Indirect jump opcode: 25
    pub dummy2: u8,
    /// RIP offset: 00000000
    pub dummy3: u32,
    /// Absolute destination address
    pub address: u64,
}

/// Trampoline function information
pub struct Trampoline {
    /// Address of the target function
    pub target: *mut c_void,
    /// Address of the detour function
    pub detour: *mut c_void,
    /// Buffer address for the trampoline
    pub trampoline: *mut c_void,
    /// Address of the relay function
    pub relay: *mut c_void,
    /// Should use the hot patch area?
    pub patch_above: bool,
    /// Number of instruction boundaries
    pub n_ip: u32,
    /// Instruction boundaries of the target function
    pub old_ips: [u8; 8],
    /// Instruction boundaries of the trampoline function
    pub new_ips: [u8; 8],
}

impl JmpRelShort {
    /// Create a new short jump instruction
    pub fn new(offset: i8) -> Self {
        Self {
            opcode: 0xEB,
            operand: offset as u8,
        }
    }
}

impl JmpRel {
    /// Create a new relative jump instruction
    pub fn new_jmp(offset: i32) -> Self {
        Self {
            opcode: 0xE9,
            operand: offset as u32,
        }
    }

    /// Create a new relative call instruction
    pub fn new_call(offset: i32) -> Self {
        Self {
            opcode: 0xE8,
            operand: offset as u32,
        }
    }
}

impl JmpAbs {
    /// Create a new absolute jump instruction
    pub fn new(address: u64) -> Self {
        Self {
            opcode0: 0xFF,
            opcode1: 0x25,
            dummy: 0x00000000,
            address,
        }
    }
}

impl CallAbs {
    /// Create a new absolute call instruction
    pub fn new(address: u64) -> Self {
        Self {
            opcode0: 0xFF,
            opcode1: 0x15,
            dummy0: 0x00000002,
            dummy1: 0xEB,
            dummy2: 0x08,
            address,
        }
    }
}

impl JccRel {
    /// Create a new conditional jump instruction
    pub fn new(condition: u8, offset: i32) -> Self {
        Self {
            opcode0: 0x0F,
            opcode1: 0x80 | (condition & 0x0F),
            operand: offset as u32,
        }
    }
}

impl JccAbs {
    /// Create a new absolute conditional jump instruction
    pub fn new(condition: u8, address: u64) -> Self {
        Self {
            opcode: 0x70 | (condition & 0x0F),
            dummy0: 0x0E,
            dummy1: 0xFF,
            dummy2: 0x25,
            dummy3: 0x00000000,
            address,
        }
    }
}

impl Trampoline {
    /// Create a new trampoline structure
    pub fn new(target: *mut c_void, detour: *mut c_void, trampoline: *mut c_void) -> Self {
        Self {
            target,
            detour,
            trampoline,
            relay: std::ptr::null_mut(),
            patch_above: false,
            n_ip: 0,
            old_ips: [0; 8],
            new_ips: [0; 8],
        }
    }
}

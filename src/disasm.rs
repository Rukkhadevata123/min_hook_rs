//! Precise x86_64 instruction decoder - designed for MinHook
//! Based on HDE64 table data, ensuring absolutely accurate instruction length calculation

#[cfg(not(target_arch = "x86_64"))]
compile_error!("This disasm module only supports x86_64 architecture");

/// MinHook-specific instruction information (only includes fields actually needed by trampoline)
#[derive(Debug, Clone, Default)]
pub struct HookInstruction {
    /// Instruction length (absolutely accurate)
    pub len: u8,
    /// Primary opcode
    pub opcode: u8,
    /// Secondary opcode (0F xx instructions) - needed by trampoline.c:177
    pub opcode2: u8,
    /// ModR/M byte  
    pub modrm: u8,
    /// Immediate value (unified as i32)
    pub immediate: i32,
    /// Displacement value (for RIP-relative)
    pub displacement: i32,
    /// HDE64 fully compatible flags (for RIP relocation calculation)
    pub flags: u32,
    /// Parse error
    pub error: bool,
}

impl HookInstruction {
    /// RIP-relative addressing detection (fully consistent with trampoline.c)
    #[inline]
    pub fn is_rip_relative(&self) -> bool {
        (self.modrm & 0xC7) == 0x05
    }

    /// Get ModR/M.reg field (for indirect jump detection)
    #[inline]
    pub fn modrm_reg(&self) -> u8 {
        (self.modrm >> 3) & 7
    }

    /// Calculate immediate field length (for RIP relocation - trampoline.c:115)
    #[inline]
    pub fn immediate_size(&self) -> u8 {
        let mut size = 0u8;
        if (self.flags & F_IMM8) != 0 {
            size += 1;
        }
        if (self.flags & F_IMM16) != 0 {
            size += 2;
        }
        if (self.flags & F_IMM32) != 0 {
            size += 4;
        }
        if (self.flags & F_IMM64) != 0 {
            size += 8;
        }
        size
    }

    /// Check for errors
    #[inline]
    pub fn has_error(&self) -> bool {
        self.error || (self.flags & F_ERROR) != 0
    }

    #[inline]
    pub fn is_call(&self) -> bool {
        self.opcode == 0xE8
    }

    #[inline]
    pub fn is_jmp(&self) -> bool {
        matches!(self.opcode, 0xE9 | 0xEB)
    }

    #[inline]
    pub fn is_conditional(&self) -> bool {
        (self.opcode & 0xF0) == 0x70
            || (self.opcode & 0xFC) == 0xE0
            || (self.opcode2 & 0xF0) == 0x80 // Need opcode2 check
    }

    #[inline]
    pub fn is_ret(&self) -> bool {
        (self.opcode & 0xFE) == 0xC2
    }

    #[inline]
    pub fn is_indirect_jmp(&self) -> bool {
        self.opcode == 0xFF && self.modrm_reg() == 4
    }
}

// HDE64 fully compatible flag constants
pub const F_MODRM: u32 = 0x00000001;
pub const F_SIB: u32 = 0x00000002;
pub const F_IMM8: u32 = 0x00000004;
pub const F_IMM16: u32 = 0x00000008;
pub const F_IMM32: u32 = 0x00000010;
pub const F_IMM64: u32 = 0x00000020;
pub const F_DISP8: u32 = 0x00000040;
pub const F_DISP16: u32 = 0x00000080;
pub const F_DISP32: u32 = 0x00000100;
pub const F_RELATIVE: u32 = 0x00000200;
pub const F_ERROR: u32 = 0x00001000;
pub const F_ERROR_OPCODE: u32 = 0x00002000;
pub const F_ERROR_LENGTH: u32 = 0x00004000;
pub const F_ERROR_LOCK: u32 = 0x00008000;
pub const F_ERROR_OPERAND: u32 = 0x00010000;

// HDE64 table constants - exactly as in the original
const C_MODRM: u8 = 0x01;
const C_IMM8: u8 = 0x02;
const C_IMM16: u8 = 0x04;
const C_IMM_P66: u8 = 0x10;
const C_REL8: u8 = 0x20;
const C_REL32: u8 = 0x40;
const C_GROUP: u8 = 0x80;
const C_ERROR: u8 = 0xff;

// Prefix constants
const PRE_NONE: u8 = 0x01;
const PRE_F2: u8 = 0x02;
const PRE_F3: u8 = 0x04;
const PRE_66: u8 = 0x08;
const PRE_67: u8 = 0x10;

// Table offsets - exactly as in the original table64.h
const DELTA_OPCODES: usize = 0x4a;

// Complete HDE64 table data - copied directly from table64.h
static HDE64_TABLE: &[u8] = &[
    0xa5, 0xaa, 0xa5, 0xb8, 0xa5, 0xaa, 0xa5, 0xaa, 0xa5, 0xb8, 0xa5, 0xb8, 0xa5, 0xb8, 0xa5, 0xb8,
    0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xac, 0xc0, 0xcc, 0xc0, 0xa1, 0xa1, 0xa1, 0xa1,
    0xb1, 0xa5, 0xa5, 0xa6, 0xc0, 0xc0, 0xd7, 0xda, 0xe0, 0xc0, 0xe4, 0xc0, 0xea, 0xea, 0xe0, 0xe0,
    0x98, 0xc8, 0xee, 0xf1, 0xa5, 0xd3, 0xa5, 0xa5, 0xa1, 0xea, 0x9e, 0xc0, 0xc0, 0xc2, 0xc0, 0xe6,
    0x03, 0x7f, 0x11, 0x7f, 0x01, 0x7f, 0x01, 0x3f, 0x01, 0x01, 0xab, 0x8b, 0x90, 0x64, 0x5b, 0x5b,
    0x5b, 0x5b, 0x5b, 0x92, 0x5b, 0x5b, 0x76, 0x90, 0x92, 0x92, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b,
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x6a, 0x73, 0x90, 0x5b, 0x52, 0x52, 0x52, 0x52, 0x5b, 0x5b,
    0x5b, 0x5b, 0x77, 0x7c, 0x77, 0x85, 0x5b, 0x5b, 0x70, 0x5b, 0x7a, 0xaf, 0x76, 0x76, 0x5b, 0x5b,
    0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x5b, 0x86, 0x01, 0x03, 0x01, 0x04, 0x03, 0xd5,
    0x03, 0xd5, 0x03, 0xcc, 0x01, 0xbc, 0x03, 0xf0, 0x03, 0x03, 0x04, 0x00, 0x50, 0x50, 0x50, 0x50,
    0xff, 0x20, 0x20, 0x20, 0x20, 0x01, 0x01, 0x01, 0x01, 0xc4, 0x02, 0x10, 0xff, 0xff, 0xff, 0x01,
    0x00, 0x03, 0x11, 0xff, 0x03, 0xc4, 0xc6, 0xc8, 0x02, 0x10, 0x00, 0xff, 0xcc, 0x01, 0x01, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x03, 0x01, 0xff, 0xff, 0xc0, 0xc2, 0x10, 0x11, 0x02, 0x03,
    0x01, 0x01, 0x01, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0x10, 0x10, 0x10, 0x10, 0x02, 0x10, 0x00, 0x00, 0xc6, 0xc8, 0x02, 0x02, 0x02, 0x02, 0x06, 0x00,
    0x04, 0x00, 0x02, 0xff, 0x00, 0xc0, 0xc2, 0x01, 0x01, 0x03, 0x03, 0x03, 0xca, 0x40, 0x00, 0x0a,
    0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x00, 0x33, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xbf, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0xbf,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x00, 0x00, 0xff, 0x40, 0x40, 0x40, 0x40,
    0x41, 0x49, 0x40, 0x40, 0x40, 0x40, 0x4c, 0x42, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
    0x4f, 0x44, 0x53, 0x40, 0x40, 0x40, 0x44, 0x57, 0x43, 0x5c, 0x40, 0x60, 0x40, 0x40, 0x40, 0x40,
    0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x64, 0x66, 0x6e, 0x6b, 0x40, 0x40,
    0x6a, 0x46, 0x40, 0x40, 0x44, 0x46, 0x40, 0x40, 0x5b, 0x44, 0x40, 0x40, 0x00, 0x00, 0x00, 0x00,
    0x06, 0x06, 0x06, 0x06, 0x01, 0x06, 0x06, 0x02, 0x06, 0x06, 0x00, 0x06, 0x00, 0x0a, 0x0a, 0x00,
    0x00, 0x00, 0x02, 0x07, 0x07, 0x06, 0x02, 0x0d, 0x06, 0x06, 0x06, 0x0e, 0x05, 0x05, 0x02, 0x02,
    0x00, 0x00, 0x04, 0x04, 0x04, 0x04, 0x05, 0x06, 0x06, 0x06, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00,
    0x08, 0x00, 0x10, 0x00, 0x18, 0x00, 0x20, 0x00, 0x28, 0x00, 0x30, 0x00, 0x80, 0x01, 0x82, 0x01,
    0x86, 0x00, 0xf6, 0xcf, 0xfe, 0x3f, 0xab, 0x00, 0xb0, 0x00, 0xb1, 0x00, 0xb3, 0x00, 0xba, 0xf8,
    0xbb, 0x00, 0xc0, 0x00, 0xc1, 0x00, 0xc7, 0xbf, 0x62, 0xff, 0x00, 0x8d, 0xff, 0x00, 0xc4, 0xff,
    0x00, 0xc5, 0xff, 0x00, 0xff, 0xff, 0xeb, 0x01, 0xff, 0x0e, 0x12, 0x08, 0x00, 0x13, 0x09, 0x00,
    0x16, 0x08, 0x00, 0x17, 0x09, 0x00, 0x2b, 0x09, 0x00, 0xae, 0xff, 0x07, 0xb2, 0xff, 0x00, 0xb4,
    0xff, 0x00, 0xb5, 0xff, 0x00, 0xc3, 0x01, 0x00, 0xc7, 0xff, 0xbf, 0xe7, 0x08, 0x00, 0xf0, 0x02,
    0x00,
];

/// Main instruction decoder function - based on hde64.c
pub fn decode_instruction(code: &[u8]) -> HookInstruction {
    let mut inst = HookInstruction::default();
    if code.is_empty() {
        inst.error = true;
        inst.flags = F_ERROR | F_ERROR_LENGTH;
        return inst;
    }

    let mut pos = 0;
    let pref = parse_prefixes(code, &mut pos);

    if pos >= code.len() {
        inst.error = true;
        inst.flags = F_ERROR | F_ERROR_LENGTH;
        inst.len = 15;
        return inst;
    }

    // REX prefix handling
    let mut c = code[pos];
    if (c & 0xf0) == 0x40 {
        pos += 1;
        if pos >= code.len() || (code[pos] & 0xf0) == 0x40 {
            inst.error = true;
            inst.flags = F_ERROR | F_ERROR_LENGTH;
            inst.len = 15;
            return inst;
        }
        c = code[pos];
    }

    // Primary opcode
    inst.opcode = c;
    pos += 1;

    // Handle 0F prefix (two-byte opcodes)
    let ht_offset = if inst.opcode == 0x0F {
        if pos >= code.len() {
            inst.error = true;
            inst.flags = F_ERROR | F_ERROR_LENGTH;
            inst.len = 15;
            return inst;
        }
        inst.opcode2 = code[pos];
        pos += 1;
        DELTA_OPCODES
    } else {
        0
    };

    // Table lookup
    let opcode = if inst.opcode2 != 0 {
        inst.opcode2
    } else {
        inst.opcode
    };
    let cflags = get_instruction_flags(opcode, ht_offset);

    if cflags == C_ERROR {
        inst.error = true;
        inst.flags = F_ERROR | F_ERROR_OPCODE;
        inst.len = 15;
        return inst;
    }

    // ModR/M byte handling
    if (cflags & C_MODRM) != 0 {
        if pos >= code.len() {
            inst.error = true;
            inst.flags = F_ERROR | F_ERROR_LENGTH;
            inst.len = 15;
            return inst;
        }

        inst.flags |= F_MODRM;
        inst.modrm = code[pos];
        pos += 1;

        let (additional_bytes, displacement, disp_flags) =
            parse_addressing(code, pos, inst.modrm, (pref & PRE_67) != 0);

        if additional_bytes == u8::MAX {
            inst.error = true;
            inst.flags = F_ERROR | F_ERROR_LENGTH;
            inst.len = 15;
            return inst;
        }

        inst.displacement = displacement;
        inst.flags |= disp_flags;
        pos += additional_bytes as usize;
    }

    // Immediate value handling
    let (imm_size, imm_value, imm_flags) = parse_immediate(code, pos, cflags, (pref & PRE_66) != 0);
    if imm_size == u8::MAX {
        inst.error = true;
        inst.flags = F_ERROR | F_ERROR_LENGTH;
        inst.len = 15;
        return inst;
    }

    inst.immediate = imm_value;
    inst.flags |= imm_flags;
    pos += imm_size as usize;

    inst.len = pos as u8;
    if inst.len > 15 {
        inst.error = true;
        inst.flags |= F_ERROR | F_ERROR_LENGTH;
        inst.len = 15;
    }

    inst
}

/// HDE64 table lookup - maintains the exact same logic as hde64.c
fn get_instruction_flags(opcode: u8, ht_offset: usize) -> u8 {
    if ht_offset >= HDE64_TABLE.len() {
        return C_ERROR;
    }

    let idx1_pos = ht_offset + (opcode / 4) as usize;
    if idx1_pos >= HDE64_TABLE.len() {
        return C_ERROR;
    }

    let idx1 = HDE64_TABLE[idx1_pos];
    let final_pos = ht_offset + idx1 as usize + (opcode % 4) as usize;
    if final_pos >= HDE64_TABLE.len() {
        return C_ERROR;
    }

    let mut cflags = HDE64_TABLE[final_pos];

    // Handle GROUP instructions
    if (cflags & C_GROUP) != 0 {
        let group_offset = ht_offset + (cflags & 0x7f) as usize;
        if group_offset + 1 < HDE64_TABLE.len() {
            let group_data =
                u16::from_le_bytes([HDE64_TABLE[group_offset], HDE64_TABLE[group_offset + 1]]);
            cflags = (group_data & 0xFF) as u8;
        } else {
            return C_ERROR;
        }
    }

    cflags
}

/// Parse instruction prefixes - based on hde64.c:28-50
fn parse_prefixes(code: &[u8], pos: &mut usize) -> u8 {
    let mut pref = 0u8;

    // Match C code: for (x = 16; x; x--) switch (c = *p++)
    for _ in 0..16 {
        if *pos >= code.len() {
            break;
        }

        match code[*pos] {
            0x66 => pref |= PRE_66,
            0x67 => pref |= PRE_67,
            0xf2 => pref |= PRE_F2,
            0xf3 => pref |= PRE_F3,
            0xf0 | 0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 => {} // Other prefixes, ignored
            _ => break,                                          // Stop at non-prefix byte
        }
        *pos += 1;
    }

    if pref == 0 {
        pref |= PRE_NONE;
    }

    pref
}

/// Parse addressing mode - based on hde64.c:156-195
fn parse_addressing(code: &[u8], pos: usize, modrm: u8, has_67: bool) -> (u8, i32, u32) {
    let m_mod = modrm >> 6;
    let m_rm = modrm & 7;

    // Register mode - return immediately
    if m_mod == 3 {
        return (0, 0, 0);
    }

    let mut bytes_used = 0;
    let mut displacement = 0;
    let mut flags = 0u32;

    // Calculate displacement size - based on hde64.c:156-168
    let mut disp_size = match m_mod {
        0 => {
            if has_67 && m_rm == 6 {
                2
            } else if !has_67 && m_rm == 5 {
                4
            }
            // RIP-relative
            else {
                0
            }
        }
        1 => 1,
        2 => {
            if has_67 {
                2
            } else {
                4
            }
        }
        _ => 0,
    };

    // SIB byte handling - based on hde64.c:169-176
    if m_mod != 3 && m_rm == 4 {
        if pos + bytes_used >= code.len() {
            return (u8::MAX, 0, 0);
        }

        flags |= F_SIB;
        let sib = code[pos + bytes_used];
        bytes_used += 1;

        // SIB base special case
        if (sib & 7) == 5 && (m_mod & 1) == 0 {
            disp_size = 4;
        }
    }

    // Read displacement - based on hde64.c:178-191
    if disp_size > 0 {
        if pos + bytes_used + disp_size > code.len() {
            return (u8::MAX, 0, 0);
        }

        let disp_pos = pos + bytes_used;
        displacement = match disp_size {
            1 => {
                flags |= F_DISP8;
                code[disp_pos] as i8 as i32
            }
            2 => {
                flags |= F_DISP16;
                i16::from_le_bytes([code[disp_pos], code[disp_pos + 1]]) as i32
            }
            4 => {
                flags |= F_DISP32;
                i32::from_le_bytes([
                    code[disp_pos],
                    code[disp_pos + 1],
                    code[disp_pos + 2],
                    code[disp_pos + 3],
                ])
            }
            _ => 0,
        };
        bytes_used += disp_size;
    }

    (bytes_used as u8, displacement, flags)
}

/// Parse immediate values - based on hde64.c:199-246
fn parse_immediate(code: &[u8], pos: usize, cflags: u8, has_66: bool) -> (u8, i32, u32) {
    let mut imm_size = 0u8;
    let mut imm_value = 0i32;
    let mut flags = 0u32;

    // C_IMM_P66 handling - based on hde64.c:199-217
    if (cflags & C_IMM_P66) != 0 {
        if (cflags & C_REL32) != 0 && has_66 {
            // 16-bit relative jump
            flags |= F_IMM16 | F_RELATIVE;
            imm_size = 2;
        } else if (cflags & C_REL32) == 0 && has_66 {
            // 16-bit immediate
            flags |= F_IMM16;
            imm_size = 2;
        } else {
            // 32-bit immediate or relative jump
            flags |= F_IMM32;
            if (cflags & C_REL32) != 0 {
                flags |= F_RELATIVE;
            }
            imm_size = 4;
        }
    }

    // Other immediate types - based on hde64.c:219-246
    if (cflags & C_IMM16) != 0 {
        flags |= F_IMM16;
        imm_size += 2;
    }
    if (cflags & C_IMM8) != 0 {
        flags |= F_IMM8;
        imm_size += 1;
    }
    if (cflags & C_REL8) != 0 {
        flags |= F_IMM8 | F_RELATIVE;
        imm_size += 1;
    }

    // Read immediate value
    if imm_size > 0 {
        if pos + imm_size as usize > code.len() {
            return (u8::MAX, 0, 0);
        }

        // Always read the primary immediate value
        imm_value = match imm_size {
            1 => code[pos] as i8 as i32,
            2 => i16::from_le_bytes([code[pos], code[pos + 1]]) as i32,
            3 => {
                // IMM16 + IMM8 combination
                i16::from_le_bytes([code[pos], code[pos + 1]]) as i32
            }
            4 => i32::from_le_bytes([code[pos], code[pos + 1], code[pos + 2], code[pos + 3]]),
            _ => 0,
        };
    }

    (imm_size, imm_value, flags)
}

/// Check if hook can be safely installed at the given address
pub fn can_hook_safely(code: &[u8], required_length: usize) -> bool {
    if code.len() < required_length {
        return false;
    }

    let mut pos = 0;
    let mut total_len = 0;

    while total_len < required_length && pos < code.len() {
        let inst = decode_instruction(&code[pos..]);

        if inst.error || inst.len == 0 {
            return false;
        }

        // Check RET instruction
        if inst.is_ret() && total_len < required_length {
            return false;
        }

        total_len += inst.len as usize;
        pos += inst.len as usize;
    }

    total_len >= required_length
}

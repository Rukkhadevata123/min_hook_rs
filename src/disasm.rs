//! Precise x86_64 instruction decoder - direct port of HDE64 with goto elimination
//! Based on hde64.c, maintaining exact compatibility while removing goto statements

/// HDE64-compatible instruction structure
#[derive(Debug, Clone, Default)]
pub struct HookInstruction {
    pub len: u8,
    pub p_rep: u8,
    pub p_lock: u8,
    pub p_seg: u8,
    pub p_66: u8,
    pub p_67: u8,
    pub rex: u8,
    pub rex_w: u8,
    pub rex_r: u8,
    pub rex_x: u8,
    pub rex_b: u8,
    pub opcode: u8,
    pub opcode2: u8,
    pub modrm: u8,
    pub modrm_mod: u8,
    pub modrm_reg: u8,
    pub modrm_rm: u8,
    pub sib: u8,
    pub sib_scale: u8,
    pub sib_index: u8,
    pub sib_base: u8,
    pub immediate: i32,    // Unified immediate field
    pub displacement: i32, // Unified displacement field
    pub flags: u32,
    pub error: bool,
}

impl HookInstruction {
    #[inline]
    pub fn is_rip_relative(&self) -> bool {
        (self.modrm & 0xC7) == 0x05
    }

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
}

// HDE64 flag constants
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
pub const F_PREFIX_REPNZ: u32 = 0x01000000;
pub const F_PREFIX_REPX: u32 = 0x02000000;
pub const F_PREFIX_REP: u32 = 0x03000000;
pub const F_PREFIX_66: u32 = 0x04000000;
pub const F_PREFIX_67: u32 = 0x08000000;
pub const F_PREFIX_LOCK: u32 = 0x10000000;
pub const F_PREFIX_SEG: u32 = 0x20000000;
pub const F_PREFIX_REX: u32 = 0x40000000;
pub const F_PREFIX_ANY: u32 = 0x7f000000;

// Table constants
const C_NONE: u8 = 0x00;
const C_MODRM: u8 = 0x01;
const C_IMM8: u8 = 0x02;
const C_IMM16: u8 = 0x04;
const C_IMM_P66: u8 = 0x10;
const C_REL8: u8 = 0x20;
const C_REL32: u8 = 0x40;
const C_GROUP: u8 = 0x80;
const C_ERROR: u8 = 0xff;

const PRE_ANY: u8 = 0x00;
const PRE_NONE: u8 = 0x01;
const PRE_F2: u8 = 0x02;
const PRE_F3: u8 = 0x04;
const PRE_66: u8 = 0x08;
const PRE_67: u8 = 0x10;
const PRE_LOCK: u8 = 0x20;
const PRE_SEG: u8 = 0x40;
const PRE_ALL: u8 = 0xff;

const DELTA_OPCODES: usize = 0x4a;
const DELTA_FPU_REG: usize = 0xfd;
const DELTA_FPU_MODRM: usize = 0x104;
const DELTA_PREFIXES: usize = 0x13c;
const DELTA_OP_LOCK_OK: usize = 0x1ae;
const DELTA_OP2_LOCK_OK: usize = 0x1c6;
const DELTA_OP_ONLY_MEM: usize = 0x1d8;
const DELTA_OP2_ONLY_MEM: usize = 0x1e7;

// Complete HDE64 table
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

/// Main disassembly function
pub fn decode_instruction(code: &[u8]) -> HookInstruction {
    let mut hs = HookInstruction::default();

    if code.is_empty() {
        hs.error = true;
        hs.flags = F_ERROR | F_ERROR_LENGTH;
        return hs;
    }

    let mut p = 0usize;
    let mut pref = 0u8;
    let mut op64 = 0u8;

    // Prefix parsing loop
    for _ in 0..16 {
        if p >= code.len() {
            break;
        }

        let c = code[p];
        p += 1;

        match c {
            0xf3 => {
                hs.p_rep = c;
                pref |= PRE_F3;
            }
            0xf2 => {
                hs.p_rep = c;
                pref |= PRE_F2;
            }
            0xf0 => {
                hs.p_lock = c;
                pref |= PRE_LOCK;
            }
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 => {
                hs.p_seg = c;
                pref |= PRE_SEG;
            }
            0x66 => {
                hs.p_66 = c;
                pref |= PRE_66;
            }
            0x67 => {
                hs.p_67 = c;
                pref |= PRE_67;
            }
            _ => {
                p -= 1; // Back up one position
                break; // Exit prefix loop
            }
        }
    }
    // pref_done equivalent

    hs.flags = (pref as u32) << 23;

    if pref == 0 {
        pref |= PRE_NONE;
    }

    if p >= code.len() {
        hs.error = true;
        hs.flags = F_ERROR | F_ERROR_LENGTH;
        return hs;
    }

    let mut c = code[p];
    p += 1;

    // REX prefix handling for x64
    if (c & 0xf0) == 0x40 {
        hs.flags |= F_PREFIX_REX;
        hs.rex_w = (c & 0xf) >> 3;
        if hs.rex_w != 0 && p < code.len() && (code[p] & 0xf8) == 0xb8 {
            op64 += 1;
        }
        hs.rex_r = (c & 7) >> 2;
        hs.rex_x = (c & 3) >> 1;
        hs.rex_b = c & 1;

        if p >= code.len() {
            hs.error = true;
            hs.flags = F_ERROR | F_ERROR_LENGTH;
            return hs;
        }

        c = code[p];
        p += 1;

        // Error check
        if (c & 0xf0) == 0x40 {
            hs.flags |= F_ERROR | F_ERROR_OPCODE;
            hs.len = 15;
            return hs; // Direct return instead of goto
        }
    }

    hs.opcode = c;
    let mut ht = 0usize; // Table offset

    // Two-byte opcode handling
    if c == 0x0f {
        if p >= code.len() {
            hs.error = true;
            hs.flags = F_ERROR | F_ERROR_LENGTH;
            return hs;
        }
        hs.opcode2 = code[p];
        p += 1;
        c = hs.opcode2;
        ht += DELTA_OPCODES;
    } else if (0xa0..=0xa3).contains(&c) {
        op64 += 1;
        if (pref & PRE_67) != 0 {
            pref |= PRE_66;
        } else {
            pref &= !PRE_66;
        }
    }

    let opcode = c;
    let mut cflags = get_table_entry(ht, opcode);

    // Error handling
    if cflags == C_ERROR {
        hs.flags |= F_ERROR | F_ERROR_OPCODE;
        if (opcode & !3) == 0x24 {
            cflags = 1; // Special case from original
        } else {
            cflags = 0;
        }
    }

    let mut x = 0u8;
    if (cflags & C_GROUP) != 0 {
        let group_offset = ht + (cflags & 0x7f) as usize;
        if group_offset + 1 < HDE64_TABLE.len() {
            let t = u16::from_le_bytes([HDE64_TABLE[group_offset], HDE64_TABLE[group_offset + 1]]);
            cflags = (t & 0xff) as u8;
            x = (t >> 8) as u8;
        }
    }

    // Prefix validation for two-byte opcodes
    if hs.opcode2 != 0 {
        let prefix_ht = DELTA_PREFIXES;
        let prefix_flags = get_table_entry(prefix_ht, opcode);
        if (prefix_flags & pref) != 0 {
            hs.flags |= F_ERROR | F_ERROR_OPCODE;
        }
    }

    // ModR/M processing
    if (cflags & C_MODRM) != 0 {
        if p >= code.len() {
            hs.error = true;
            hs.flags = F_ERROR | F_ERROR_LENGTH;
            return hs;
        }

        hs.flags |= F_MODRM;
        c = code[p];
        p += 1;
        hs.modrm = c;
        hs.modrm_mod = c >> 6;
        hs.modrm_rm = c & 7;
        hs.modrm_reg = (c & 0x3f) >> 3;

        // Group instruction validation
        if x != 0 && ((x << hs.modrm_reg) & 0x80) != 0 {
            hs.flags |= F_ERROR | F_ERROR_OPCODE;
        }

        // FPU instruction handling
        if hs.opcode2 == 0 && (0xd9..=0xdf).contains(&opcode) {
            let t_base = opcode - 0xd9;
            let fpu_result = if hs.modrm_mod == 3 {
                let fpu_ht = DELTA_FPU_MODRM + (t_base as usize) * 8;
                if fpu_ht + (hs.modrm_reg as usize) < HDE64_TABLE.len() {
                    HDE64_TABLE[fpu_ht + (hs.modrm_reg as usize)] << hs.modrm_rm
                } else {
                    0x80
                }
            } else {
                let fpu_ht = DELTA_FPU_REG;
                if fpu_ht + (t_base as usize) < HDE64_TABLE.len() {
                    HDE64_TABLE[fpu_ht + (t_base as usize)] << hs.modrm_reg
                } else {
                    0x80
                }
            };

            if (fpu_result & 0x80) != 0 {
                hs.flags |= F_ERROR | F_ERROR_OPCODE;
            }
        }

        // LOCK prefix validation
        if (pref & PRE_LOCK) != 0 {
            if hs.modrm_mod == 3 {
                hs.flags |= F_ERROR | F_ERROR_LOCK;
            } else {
                let lock_valid = validate_lock_prefix(hs.opcode2 != 0, opcode, hs.modrm_reg);
                if !lock_valid {
                    hs.flags |= F_ERROR | F_ERROR_LOCK;
                }
            }
        }

        // Special operand validation
        let operand_error =
            check_operand_errors(hs.opcode2 != 0, opcode, hs.modrm_mod, hs.modrm_reg, pref);
        if operand_error {
            hs.flags |= F_ERROR | F_ERROR_OPERAND;
        }

        // SIB and displacement processing
        let (sib_bytes, disp_size) =
            process_addressing_mode(code, p, hs.modrm_mod, hs.modrm_rm, pref);

        if sib_bytes == u8::MAX {
            hs.error = true;
            hs.flags = F_ERROR | F_ERROR_LENGTH;
            return hs;
        }

        // SIB byte processing
        if sib_bytes > 0 {
            hs.flags |= F_SIB;
            hs.sib = code[p];
            hs.sib_scale = code[p] >> 6;
            hs.sib_index = (code[p] & 0x3f) >> 3;
            hs.sib_base = code[p] & 7;
        }
        p += sib_bytes as usize;

        // Displacement processing
        p += process_displacement(code, p, disp_size, &mut hs);

        // Additional immediate processing for F6/F7 instructions
        if hs.modrm_reg <= 1 {
            if opcode == 0xf6 {
                cflags |= C_IMM8;
            } else if opcode == 0xf7 {
                cflags |= C_IMM_P66;
            }
        }
    } else if (pref & PRE_LOCK) != 0 {
        hs.flags |= F_ERROR | F_ERROR_LOCK;
    }

    // Immediate value processing
    process_immediate_values(code, &mut p, &mut hs, cflags, pref, op64);

    // Final length calculation
    hs.len = p as u8;
    if hs.len > 15 {
        hs.flags |= F_ERROR | F_ERROR_LENGTH;
        hs.len = 15;
    }

    hs
}

/// Table lookup helper
fn get_table_entry(ht_offset: usize, opcode: u8) -> u8 {
    if ht_offset + (opcode / 4) as usize >= HDE64_TABLE.len() {
        return C_ERROR;
    }

    let table_idx = HDE64_TABLE[ht_offset + (opcode / 4) as usize];
    let final_idx = ht_offset + table_idx as usize + (opcode % 4) as usize;

    if final_idx >= HDE64_TABLE.len() {
        return C_ERROR;
    }

    HDE64_TABLE[final_idx]
}

/// LOCK prefix validation
fn validate_lock_prefix(is_two_byte: bool, opcode: u8, modrm_reg: u8) -> bool {
    let (table_start, table_end) = if is_two_byte {
        (DELTA_OP2_LOCK_OK, DELTA_OP_ONLY_MEM)
    } else {
        (DELTA_OP_LOCK_OK, DELTA_OP2_LOCK_OK)
    };

    let search_opcode = if !is_two_byte { opcode & !2 } else { opcode };

    let mut i = table_start;
    while i < table_end && i + 1 < HDE64_TABLE.len() {
        if HDE64_TABLE[i] == search_opcode {
            let reg_mask = HDE64_TABLE[i + 1];
            return ((reg_mask << modrm_reg) & 0x80) == 0;
        }
        i += 2;
    }
    false
}

/// Operand error checking
fn check_operand_errors(
    is_two_byte: bool,
    opcode: u8,
    modrm_mod: u8,
    modrm_reg: u8,
    pref: u8,
) -> bool {
    if is_two_byte {
        match opcode {
            0x20 | 0x22 => {
                return modrm_mod != 3 || modrm_reg > 4 || modrm_reg == 1;
            }
            0x21 | 0x23 => {
                return modrm_mod != 3 || modrm_reg == 4 || modrm_reg == 5;
            }
            _ => {}
        }

        if modrm_mod != 3 {
            match opcode {
                0x50 | 0xd7 | 0xf7 => {
                    return (pref & (PRE_NONE | PRE_66)) != 0;
                }
                0xd6 => {
                    return (pref & (PRE_F2 | PRE_F3)) != 0;
                }
                0xc5 => {
                    return true;
                }
                _ => {}
            }
        }

        // Memory-only instruction check for two-byte opcodes
        if modrm_mod == 3 {
            return check_memory_only_instruction(
                DELTA_OP2_ONLY_MEM,
                HDE64_TABLE.len(),
                opcode,
                modrm_reg,
                pref,
            );
        }
    } else {
        match opcode {
            0x8c => {
                return modrm_reg > 5;
            }
            0x8e => {
                return modrm_reg == 1 || modrm_reg > 5;
            }
            _ => {}
        }

        // Memory-only instruction check for one-byte opcodes
        if modrm_mod == 3 {
            return check_memory_only_instruction(
                DELTA_OP_ONLY_MEM,
                DELTA_OP2_ONLY_MEM,
                opcode,
                modrm_reg,
                pref,
            );
        }
    }

    false
}

/// Memory-only instruction validation
fn check_memory_only_instruction(
    table_start: usize,
    table_end: usize,
    opcode: u8,
    modrm_reg: u8,
    pref: u8,
) -> bool {
    let mut i = table_start;
    while i + 2 < table_end && i + 2 < HDE64_TABLE.len() {
        if HDE64_TABLE[i] == opcode {
            let prefix_mask = HDE64_TABLE[i + 1];
            let reg_mask = HDE64_TABLE[i + 2];
            return (prefix_mask & pref) != 0 && ((reg_mask << modrm_reg) & 0x80) == 0;
        }
        i += 2;
    }
    false
}

/// SIB and displacement size calculation
fn process_addressing_mode(
    code: &[u8],
    pos: usize,
    modrm_mod: u8,
    modrm_rm: u8,
    pref: u8,
) -> (u8, u8) {
    let mut sib_bytes = 0u8;
    let mut disp_size = 0u8;

    // Calculate displacement size based on addressing mode
    match modrm_mod {
        0 => {
            if (pref & PRE_67) != 0 {
                if modrm_rm == 6 {
                    disp_size = 2;
                }
            } else if modrm_rm == 5 {
                disp_size = 4;
            }
        }
        1 => {
            disp_size = 1;
        }
        2 => {
            disp_size = 2;
            if (pref & PRE_67) == 0 {
                disp_size <<= 1; // disp_size *= 2
            }
        }
        _ => {}
    }

    // SIB byte processing
    if modrm_mod != 3 && modrm_rm == 4 {
        if pos >= code.len() {
            return (u8::MAX, 0); // Error condition
        }
        sib_bytes = 1;

        // SIB base special case
        let sib = code[pos];
        if (sib & 7) == 5 && (modrm_mod & 1) == 0 {
            disp_size = 4;
        }
    }

    (sib_bytes, disp_size)
}

/// Displacement processing
fn process_displacement(code: &[u8], pos: usize, disp_size: u8, hs: &mut HookInstruction) -> usize {
    if disp_size == 0 {
        return 0;
    }

    if pos + disp_size as usize > code.len() {
        hs.error = true;
        hs.flags = F_ERROR | F_ERROR_LENGTH;
        return 0;
    }

    match disp_size {
        1 => {
            hs.flags |= F_DISP8;
            hs.displacement = code[pos] as i8 as i32;
        }
        2 => {
            hs.flags |= F_DISP16;
            hs.displacement = i16::from_le_bytes([code[pos], code[pos + 1]]) as i32;
        }
        4 => {
            hs.flags |= F_DISP32;
            hs.displacement =
                i32::from_le_bytes([code[pos], code[pos + 1], code[pos + 2], code[pos + 3]]);
        }
        _ => {}
    }

    disp_size as usize
}

/// Immediate value processing - FIXED to handle 16-bit immediates correctly
fn process_immediate_values(
    code: &[u8],
    pos: &mut usize,
    hs: &mut HookInstruction,
    cflags: u8,
    pref: u8,
    op64: u8,
) {
    // C_IMM_P66 processing
    if (cflags & C_IMM_P66) != 0 {
        if (cflags & C_REL32) != 0 {
            if (pref & PRE_66) != 0 {
                // 16-bit relative
                if read_immediate_16(code, pos, hs) {
                    hs.flags |= F_IMM16 | F_RELATIVE;
                }
                return; // Equivalent to "goto disasm_done"
            }
            // Continue to rel32_ok processing below
        } else if op64 != 0 {
            // 64-bit immediate
            if read_immediate_64(code, pos, hs) {
                hs.flags |= F_IMM64;
            }
        } else if (pref & PRE_66) == 0 {
            // 32-bit immediate
            if read_immediate_32(code, pos, hs) {
                hs.flags |= F_IMM32;
            }
        } else {
            // 16-bit immediate - FIXED: Actually process the 16-bit immediate
            if read_immediate_16(code, pos, hs) {
                hs.flags |= F_IMM16;
            }
        }
    }

    // C_IMM16 processing
    if (cflags & C_IMM16) != 0 && read_immediate_16(code, pos, hs) {
        hs.flags |= F_IMM16;
    }

    // C_IMM8 processing
    if (cflags & C_IMM8) != 0 && read_immediate_8(code, pos, hs) {
        hs.flags |= F_IMM8;
    }

    // C_REL32 processing
    if (cflags & C_REL32) != 0 {
        if read_immediate_32(code, pos, hs) {
            hs.flags |= F_IMM32 | F_RELATIVE;
        }
    } else if (cflags & C_REL8) != 0 && read_immediate_8(code, pos, hs) {
        hs.flags |= F_IMM8 | F_RELATIVE;
    }
}

/// Read 8-bit immediate value
fn read_immediate_8(code: &[u8], pos: &mut usize, hs: &mut HookInstruction) -> bool {
    if *pos >= code.len() {
        hs.error = true;
        hs.flags |= F_ERROR | F_ERROR_LENGTH;
        return false;
    }

    hs.immediate = code[*pos] as i8 as i32;
    *pos += 1;
    true
}

/// Read 16-bit immediate value
fn read_immediate_16(code: &[u8], pos: &mut usize, hs: &mut HookInstruction) -> bool {
    if *pos + 2 > code.len() {
        hs.error = true;
        hs.flags |= F_ERROR | F_ERROR_LENGTH;
        return false;
    }

    hs.immediate = i16::from_le_bytes([code[*pos], code[*pos + 1]]) as i32;
    *pos += 2;
    true
}

/// Read 32-bit immediate value
fn read_immediate_32(code: &[u8], pos: &mut usize, hs: &mut HookInstruction) -> bool {
    if *pos + 4 > code.len() {
        hs.error = true;
        hs.flags |= F_ERROR | F_ERROR_LENGTH;
        return false;
    }

    hs.immediate = i32::from_le_bytes([code[*pos], code[*pos + 1], code[*pos + 2], code[*pos + 3]]);
    *pos += 4;
    true
}

/// Read 64-bit immediate value (only for x64)
fn read_immediate_64(code: &[u8], pos: &mut usize, hs: &mut HookInstruction) -> bool {
    if *pos + 8 > code.len() {
        hs.error = true;
        hs.flags |= F_ERROR | F_ERROR_LENGTH;
        return false;
    }

    // For compatibility, store lower 32 bits in immediate field
    hs.immediate = i32::from_le_bytes([code[*pos], code[*pos + 1], code[*pos + 2], code[*pos + 3]]);
    *pos += 8;
    true
}
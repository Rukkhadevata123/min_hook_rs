//! Minimal disassembler specifically designed for MinHook
//! Only implements functionality actually needed by trampoline.c

#[cfg(not(target_arch = "x86_64"))]
compile_error!("MinHook-rs only supports x86_64");

/// Hook-specific instruction information
#[derive(Debug, Clone, Default)]
pub struct HookInstruction {
    /// Instruction length (most important)
    pub len: u8,
    /// Primary opcode
    pub opcode: u8,
    /// Secondary opcode (for two-byte instructions)
    pub opcode2: u8,
    /// ModR/M byte
    pub modrm: u8,
    /// Immediate value
    pub immediate: i32,
    /// Displacement value
    pub displacement: i32,
    /// Whether parsing failed
    pub error: bool,
}

impl HookInstruction {
    /// Check if instruction uses RIP-relative addressing (ModR/M = 00???101)
    #[inline]
    pub fn is_rip_relative(&self) -> bool {
        (self.modrm & 0xC7) == 0x05
    }

    /// Check if instruction is direct CALL (E8)
    #[inline]
    pub fn is_call(&self) -> bool {
        self.opcode == 0xE8
    }

    /// Check if instruction is direct JMP (E9/EB)
    #[inline]
    pub fn is_jmp(&self) -> bool {
        matches!(self.opcode, 0xE9 | 0xEB)
    }

    /// Check if instruction is conditional jump
    #[inline]
    pub fn is_conditional(&self) -> bool {
        (self.opcode & 0xF0) == 0x70 || // Short conditional jumps
        (self.opcode & 0xFC) == 0xE0 || // LOOP series
        (self.opcode2 & 0xF0) == 0x80 // Long conditional jumps
    }

    /// Check if instruction is RET
    #[inline]
    pub fn is_ret(&self) -> bool {
        (self.opcode & 0xFE) == 0xC2
    }

    /// Check if instruction is indirect JMP (FF /4)
    #[inline]
    pub fn is_indirect_jmp(&self) -> bool {
        self.opcode == 0xFF && (self.modrm >> 3 & 7) == 4
    }

    /// Calculate relative jump target address
    pub fn relative_target(&self, inst_addr: usize) -> Option<usize> {
        if !(self.is_call() || self.is_jmp() || self.is_conditional()) {
            return None;
        }

        let next_addr = inst_addr + self.len as usize;

        match self.opcode {
            0xE8 | 0xE9 => Some((next_addr as i64 + self.immediate as i64) as usize),
            0xEB => Some((next_addr as i64 + (self.immediate as i8) as i64) as usize),
            op if (op & 0xF0) == 0x70 || (op & 0xFC) == 0xE0 => {
                Some((next_addr as i64 + (self.immediate as i8) as i64) as usize)
            }
            _ if self.opcode2 != 0 && (self.opcode2 & 0xF0) == 0x80 => {
                Some((next_addr as i64 + self.immediate as i64) as usize)
            }
            _ => None,
        }
    }
}

/// Parse ModR/M addressing mode and return (displacement_size, needs_sib)
fn parse_modrm_addressing(modrm: u8) -> (usize, bool) {
    let mod_bits = modrm >> 6;
    let rm = modrm & 7;

    let disp_size = match mod_bits {
        0 => {
            if rm == 5 {
                4
            } else {
                0
            }
        } // RIP-relative or no displacement
        1 => 1, // 8-bit displacement
        2 => 4, // 32-bit displacement
        3 => 0, // Register direct
        _ => 0, // Other
    };

    let needs_sib = mod_bits != 3 && rm == 4;

    (disp_size, needs_sib)
}

/// Decode single instruction (simplified version based on original HDE64 logic)
pub fn decode_instruction(code: &[u8]) -> HookInstruction {
    let mut inst = HookInstruction::default();

    if code.is_empty() {
        inst.error = true;
        return inst;
    }

    let mut pos = 0;

    // Skip prefixes (up to 15 bytes)
    let mut prefix_count = 0;
    while pos < code.len() && prefix_count < 15 {
        match code[pos] {
            0x40..=0x4F => {
                pos += 1;
                prefix_count += 1;
            } // REX prefix
            0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3 => {
                pos += 1;
                prefix_count += 1;
            }
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 => {
                pos += 1;
                prefix_count += 1;
            }
            _ => break,
        }
    }

    if pos >= code.len() {
        inst.error = true;
        return inst;
    }

    // Primary opcode
    inst.opcode = code[pos];
    pos += 1;

    // Two-byte opcode
    if inst.opcode == 0x0F {
        if pos >= code.len() {
            inst.error = true;
            return inst;
        }
        inst.opcode2 = code[pos];
        pos += 1;
    }

    // Parse based on instruction type (based on actual needs from trampoline.c)
    match inst.opcode {
        // Group 1 instructions (80-83): need ModR/M + immediate - 关键修复！
        0x80..=0x83 => {
            if pos >= code.len() {
                inst.error = true;
                return inst;
            }

            inst.modrm = code[pos];
            pos += 1;

            // Handle ModR/M addressing
            let (disp_size, sib_needed) = parse_modrm_addressing(inst.modrm);

            if sib_needed && pos < code.len() {
                pos += 1; // Skip SIB
            }

            if code.len() < pos + disp_size {
                inst.error = true;
                return inst;
            }

            // Extract displacement for RIP-relative addressing
            if (inst.modrm & 0xC7) == 0x05 && disp_size == 4 {
                inst.displacement = read_i32(&code[pos..]).unwrap_or(0);
            }

            pos += disp_size;

            // Add immediate size based on opcode
            let imm_size = match inst.opcode {
                0x80 | 0x82 => 1, // 8-bit immediate
                0x81 => 4,        // 32-bit immediate
                0x83 => 1,        // 8-bit immediate (sign-extended) - SUB RSP, 78h
                _ => 0,
            };

            if code.len() < pos + imm_size {
                inst.error = true;
                return inst;
            }
            pos += imm_size;
        }

        // Direct relative CALL/JMP
        0xE8 | 0xE9 => {
            if code.len() < pos + 4 {
                inst.error = true;
                return inst;
            }
            inst.immediate = read_i32(&code[pos..]).unwrap();
            pos += 4;
        }

        // Short jump
        0xEB => {
            if pos >= code.len() {
                inst.error = true;
                return inst;
            }
            inst.immediate = code[pos] as i8 as i32;
            pos += 1;
        }

        // Short conditional jumps (70-7F)
        op if (op & 0xF0) == 0x70 => {
            if pos >= code.len() {
                inst.error = true;
                return inst;
            }
            inst.immediate = code[pos] as i8 as i32;
            pos += 1;
        }

        // LOOP series (E0-E3)
        op if (op & 0xFC) == 0xE0 => {
            if pos >= code.len() {
                inst.error = true;
                return inst;
            }
            inst.immediate = code[pos] as i8 as i32;
            pos += 1;
        }

        // Long conditional jumps (0F 8x)
        _ if inst.opcode2 != 0 && (inst.opcode2 & 0xF0) == 0x80 => {
            if code.len() < pos + 4 {
                inst.error = true;
                return inst;
            }
            inst.immediate = read_i32(&code[pos..]).unwrap();
            pos += 4;
        }

        // RET instructions
        0xC2 => {
            if code.len() < pos + 2 {
                inst.error = true;
                return inst;
            }
            pos += 2; // Skip 16-bit immediate
        }

        0xC3 => {
            // No operands
        }

        // Other instructions: use simplified length calculation
        _ => {
            // Check if ModR/M is needed
            if needs_modrm(inst.opcode, inst.opcode2) {
                if pos >= code.len() {
                    inst.error = true;
                    return inst;
                }

                inst.modrm = code[pos];
                pos += 1;

                let mod_bits = inst.modrm >> 6;
                let rm = inst.modrm & 7;

                // SIB byte
                if mod_bits != 3 && rm == 4 {
                    if pos >= code.len() {
                        inst.error = true;
                        return inst;
                    }
                    pos += 1; // Skip SIB
                }

                // Displacement handling
                let disp_size = match mod_bits {
                    0 if rm == 5 => 4, // RIP-relative addressing
                    1 => 1,            // 8-bit displacement
                    2 => 4,            // 32-bit displacement
                    _ => 0,
                };

                if disp_size > 0 {
                    if code.len() < pos + disp_size {
                        inst.error = true;
                        return inst;
                    }

                    // Extract displacement for RIP-relative addressing
                    if (inst.modrm & 0xC7) == 0x05 && disp_size == 4 {
                        inst.displacement = read_i32(&code[pos..]).unwrap_or(0);
                    }

                    pos += disp_size;
                }
            } else {
                // Immediate value handling for simple instructions
                let imm_size = get_immediate_size(inst.opcode, inst.opcode2);
                if imm_size > 0 {
                    if code.len() < pos + imm_size {
                        inst.error = true;
                        return inst;
                    }
                    pos += imm_size;
                }
            }
        }
    }

    inst.len = pos as u8;
    if inst.len > 15 {
        inst.error = true;
        inst.len = 15;
    }

    inst
}

/// Read 32-bit signed integer
#[inline]
fn read_i32(data: &[u8]) -> Option<i32> {
    if data.len() >= 4 {
        Some(i32::from_le_bytes([data[0], data[1], data[2], data[3]]))
    } else {
        None
    }
}

/// Check if instruction needs ModR/M byte (simplified version)
fn needs_modrm(opcode: u8, opcode2: u8) -> bool {
    if opcode2 != 0 {
        // Most two-byte instructions need ModR/M, except some special ones
        !matches!(opcode2, 0x01 | 0x06 | 0x08 | 0x09 | 0x0B | 0x30..=0x37)
    } else {
        // Single-byte instructions that need ModR/M (simplified list)
        matches!(opcode,
            0x00..=0x03 | 0x08..=0x0B | 0x10..=0x13 | 0x18..=0x1B |
            0x20..=0x23 | 0x28..=0x2B | 0x30..=0x33 | 0x38..=0x3B |
            0x62 | 0x63 | 0x69 | 0x6B |
            // 注意：0x80..=0x83 现在在上面专门处理，不在这里
            0x88..=0x8D | // MOV, LEA 等
            0xC0 | 0xC1 | 0xC6 | 0xC7 | 0xD0..=0xD3 | 0xF6 | 0xF7 | 0xFE | 0xFF
        )
    }
}

/// Get immediate value size (simplified version)
fn get_immediate_size(opcode: u8, opcode2: u8) -> usize {
    if opcode2 != 0 {
        return 0; // Two-byte instruction immediate handling is more complex, simplified here
    }

    match opcode {
        // 8-bit immediate
        0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C => 1,
        0xB0..=0xB7 => 1, // MOV reg8, imm8
        // 注意：0x80..=0x83 现在在decode_instruction中专门处理

        // 32-bit immediate
        0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D => 4,
        0xB8..=0xBF => 4, // MOV reg32/64, imm32/64

        // 16-bit immediate (in certain cases)
        0x68 => 4, // PUSH imm32
        0x6A => 1, // PUSH imm8

        _ => 0,
    }
}

/// Hook safety check
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

        // Check for internal jumps
        if let Some(target) = inst.relative_target(pos) {
            if target < required_length {
                return false;
            }
        }

        // Check for RET
        if inst.is_ret() && total_len < required_length {
            return false;
        }

        total_len += inst.len as usize;
        pos += inst.len as usize;
    }

    total_len >= required_length
}

/// Scan instruction boundaries
pub fn scan_boundaries(code: &[u8], max_bytes: usize) -> Vec<u8> {
    let mut boundaries = Vec::new();
    let mut pos = 0;

    while pos < code.len() && pos < max_bytes {
        let inst = decode_instruction(&code[pos..]);

        if inst.error || inst.len == 0 {
            break;
        }

        boundaries.push(pos as u8);
        pos += inst.len as usize;

        if inst.is_ret() {
            break;
        }
    }

    boundaries
}

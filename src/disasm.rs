//! MinHook 专用的最小化反汇编器
//! 只实现 trampoline.c 实际需要的功能

#[cfg(not(target_arch = "x86_64"))]
compile_error!("MinHook-rs only supports x86_64");

/// Hook 专用指令信息
#[derive(Debug, Clone, Default)]
pub struct HookInstruction {
    /// 指令长度（最重要）
    pub len: u8,
    /// 操作码
    pub opcode: u8,
    /// 第二操作码（双字节指令）
    pub opcode2: u8,
    /// ModR/M 字节
    pub modrm: u8,
    /// 立即数值
    pub immediate: i32,
    /// 位移值  
    pub displacement: i32,
    /// 是否解析错误
    pub error: bool,
}

impl HookInstruction {
    /// 是否是 RIP 相对寻址 (ModR/M = 00???101)
    #[inline]
    pub fn is_rip_relative(&self) -> bool {
        (self.modrm & 0xC7) == 0x05
    }

    /// 是否是直接 CALL (E8)
    #[inline]
    pub fn is_call(&self) -> bool {
        self.opcode == 0xE8
    }

    /// 是否是直接 JMP (E9/EB)
    #[inline]
    pub fn is_jmp(&self) -> bool {
        matches!(self.opcode, 0xE9 | 0xEB)
    }

    /// 是否是条件跳转
    #[inline]
    pub fn is_conditional(&self) -> bool {
        (self.opcode & 0xF0) == 0x70 || // 短条件跳转
        (self.opcode & 0xFC) == 0xE0 || // LOOP系列
        (self.opcode2 & 0xF0) == 0x80 // 长条件跳转
    }

    /// 是否是 RET
    #[inline]
    pub fn is_ret(&self) -> bool {
        (self.opcode & 0xFE) == 0xC2
    }

    /// 是否是间接 JMP (FF /4)
    #[inline]
    pub fn is_indirect_jmp(&self) -> bool {
        self.opcode == 0xFF && (self.modrm >> 3 & 7) == 4
    }

    /// 计算相对跳转目标地址
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

/// 解析单条指令（基于原始 HDE64 逻辑的简化版）
pub fn decode_instruction(code: &[u8]) -> HookInstruction {
    let mut inst = HookInstruction::default();

    if code.is_empty() {
        inst.error = true;
        return inst;
    }

    let mut pos = 0;

    // 跳过前缀（最多15字节）
    let mut prefix_count = 0;
    while pos < code.len() && prefix_count < 15 {
        match code[pos] {
            0x40..=0x4F => {
                pos += 1;
                prefix_count += 1;
            } // REX 前缀
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

    // 操作码
    inst.opcode = code[pos];
    pos += 1;

    // 双字节操作码
    if inst.opcode == 0x0F {
        if pos >= code.len() {
            inst.error = true;
            return inst;
        }
        inst.opcode2 = code[pos];
        pos += 1;
    }

    // 根据指令类型解析（基于 trampoline.c 的实际需求）
    match inst.opcode {
        // 直接相对 CALL/JMP
        0xE8 | 0xE9 => {
            if code.len() < pos + 4 {
                inst.error = true;
                return inst;
            }
            inst.immediate = read_i32(&code[pos..]).unwrap();
            pos += 4;
        }

        // 短跳转
        0xEB => {
            if pos >= code.len() {
                inst.error = true;
                return inst;
            }
            inst.immediate = code[pos] as i8 as i32;
            pos += 1;
        }

        // 短条件跳转 (70-7F)
        op if (op & 0xF0) == 0x70 => {
            if pos >= code.len() {
                inst.error = true;
                return inst;
            }
            inst.immediate = code[pos] as i8 as i32;
            pos += 1;
        }

        // LOOP 系列 (E0-E3)
        op if (op & 0xFC) == 0xE0 => {
            if pos >= code.len() {
                inst.error = true;
                return inst;
            }
            inst.immediate = code[pos] as i8 as i32;
            pos += 1;
        }

        // 长条件跳转（0F 8x）
        _ if inst.opcode2 != 0 && (inst.opcode2 & 0xF0) == 0x80 => {
            if code.len() < pos + 4 {
                inst.error = true;
                return inst;
            }
            inst.immediate = read_i32(&code[pos..]).unwrap();
            pos += 4;
        }

        // RET 指令
        0xC2 => {
            if code.len() < pos + 2 {
                inst.error = true;
                return inst;
            }
            pos += 2; // 跳过 16位立即数
        }

        0xC3 => {
            // 无操作数
        }

        // 其他指令：使用简化的长度计算
        _ => {
            // 检查是否需要 ModR/M
            if needs_modrm(inst.opcode, inst.opcode2) {
                if pos >= code.len() {
                    inst.error = true;
                    return inst;
                }

                inst.modrm = code[pos];
                pos += 1;

                let mod_bits = inst.modrm >> 6;
                let rm = inst.modrm & 7;

                // SIB 字节
                if mod_bits != 3 && rm == 4 {
                    if pos >= code.len() {
                        inst.error = true;
                        return inst;
                    }
                    pos += 1; // 跳过 SIB
                }

                // 位移处理
                let disp_size = match mod_bits {
                    0 if rm == 5 => 4, // RIP 相对寻址
                    1 => 1,            // 8位位移
                    2 => 4,            // 32位位移
                    _ => 0,
                };

                if disp_size > 0 {
                    if code.len() < pos + disp_size {
                        inst.error = true;
                        return inst;
                    }

                    // 提取 RIP 相对寻址的位移
                    if (inst.modrm & 0xC7) == 0x05 && disp_size == 4 {
                        inst.displacement = read_i32(&code[pos..]).unwrap_or(0);
                    }

                    pos += disp_size;
                }
            } else {
                // 简单指令的立即数处理
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

/// 读取 32位有符号整数
#[inline]
fn read_i32(data: &[u8]) -> Option<i32> {
    if data.len() >= 4 {
        Some(i32::from_le_bytes([data[0], data[1], data[2], data[3]]))
    } else {
        None
    }
}

/// 检查指令是否需要 ModR/M 字节（简化版）
fn needs_modrm(opcode: u8, opcode2: u8) -> bool {
    if opcode2 != 0 {
        // 大部分双字节指令都需要 ModR/M，除了一些特殊的
        !matches!(opcode2, 0x01 | 0x06 | 0x08 | 0x09 | 0x0B | 0x30..=0x37)
    } else {
        // 单字节指令中需要 ModR/M 的（简化列表）
        matches!(opcode,
            0x00..=0x03 | 0x08..=0x0B | 0x10..=0x13 | 0x18..=0x1B |
            0x20..=0x23 | 0x28..=0x2B | 0x30..=0x33 | 0x38..=0x3B |
            0x62 | 0x63 | 0x69 | 0x6B | 0x80..=0x8D |
            0xC0 | 0xC1 | 0xC6 | 0xC7 | 0xD0..=0xD3 | 0xF6 | 0xF7 | 0xFE | 0xFF
        )
    }
}

/// 获取立即数大小（简化版）
fn get_immediate_size(opcode: u8, opcode2: u8) -> usize {
    if opcode2 != 0 {
        return 0; // 双字节指令的立即数处理更复杂，这里简化
    }

    match opcode {
        // 8位立即数
        0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C => 1,
        0xB0..=0xB7 => 1, // MOV reg8, imm8

        // 32位立即数
        0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D => 4,
        0xB8..=0xBF => 4, // MOV reg32/64, imm32/64

        // 16位立即数（某些情况下）
        0x68 => 4, // PUSH imm32
        0x6A => 1, // PUSH imm8

        _ => 0,
    }
}

/// Hook 安全性检查
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

        // 检查内部跳转
        if let Some(target) = inst.relative_target(pos) {
            if target < required_length {
                return false;
            }
        }

        // 检查 RET
        if inst.is_ret() && total_len < required_length {
            return false;
        }

        total_len += inst.len as usize;
        pos += inst.len as usize;
    }

    total_len >= required_length
}

/// 扫描指令边界
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

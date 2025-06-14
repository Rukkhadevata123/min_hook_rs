//! x64 instruction disassembly engine

#[cfg(not(target_arch = "x86_64"))]
compile_error!("This disasm module only supports x86_64 architecture");

const C_MODRM: u8 = 0x01;
const C_IMM8: u8 = 0x02;
const C_IMM16: u8 = 0x04;
const C_IMM_P66: u8 = 0x10;
const C_REL8: u8 = 0x20;
const C_REL32: u8 = 0x40;
const C_GROUP: u8 = 0x80;
const C_ERROR: u8 = 0xff;

const PRE_NONE: u8 = 0x01;
const PRE_F2: u8 = 0x02;
const PRE_F3: u8 = 0x04;
const PRE_66: u8 = 0x08;
const PRE_67: u8 = 0x10;
const PRE_LOCK: u8 = 0x20;
const PRE_SEG: u8 = 0x40;

const DELTA_OPCODES: usize = 0x4a;
const DELTA_FPU_REG: usize = 0xfd;
const DELTA_FPU_MODRM: usize = 0x104;
const DELTA_PREFIXES: usize = 0x13c;
const DELTA_OP_LOCK_OK: usize = 0x1ae;
const DELTA_OP2_LOCK_OK: usize = 0x1c6;
const DELTA_OP_ONLY_MEM: usize = 0x1d8;
const DELTA_OP2_ONLY_MEM: usize = 0x1e7;

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
pub const F_PREFIX_REP: u32 = 0x03000000;
pub const F_PREFIX_66: u32 = 0x04000000;
pub const F_PREFIX_67: u32 = 0x08000000;
pub const F_PREFIX_LOCK: u32 = 0x10000000;
pub const F_PREFIX_SEG: u32 = 0x20000000;
pub const F_PREFIX_REX: u32 = 0x40000000;

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

#[repr(C)]
union ImmValue {
    imm8: u8,
    imm16: u16,
    imm32: u32,
    imm64: u64,
}

#[repr(C)]
union DispValue {
    disp8: u8,
    disp16: u16,
    disp32: u32,
}

#[repr(C)]
pub struct HdeResult {
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
    imm: ImmValue,
    disp: DispValue,
    pub flags: u32,
}

impl Default for HdeResult {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

impl HdeResult {
    pub fn imm8(&self) -> u8 {
        unsafe { self.imm.imm8 }
    }
    pub fn imm16(&self) -> u16 {
        unsafe { self.imm.imm16 }
    }
    pub fn imm32(&self) -> u32 {
        unsafe { self.imm.imm32 }
    }
    pub fn imm64(&self) -> u64 {
        unsafe { self.imm.imm64 }
    }
    pub fn disp8(&self) -> u8 {
        unsafe { self.disp.disp8 }
    }
    pub fn disp16(&self) -> u16 {
        unsafe { self.disp.disp16 }
    }
    pub fn disp32(&self) -> u32 {
        unsafe { self.disp.disp32 }
    }
}

pub fn hde_disasm(code: &[u8]) -> HdeResult {
    if code.is_empty() {
        let mut hs = HdeResult::default();
        hs.flags = F_ERROR | F_ERROR_LENGTH;
        return hs;
    }

    let mut x: u8;
    let mut c: u8;
    let mut p = code.as_ptr();
    let mut cflags: u8;
    let opcode: u8;
    let mut pref: u8 = 0;
    let mut ht = HDE64_TABLE.as_ptr();
    let mut m_mod: u8;
    let mut m_reg: u8;
    let mut m_rm: u8;
    let mut disp_size: u8 = 0;
    let mut op64: u8 = 0;
    let mut hs = HdeResult::default();

    // 前缀处理循环 - 使用 for 循环和 switch 模拟
    x = 16;
    loop {
        c = unsafe { *p };
        p = unsafe { p.add(1) };

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
            _ => break, // goto pref_done
        }

        x -= 1;
        if x == 0 {
            break;
        }
    }

    // pref_done:
    hs.flags = (pref as u32) << 23;

    if pref == 0 {
        pref |= PRE_NONE;
    }

    // REX 前缀处理 - 与原始 C 代码完全一致（不保存 rex）
    if (c & 0xf0) == 0x40 {
        hs.flags |= F_PREFIX_REX;
        hs.rex_w = (c & 0xf) >> 3;
        if hs.rex_w != 0 && unsafe { *p } & 0xf8 == 0xb8 {
            op64 += 1;
        }
        hs.rex_r = (c & 7) >> 2;
        hs.rex_x = (c & 3) >> 1;
        hs.rex_b = c & 1;

        c = unsafe { *p };
        p = unsafe { p.add(1) };
        if (c & 0xf0) == 0x40 {
            let opcode = c;
            // goto error_opcode
            hs.opcode = opcode;
            hs.flags |= F_ERROR | F_ERROR_OPCODE;
            hs.len = unsafe { p.offset_from(code.as_ptr()) as u8 };
            return hs;
        }
    }

    // Opcode 处理
    hs.opcode = c;
    if c == 0x0f {
        hs.opcode2 = unsafe { *p };
        c = unsafe { *p };
        p = unsafe { p.add(1) };
        ht = unsafe { ht.add(DELTA_OPCODES) };
    } else if c >= 0xa0 && c <= 0xa3 {
        op64 += 1;
        if (pref & PRE_67) != 0 {
            pref |= PRE_66;
        } else {
            pref &= !PRE_66;
        }
    }

    opcode = c;

    // Opcode flags 查找
    cflags = unsafe {
        let idx1 = *ht.add((opcode / 4) as usize);
        *ht.add(idx1 as usize + (opcode % 4) as usize)
    };

    if cflags == C_ERROR {
        // error_opcode:
        hs.flags |= F_ERROR | F_ERROR_OPCODE;
        cflags = 0;
        if (opcode & 0xFD) == 0x24 {
            // -3 等于 0xFD
            cflags = 1;
        }
    }

    // Group 处理
    x = 0;
    if (cflags & C_GROUP) != 0 {
        let t = unsafe {
            let ptr = ht.add((cflags & 0x7f) as usize) as *const u16;
            *ptr
        };
        cflags = t as u8;
        x = (t >> 8) as u8;
    }

    // 2-byte opcode 前缀检查
    if hs.opcode2 != 0 {
        ht = unsafe { HDE64_TABLE.as_ptr().add(DELTA_PREFIXES) };
        let check = unsafe {
            let idx1 = *ht.add((opcode / 4) as usize);
            *ht.add(idx1 as usize + (opcode % 4) as usize)
        };
        if (check & pref) != 0 {
            hs.flags |= F_ERROR | F_ERROR_OPCODE;
        }
    }

    // ModR/M 处理
    if (cflags & C_MODRM) != 0 {
        hs.flags |= F_MODRM;
        hs.modrm = unsafe { *p };
        c = unsafe { *p };
        p = unsafe { p.add(1) };

        m_mod = c >> 6;
        hs.modrm_mod = m_mod;
        m_rm = c & 7;
        hs.modrm_rm = m_rm;
        m_reg = (c & 0x3f) >> 3;
        hs.modrm_reg = m_reg;

        if x != 0 && ((x << m_reg) & 0x80) != 0 {
            hs.flags |= F_ERROR | F_ERROR_OPCODE;
        }

        // FPU 指令检查
        if hs.opcode2 == 0 && opcode >= 0xd9 && opcode <= 0xdf {
            let t = opcode - 0xd9;
            let fpu_t = if m_mod == 3 {
                unsafe {
                    let ht_fpu = HDE64_TABLE.as_ptr().add(DELTA_FPU_MODRM + (t as usize) * 8);
                    *ht_fpu.add(m_reg as usize) << m_rm
                }
            } else {
                unsafe {
                    let ht_fpu = HDE64_TABLE.as_ptr().add(DELTA_FPU_REG);
                    *ht_fpu.add(t as usize) << m_reg
                }
            };
            if (fpu_t & 0x80) != 0 {
                hs.flags |= F_ERROR | F_ERROR_OPCODE;
            }
        }

        // LOCK 前缀检查
        if (pref & PRE_LOCK) != 0 {
            if m_mod == 3 {
                hs.flags |= F_ERROR | F_ERROR_LOCK;
            } else {
                let mut op = opcode;
                let table_end: *const u8;

                if hs.opcode2 != 0 {
                    ht = unsafe { HDE64_TABLE.as_ptr().add(DELTA_OP2_LOCK_OK) };
                    table_end = unsafe { ht.add(DELTA_OP_ONLY_MEM - DELTA_OP2_LOCK_OK) };
                } else {
                    ht = unsafe { HDE64_TABLE.as_ptr().add(DELTA_OP_LOCK_OK) };
                    table_end = unsafe { ht.add(DELTA_OP2_LOCK_OK - DELTA_OP_LOCK_OK) };
                    op &= 0xFE; // -2 等于 0xFE
                }

                let mut no_lock_error = false;
                unsafe {
                    let mut ht_ptr = ht;
                    while ht_ptr != table_end {
                        if *ht_ptr == op {
                            ht_ptr = ht_ptr.add(1);
                            if ((*ht_ptr << m_reg) & 0x80) == 0 {
                                no_lock_error = true;
                            } else {
                                break;
                            }
                        }
                        ht_ptr = ht_ptr.add(1);
                    }
                }

                if !no_lock_error {
                    hs.flags |= F_ERROR | F_ERROR_LOCK;
                }
                // no_lock_error:
            }
        }

        // 操作数错误检查 - 完整实现 goto 逻辑
        let mut error_operand = false;

        if hs.opcode2 != 0 {
            match opcode {
                0x20 | 0x22 => {
                    m_mod = 3;
                    if m_reg > 4 || m_reg == 1 {
                        error_operand = true;
                    }
                    // else goto no_error_operand
                }
                0x21 | 0x23 => {
                    m_mod = 3;
                    if m_reg == 4 || m_reg == 5 {
                        error_operand = true;
                    }
                    // else goto no_error_operand
                }
                _ => {
                    // 继续下面的逻辑
                    if m_mod == 3 {
                        let table_end: *const u8;
                        ht = unsafe { HDE64_TABLE.as_ptr().add(DELTA_OP2_ONLY_MEM) };
                        table_end = unsafe { ht.add(HDE64_TABLE.len() - DELTA_OP2_ONLY_MEM) };

                        unsafe {
                            let mut ht_ptr = ht;
                            while ht_ptr != table_end {
                                if *ht_ptr == opcode {
                                    ht_ptr = ht_ptr.add(1);
                                    let pref_check = *ht_ptr;
                                    ht_ptr = ht_ptr.add(1);

                                    if (pref_check & pref) != 0 && ((*ht_ptr << m_reg) & 0x80) == 0
                                    {
                                        error_operand = true;
                                    }
                                    break;
                                } else {
                                    ht_ptr = ht_ptr.add(2);
                                }
                            }
                        }
                        // goto no_error_operand
                    } else {
                        match opcode {
                            0x50 | 0xd7 | 0xf7 => {
                                if (pref & (PRE_NONE | PRE_66)) != 0 {
                                    error_operand = true;
                                }
                            }
                            0xd6 => {
                                if (pref & (PRE_F2 | PRE_F3)) != 0 {
                                    error_operand = true;
                                }
                            }
                            0xc5 => {
                                error_operand = true;
                            }
                            _ => {}
                        }
                        // goto no_error_operand
                    }
                }
            }
        } else {
            match opcode {
                0x8c => {
                    if m_reg > 5 {
                        error_operand = true;
                    }
                    // else goto no_error_operand
                }
                0x8e => {
                    if m_reg == 1 || m_reg > 5 {
                        error_operand = true;
                    }
                    // else goto no_error_operand
                }
                _ => {
                    // 继续下面的逻辑
                    if m_mod == 3 {
                        let table_end: *const u8;
                        ht = unsafe { HDE64_TABLE.as_ptr().add(DELTA_OP_ONLY_MEM) };
                        table_end = unsafe { ht.add(DELTA_OP2_ONLY_MEM - DELTA_OP_ONLY_MEM) };

                        unsafe {
                            let mut ht_ptr = ht;
                            while ht_ptr != table_end {
                                if *ht_ptr == opcode {
                                    ht_ptr = ht_ptr.add(1);
                                    let pref_check = *ht_ptr;
                                    ht_ptr = ht_ptr.add(1);

                                    if (pref_check & pref) != 0 && ((*ht_ptr << m_reg) & 0x80) == 0
                                    {
                                        error_operand = true;
                                    }
                                    break;
                                } else {
                                    ht_ptr = ht_ptr.add(2);
                                }
                            }
                        }
                    }
                    // goto no_error_operand
                }
            }
        }

        // error_operand:
        if error_operand {
            hs.flags |= F_ERROR | F_ERROR_OPERAND;
        }

        // no_error_operand:
        c = unsafe { *p };
        p = unsafe { p.add(1) };

        // TEST 指令的立即数处理
        if m_reg <= 1 {
            if opcode == 0xf6 {
                cflags |= C_IMM8;
            } else if opcode == 0xf7 {
                cflags |= C_IMM_P66;
            }
        }

        // Displacement 大小计算
        match m_mod {
            0 => {
                if (pref & PRE_67) != 0 {
                    if m_rm == 6 {
                        disp_size = 2;
                    }
                } else {
                    if m_rm == 5 {
                        disp_size = 4;
                    }
                }
            }
            1 => {
                disp_size = 1;
            }
            2 => {
                disp_size = 2;
                if (pref & PRE_67) == 0 {
                    disp_size <<= 1;
                }
            }
            _ => {}
        }

        // SIB 字节处理 - 完全按照原始 C 代码（包括 bug）
        if m_mod != 3 && m_rm == 4 {
            hs.flags |= F_SIB;
            p = unsafe { p.add(1) };
            hs.sib = c;
            hs.sib_scale = c >> 6;
            hs.sib_index = (c & 0x3f) >> 3;
            hs.sib_base = c & 7;
            if hs.sib_base == 5 && (m_mod & 1) == 0 {
                disp_size = 4;
            }
        }

        // 回退指针
        p = unsafe { p.sub(1) };

        // Displacement 处理
        match disp_size {
            1 => {
                hs.flags |= F_DISP8;
                hs.disp.disp8 = unsafe { *p };
            }
            2 => {
                hs.flags |= F_DISP16;
                hs.disp.disp16 = unsafe { *(p as *const u16) };
            }
            4 => {
                hs.flags |= F_DISP32;
                hs.disp.disp32 = unsafe { *(p as *const u32) };
            }
            _ => {}
        }
        p = unsafe { p.add(disp_size as usize) };
    } else if (pref & PRE_LOCK) != 0 {
        hs.flags |= F_ERROR | F_ERROR_LOCK;
    }

    // 立即数处理 - 完整实现 goto 逻辑
    if (cflags & C_IMM_P66) != 0 {
        if (cflags & C_REL32) != 0 {
            if (pref & PRE_66) != 0 {
                hs.flags |= F_IMM16 | F_RELATIVE;
                hs.imm.imm16 = unsafe { *(p as *const u16) };
                p = unsafe { p.add(2) };
                // goto disasm_done
                hs.len = unsafe { p.offset_from(code.as_ptr()) as u8 };
                if hs.len > 15 {
                    hs.flags |= F_ERROR | F_ERROR_LENGTH;
                    hs.len = 15;
                }
                return hs;
            }
            // goto rel32_ok
        } else {
            if op64 != 0 {
                hs.flags |= F_IMM64;
                hs.imm.imm64 = unsafe { *(p as *const u64) };
                p = unsafe { p.add(8) };
            } else if (pref & PRE_66) == 0 {
                hs.flags |= F_IMM32;
                hs.imm.imm32 = unsafe { *(p as *const u32) };
                p = unsafe { p.add(4) };
            } else {
                // goto imm16_ok
                hs.flags |= F_IMM16;
                hs.imm.imm16 = unsafe { *(p as *const u16) };
                p = unsafe { p.add(2) };
            }
        }
    }

    // imm16_ok:
    if (cflags & C_IMM16) != 0 {
        hs.flags |= F_IMM16;
        hs.imm.imm16 = unsafe { *(p as *const u16) };
        p = unsafe { p.add(2) };
    }

    if (cflags & C_IMM8) != 0 {
        hs.flags |= F_IMM8;
        hs.imm.imm8 = unsafe { *p };
        p = unsafe { p.add(1) };
    }

    // rel32_ok:
    if (cflags & C_REL32) != 0 {
        hs.flags |= F_IMM32 | F_RELATIVE;
        hs.imm.imm32 = unsafe { *(p as *const u32) };
        p = unsafe { p.add(4) };
    } else if (cflags & C_REL8) != 0 {
        hs.flags |= F_IMM8 | F_RELATIVE;
        hs.imm.imm8 = unsafe { *p };
        p = unsafe { p.add(1) };
    }

    // disasm_done:
    hs.len = unsafe { p.offset_from(code.as_ptr()) as u8 };
    if hs.len > 15 {
        hs.flags |= F_ERROR | F_ERROR_LENGTH;
        hs.len = 15;
    }

    hs
}

#[inline]
pub fn get_instruction_length(code: &[u8]) -> u8 {
    hde_disasm(code).len
}

#[inline]
pub fn has_error(result: &HdeResult) -> bool {
    result.flags & F_ERROR != 0
}

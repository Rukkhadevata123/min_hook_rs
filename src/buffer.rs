//! Memory buffer management for MinHook-rs
//!
//! This module handles allocation of executable memory blocks near the target functions.
//! In x64 mode, memory must be allocated within ±2GB range for relative jumps to work.

use crate::error::{HookError, Result};
use std::ffi::c_void;
use std::ptr;
use std::sync::Mutex;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::SystemInformation::*;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("Buffer module only supports x86_64 architecture");

/// Size of each memory block (4KB = page size)
const MEMORY_BLOCK_SIZE: usize = 0x1000;

/// Maximum range for seeking memory blocks (±1GB, actual range is ±2GB)
const MAX_MEMORY_RANGE: usize = 0x40000000;

/// Size of each memory slot
const MEMORY_SLOT_SIZE: usize = 64;

/// Memory protection flags for executable addresses
const PAGE_EXECUTE_FLAGS: u32 =
    PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

/// Memory slot structure
#[repr(C)]
union MemorySlot {
    /// Pointer to next free slot
    next: *mut MemorySlot,
    /// Buffer data
    buffer: [u8; MEMORY_SLOT_SIZE],
}

/// Memory block structure
#[repr(C)]
struct MemoryBlock {
    /// Pointer to next block
    next: *mut MemoryBlock,
    /// Pointer to first free slot
    free_list: *mut MemorySlot,
    /// Number of used slots
    used_count: u32,
}

// 为了线程安全，我们需要实现 Send 和 Sync
unsafe impl Send for MemoryBlock {}
unsafe impl Sync for MemoryBlock {}
unsafe impl Send for MemorySlot {}
unsafe impl Sync for MemorySlot {}

/// Global memory buffer manager
struct BufferManager {
    /// First memory block in the chain
    blocks: *mut MemoryBlock,
}

// 实现 Send 和 Sync 以支持 Mutex
unsafe impl Send for BufferManager {}
unsafe impl Sync for BufferManager {}

impl BufferManager {
    const fn new() -> Self {
        Self {
            blocks: ptr::null_mut(),
        }
    }

    /// Initialize buffer manager
    fn initialize(&mut self) {
        // Nothing to do for now
    }

    /// Cleanup all allocated blocks
    fn uninitialize(&mut self) {
        let mut block = self.blocks;
        self.blocks = ptr::null_mut();

        while !block.is_null() {
            unsafe {
                let next = (*block).next;
                VirtualFree(block as *mut c_void, 0, MEM_RELEASE);
                block = next;
            }
        }
    }

    /// Allocate a buffer near the origin address
    fn allocate(&mut self, origin: *mut c_void) -> Result<*mut c_void> {
        let block = self.get_memory_block(origin)?;
        if block.is_null() {
            return Err(HookError::MemoryAlloc);
        }

        unsafe {
            // Get a free slot from the block
            let slot = (*block).free_list;
            if slot.is_null() {
                return Err(HookError::MemoryAlloc);
            }

            // Remove slot from free list
            (*block).free_list = (*slot).next;
            (*block).used_count += 1;

            #[cfg(debug_assertions)]
            {
                // Fill with INT3 for debugging
                ptr::write_bytes(slot as *mut u8, 0xCC, MEMORY_SLOT_SIZE);
            }

            Ok(slot as *mut c_void)
        }
    }

    /// Free an allocated buffer
    fn free(&mut self, buffer: *mut c_void) {
        if buffer.is_null() {
            return;
        }

        // Find the block containing this buffer
        let target_block_addr = (buffer as usize / MEMORY_BLOCK_SIZE) * MEMORY_BLOCK_SIZE;
        let mut block = self.blocks;
        let mut prev: *mut MemoryBlock = ptr::null_mut();

        while !block.is_null() {
            if block as usize == target_block_addr {
                unsafe {
                    let slot = buffer as *mut MemorySlot;

                    #[cfg(debug_assertions)]
                    {
                        // Clear for debugging
                        ptr::write_bytes(slot as *mut u8, 0x00, MEMORY_SLOT_SIZE);
                    }

                    // Return slot to free list
                    (*slot).next = (*block).free_list;
                    (*block).free_list = slot;
                    (*block).used_count -= 1;

                    // Free the block if completely unused
                    if (*block).used_count == 0 {
                        if !prev.is_null() {
                            (*prev).next = (*block).next;
                        } else {
                            self.blocks = (*block).next;
                        }

                        VirtualFree(block as *mut c_void, 0, MEM_RELEASE);
                    }
                }
                break;
            }

            unsafe {
                prev = block;
                block = (*block).next;
            }
        }
    }

    /// Get or create a memory block near the origin
    fn get_memory_block(&mut self, origin: *mut c_void) -> Result<*mut MemoryBlock> {
        let origin_addr = origin as usize;

        // Calculate address range for x64
        let (min_addr, max_addr) = unsafe {
            let mut si: SYSTEM_INFO = std::mem::zeroed();
            GetSystemInfo(&mut si);

            let mut min_addr = si.lpMinimumApplicationAddress as usize;
            let mut max_addr = si.lpMaximumApplicationAddress as usize;

            // origin ± 1GB (actual ±2GB for relative jumps)
            if origin_addr > MAX_MEMORY_RANGE && min_addr < origin_addr - MAX_MEMORY_RANGE {
                min_addr = origin_addr - MAX_MEMORY_RANGE;
            }

            if max_addr > origin_addr + MAX_MEMORY_RANGE {
                max_addr = origin_addr + MAX_MEMORY_RANGE;
            }

            // Reserve space for block header
            max_addr = max_addr.saturating_sub(MEMORY_BLOCK_SIZE - 1);

            (min_addr, max_addr)
        };

        // Look for existing reachable blocks with free slots
        let mut block = self.blocks;
        while !block.is_null() {
            let block_addr = block as usize;

            // Check if block is in range and has free slots
            if block_addr >= min_addr && block_addr < max_addr {
                unsafe {
                    if !(*block).free_list.is_null() {
                        return Ok(block);
                    }
                }
            }

            unsafe {
                block = (*block).next;
            }
        }

        // Need to allocate a new block
        self.allocate_new_block(origin, min_addr, max_addr)
    }

    /// Allocate a new memory block
    fn allocate_new_block(
        &mut self,
        origin: *mut c_void,
        min_addr: usize,
        max_addr: usize,
    ) -> Result<*mut MemoryBlock> {
        unsafe {
            let mut si: SYSTEM_INFO = std::mem::zeroed();
            GetSystemInfo(&mut si);

            // Try to allocate above the origin first
            let mut alloc_addr = origin;
            while alloc_addr as usize >= min_addr {
                alloc_addr = find_prev_free_region(
                    alloc_addr,
                    min_addr as *mut c_void,
                    si.dwAllocationGranularity,
                );
                if alloc_addr.is_null() {
                    break;
                }

                let block = VirtualAlloc(
                    alloc_addr,
                    MEMORY_BLOCK_SIZE,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                ) as *mut MemoryBlock;

                if !block.is_null() {
                    self.initialize_block(block);
                    return Ok(block);
                }
            }

            // Try to allocate below the origin
            let mut alloc_addr = origin;
            while (alloc_addr as usize) <= max_addr {
                alloc_addr = find_next_free_region(
                    alloc_addr,
                    max_addr as *mut c_void,
                    si.dwAllocationGranularity,
                );
                if alloc_addr.is_null() {
                    break;
                }

                let block = VirtualAlloc(
                    alloc_addr,
                    MEMORY_BLOCK_SIZE,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                ) as *mut MemoryBlock;

                if !block.is_null() {
                    self.initialize_block(block);
                    return Ok(block);
                }
            }

            Err(HookError::MemoryAlloc)
        }
    }

    /// Initialize a newly allocated block
    fn initialize_block(&mut self, block: *mut MemoryBlock) {
        unsafe {
            (*block).next = self.blocks;
            (*block).free_list = ptr::null_mut();
            (*block).used_count = 0;

            // Build free slot list
            let mut slot =
                (block as *mut u8).add(std::mem::size_of::<MemoryBlock>()) as *mut MemorySlot;
            let block_end = (block as *mut u8).add(MEMORY_BLOCK_SIZE);

            while (slot as *mut u8).add(MEMORY_SLOT_SIZE) <= block_end {
                (*slot).next = (*block).free_list;
                (*block).free_list = slot;
                slot = (slot as *mut u8).add(MEMORY_SLOT_SIZE) as *mut MemorySlot;
            }

            self.blocks = block;
        }
    }
}

/// Global buffer manager instance
static BUFFER_MANAGER: Mutex<BufferManager> = Mutex::new(BufferManager::new());

/// Find previous free region
fn find_prev_free_region(
    address: *mut c_void,
    min_addr: *mut c_void,
    granularity: u32,
) -> *mut c_void {
    let mut try_addr = address as usize;

    // Round down to allocation granularity
    try_addr -= try_addr % granularity as usize;
    try_addr = try_addr.saturating_sub(granularity as usize);

    while try_addr >= min_addr as usize {
        unsafe {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            if VirtualQuery(
                try_addr as *const c_void,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == 0
            {
                break;
            }

            if mbi.State == MEM_FREE {
                return try_addr as *mut c_void;
            }

            if (mbi.AllocationBase as usize) < granularity as usize {
                break;
            }

            try_addr = (mbi.AllocationBase as usize).saturating_sub(granularity as usize);
        }
    }

    ptr::null_mut()
}

/// Find next free region  
fn find_next_free_region(
    address: *mut c_void,
    max_addr: *mut c_void,
    granularity: u32,
) -> *mut c_void {
    let mut try_addr = address as usize;

    // Round down to allocation granularity
    try_addr -= try_addr % granularity as usize;
    try_addr += granularity as usize;

    while try_addr <= max_addr as usize {
        unsafe {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            if VirtualQuery(
                try_addr as *const c_void,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == 0
            {
                break;
            }

            if mbi.State == MEM_FREE {
                return try_addr as *mut c_void;
            }

            try_addr = mbi.BaseAddress as usize + mbi.RegionSize;

            // Round up to next allocation granularity
            try_addr += granularity as usize - 1;
            try_addr -= try_addr % granularity as usize;
        }
    }

    ptr::null_mut()
}

/// Initialize the buffer system
pub fn initialize_buffer() {
    if let Ok(mut manager) = BUFFER_MANAGER.lock() {
        manager.initialize();
    }
}

/// Uninitialize the buffer system
pub fn uninitialize_buffer() {
    if let Ok(mut manager) = BUFFER_MANAGER.lock() {
        manager.uninitialize();
    }
}

/// Allocate executable memory near the origin
pub fn allocate_buffer(origin: *mut c_void) -> Result<*mut c_void> {
    BUFFER_MANAGER
        .lock()
        .map_err(|_| HookError::MemoryAlloc)?
        .allocate(origin)
}

/// Free allocated buffer
pub fn free_buffer(buffer: *mut c_void) {
    if let Ok(mut manager) = BUFFER_MANAGER.lock() {
        manager.free(buffer);
    }
}

/// Check if address is executable
pub fn is_executable_address(address: *mut c_void) -> bool {
    unsafe {
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();

        if VirtualQuery(
            address as *const c_void,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        ) == 0
        {
            return false;
        }

        mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_EXECUTE_FLAGS) != 0
    }
}

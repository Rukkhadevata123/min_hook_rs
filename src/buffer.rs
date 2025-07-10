//! Memory buffer management for MinHook-rs
//!
//! This module provides memory allocation and management functionality
//! for trampoline functions. Direct port of buffer.c.

use std::ffi::c_void;
use std::ptr;
use std::sync::Mutex;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::SystemInformation::*;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("Buffer module only supports x86_64 architecture");

/// Size of each memory slot
pub const MEMORY_SLOT_SIZE: usize = 64;

/// Size of each memory block (page size of VirtualAlloc)
const MEMORY_BLOCK_SIZE: usize = 0x1000;

/// Max range for seeking a memory block (1024MB)
const MAX_MEMORY_RANGE: usize = 0x40000000;

/// Memory protection flags to check the executable address
const PAGE_EXECUTE_FLAGS: u32 =
    PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

/// Memory slot
#[repr(C)]
union MemorySlot {
    /// Pointer to next free slot
    next: *mut MemorySlot,
    /// Buffer data
    buffer: [u8; MEMORY_SLOT_SIZE],
}

/// Memory block info
#[repr(C)]
struct MemoryBlock {
    /// Pointer to next block
    next: *mut MemoryBlock,
    /// First element of the free slot list
    free: *mut MemorySlot,
    /// Number of used slots
    used_count: u32,
}

/// Global memory buffer manager
struct BufferManager {
    /// First element of the memory block list
    blocks: *mut MemoryBlock,
}

unsafe impl Send for BufferManager {}
unsafe impl Sync for BufferManager {}

impl BufferManager {
    const fn new() -> Self {
        Self {
            blocks: ptr::null_mut(),
        }
    }

    /// Get memory block
    fn get_memory_block(&mut self, origin: *mut c_void) -> *mut MemoryBlock {
        let mut block = self.blocks;

        unsafe {
            let mut si = std::mem::zeroed::<SYSTEM_INFO>();
            GetSystemInfo(&mut si);

            let mut min_addr = si.lpMinimumApplicationAddress as usize;
            let mut max_addr = si.lpMaximumApplicationAddress as usize;

            // origin ± 512MB
            if (origin as usize) > MAX_MEMORY_RANGE
                && min_addr < (origin as usize) - MAX_MEMORY_RANGE
            {
                min_addr = (origin as usize) - MAX_MEMORY_RANGE;
            }

            if max_addr > (origin as usize) + MAX_MEMORY_RANGE {
                max_addr = (origin as usize) + MAX_MEMORY_RANGE;
            }

            // Make room for MEMORY_BLOCK_SIZE bytes
            max_addr -= MEMORY_BLOCK_SIZE - 1;

            // Look for registered blocks for a reachable one
            while !block.is_null() {
                // Ignore blocks too far
                if (block as usize) < min_addr || (block as usize) >= max_addr {
                    block = (*block).next;
                    continue;
                }

                // The block has at least one unused slot
                if !(*block).free.is_null() {
                    return block;
                }

                block = (*block).next;
            }

            // Alloc a new block above if not found
            let mut alloc = origin;
            while (alloc as usize) >= min_addr {
                alloc = find_prev_free_region(
                    alloc,
                    min_addr as *mut c_void,
                    si.dwAllocationGranularity,
                );
                if alloc.is_null() {
                    break;
                }

                block = VirtualAlloc(
                    alloc,
                    MEMORY_BLOCK_SIZE,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                ) as *mut MemoryBlock;

                if !block.is_null() {
                    break;
                }
            }

            // Alloc a new block below if not found
            if block.is_null() {
                let mut alloc = origin;
                while (alloc as usize) <= max_addr {
                    alloc = find_next_free_region(
                        alloc,
                        max_addr as *mut c_void,
                        si.dwAllocationGranularity,
                    );
                    if alloc.is_null() {
                        break;
                    }

                    block = VirtualAlloc(
                        alloc,
                        MEMORY_BLOCK_SIZE,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE,
                    ) as *mut MemoryBlock;

                    if !block.is_null() {
                        break;
                    }
                }
            }

            if !block.is_null() {
                // Build a linked list of all the slots
                let mut slot = (block as *mut u8).add(size_of::<MemoryBlock>()) as *mut MemorySlot;
                (*block).free = ptr::null_mut();
                (*block).used_count = 0;

                while (slot as usize) - (block as usize) <= MEMORY_BLOCK_SIZE - MEMORY_SLOT_SIZE {
                    (*slot).next = (*block).free;
                    (*block).free = slot;
                    slot = slot.add(1);
                }

                (*block).next = self.blocks;
                self.blocks = block;
            }

            block
        }
    }

    /// Allocate a buffer
    fn allocate_buffer(
        &mut self,
        origin: *mut c_void,
    ) -> Result<*mut c_void, crate::error::HookError> {
        let block = self.get_memory_block(origin);
        if block.is_null() {
            return Err(crate::error::HookError::MemoryAlloc);
        }

        unsafe {
            // Remove an unused slot from the list
            let slot = (*block).free;
            (*block).free = (*slot).next;
            (*block).used_count += 1;

            #[cfg(debug_assertions)]
            {
                // Fill the slot with INT3 for debugging
                ptr::write_bytes(slot as *mut u8, 0xCC, MEMORY_SLOT_SIZE);
            }

            Ok(slot as *mut c_void)
        }
    }

    /// Free a buffer
    fn free_buffer(&mut self, buffer: *mut c_void) {
        if buffer.is_null() {
            return;
        }

        unsafe {
            let mut block = self.blocks;
            let mut prev: *mut MemoryBlock = ptr::null_mut();
            let target_block = ((buffer as usize) / MEMORY_BLOCK_SIZE) * MEMORY_BLOCK_SIZE;

            while !block.is_null() {
                if (block as usize) == target_block {
                    let slot = buffer as *mut MemorySlot;

                    #[cfg(debug_assertions)]
                    {
                        // Clear the released slot for debugging
                        ptr::write_bytes(slot as *mut u8, 0x00, MEMORY_SLOT_SIZE);
                    }

                    // Restore the released slot to the list
                    (*slot).next = (*block).free;
                    (*block).free = slot;
                    (*block).used_count -= 1;

                    // Free if unused
                    if (*block).used_count == 0 {
                        if !prev.is_null() {
                            (*prev).next = (*block).next;
                        } else {
                            self.blocks = (*block).next;
                        }

                        VirtualFree(block as *mut c_void, 0, MEM_RELEASE);
                    }

                    break;
                }

                prev = block;
                block = (*block).next;
            }
        }
    }

    /// Uninitialize the buffer system
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
}

/// Global memory buffer manager
static BUFFER_MANAGER: Mutex<BufferManager> = Mutex::new(BufferManager::new());

/// Initialize the buffer system
pub fn initialize_buffer() {
    // Nothing to do for now
}

/// Uninitialize the buffer system
pub fn uninitialize_buffer() {
    BUFFER_MANAGER.lock().unwrap().uninitialize();
}

/// Find previous free region
fn find_prev_free_region(
    address: *mut c_void,
    min_addr: *mut c_void,
    allocation_granularity: u32,
) -> *mut c_void {
    let mut try_addr = address as usize;

    // Round down to the allocation granularity
    try_addr -= try_addr % allocation_granularity as usize;

    // Start from the previous allocation granularity multiply
    try_addr -= allocation_granularity as usize;

    while try_addr >= min_addr as usize {
        unsafe {
            let mut mbi = std::mem::zeroed::<MEMORY_BASIC_INFORMATION>();
            if VirtualQuery(
                try_addr as *const c_void,
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == 0
            {
                break;
            }

            if mbi.State == MEM_FREE {
                return try_addr as *mut c_void;
            }

            if (mbi.AllocationBase as usize) < allocation_granularity as usize {
                break;
            }

            try_addr = mbi.AllocationBase as usize - allocation_granularity as usize;
        }
    }

    ptr::null_mut()
}

/// Find next free region
fn find_next_free_region(
    address: *mut c_void,
    max_addr: *mut c_void,
    allocation_granularity: u32,
) -> *mut c_void {
    let mut try_addr = address as usize;

    // Round down to the allocation granularity
    try_addr -= try_addr % allocation_granularity as usize;

    // Start from the next allocation granularity multiply
    try_addr += allocation_granularity as usize;

    while try_addr <= max_addr as usize {
        unsafe {
            let mut mbi = std::mem::zeroed::<MEMORY_BASIC_INFORMATION>();
            if VirtualQuery(
                try_addr as *const c_void,
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            ) == 0
            {
                break;
            }

            if mbi.State == MEM_FREE {
                return try_addr as *mut c_void;
            }

            try_addr = mbi.BaseAddress as usize + mbi.RegionSize;

            // Round up to the next allocation granularity
            try_addr += allocation_granularity as usize - 1;
            try_addr -= try_addr % allocation_granularity as usize;
        }
    }

    ptr::null_mut()
}

/// Allocate a buffer
pub fn allocate_buffer(origin: *mut c_void) -> Result<*mut c_void, crate::error::HookError> {
    BUFFER_MANAGER.lock().unwrap().allocate_buffer(origin)
}

/// Free a buffer
pub fn free_buffer(buffer: *mut c_void) {
    BUFFER_MANAGER.lock().unwrap().free_buffer(buffer);
}

/// Check if address is executable
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn is_executable_address(address: *mut c_void) -> bool {
    if address.is_null() {
        return false;
    }

    unsafe {
        let mut mi = std::mem::zeroed::<MEMORY_BASIC_INFORMATION>();
        VirtualQuery(address, &mut mi, size_of::<MEMORY_BASIC_INFORMATION>());

        mi.State == MEM_COMMIT && (mi.Protect & PAGE_EXECUTE_FLAGS) != 0
    }
}

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

/// Size of each memory block (4KB = page size of VirtualAlloc)
const MEMORY_BLOCK_SIZE: usize = 0x1000;

/// Max range for seeking a memory block (±1GB, actual range is ±2GB for relative jumps)
const MAX_MEMORY_RANGE: usize = 0x40000000;

/// Size of each memory slot
pub const MEMORY_SLOT_SIZE: usize = 64;

/// Memory protection flags to check the executable address
const PAGE_EXECUTE_FLAGS: u32 =
    PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

/// Memory slot - exact port of C union
#[repr(C)]
union MemorySlot {
    /// Pointer to next free slot
    next: *mut MemorySlot,
    /// Buffer data
    buffer: [u8; MEMORY_SLOT_SIZE],
}

/// Memory block info - exact port of C struct
/// Placed at the head of each block
#[repr(C)]
struct MemoryBlock {
    /// Pointer to next block
    next: *mut MemoryBlock,
    /// First element of the free slot list
    free_list: *mut MemorySlot,
    /// Number of used slots
    used_count: u32,
}

unsafe impl Send for MemoryBlock {}
unsafe impl Sync for MemoryBlock {}
unsafe impl Send for MemorySlot {}
unsafe impl Sync for MemorySlot {}

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

    /// Initialize buffer manager - port of InitializeBuffer
    fn initialize(&mut self) {
        // Nothing to do for now
    }

    /// Cleanup all allocated blocks - port of UninitializeBuffer
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

    /// Allocate a buffer near the origin address - port of AllocateBuffer
    fn allocate(&mut self, origin: *mut c_void) -> Result<*mut c_void> {
        let block = self.get_memory_block(origin)?;
        if block.is_null() {
            return Err(HookError::MemoryAlloc);
        }

        unsafe {
            // Remove an unused slot from the list
            let slot = (*block).free_list;
            (*block).free_list = (*slot).next;
            (*block).used_count += 1;

            #[cfg(debug_assertions)]
            {
                // Fill the slot with INT3 for debugging
                ptr::write_bytes(slot as *mut u8, 0xCC, MEMORY_SLOT_SIZE);
            }

            Ok(slot as *mut c_void)
        }
    }

    /// Free an allocated buffer - port of FreeBuffer
    fn free(&mut self, buffer: *mut c_void) {
        if buffer.is_null() {
            return;
        }

        let mut block = self.blocks;
        let mut prev: *mut MemoryBlock = ptr::null_mut();
        let target_block = ((buffer as usize) / MEMORY_BLOCK_SIZE) * MEMORY_BLOCK_SIZE;

        while !block.is_null() {
            if (block as usize) == target_block {
                unsafe {
                    let slot = buffer as *mut MemorySlot;

                    #[cfg(debug_assertions)]
                    {
                        // Clear the released slot for debugging
                        ptr::write_bytes(slot as *mut u8, 0x00, MEMORY_SLOT_SIZE);
                    }

                    // Restore the released slot to the list
                    (*slot).next = (*block).free_list;
                    (*block).free_list = slot;
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
                }
                break;
            }

            unsafe {
                prev = block;
                block = (*block).next;
            }
        }
    }

    /// Get or create a memory block near the origin - port of GetMemoryBlock
    fn get_memory_block(&mut self, origin: *mut c_void) -> Result<*mut MemoryBlock> {
        // Calculate address range for x64
        let (min_addr, max_addr) = unsafe {
            let mut si: SYSTEM_INFO = std::mem::zeroed();
            GetSystemInfo(&mut si);

            let mut min_addr = si.lpMinimumApplicationAddress as usize;
            let mut max_addr = si.lpMaximumApplicationAddress as usize;

            // origin ± 512MB (C comment says 512MB but MAX_MEMORY_RANGE is 1GB)
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

            (min_addr, max_addr)
        };

        // Look the registered blocks for a reachable one
        let mut block = self.blocks;
        while !block.is_null() {
            let block_addr = block as usize;

            // Ignore the blocks too far
            if block_addr >= min_addr && block_addr < max_addr {
                unsafe {
                    // The block has at least one unused slot
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

            let mut block: *mut MemoryBlock = ptr::null_mut();

            // Alloc a new block above if not found
            let mut alloc_addr = origin;
            while (alloc_addr as usize) >= min_addr {
                alloc_addr = find_prev_free_region(
                    alloc_addr,
                    min_addr as *mut c_void,
                    si.dwAllocationGranularity,
                );
                if alloc_addr.is_null() {
                    break;
                }

                block = VirtualAlloc(
                    alloc_addr,
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

                    block = VirtualAlloc(
                        alloc_addr,
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
                self.initialize_block(block);
                Ok(block)
            } else {
                Err(HookError::MemoryAlloc)
            }
        }
    }

    /// Initialize a newly allocated block - exact port of C logic
    fn initialize_block(&mut self, block: *mut MemoryBlock) {
        unsafe {
            // Build a linked list of all the slots
            // PMEMORY_SLOT pSlot = (PMEMORY_SLOT)pBlock + 1;
            let mut slot = block.add(1) as *mut MemorySlot;

            (*block).free_list = ptr::null_mut();
            (*block).used_count = 0;

            // C code: do { ... } while ((ULONG_PTR)pSlot - (ULONG_PTR)pBlock <= MEMORY_BLOCK_SIZE - MEMORY_SLOT_SIZE);
            loop {
                (*slot).next = (*block).free_list;
                (*block).free_list = slot;
                slot = slot.add(1);

                // Check loop condition
                if (slot as usize) - (block as usize) > MEMORY_BLOCK_SIZE - MEMORY_SLOT_SIZE {
                    break;
                }
            }

            (*block).next = self.blocks;
            self.blocks = block;
        }
    }
}

/// Global buffer manager instance
static BUFFER_MANAGER: Mutex<BufferManager> = Mutex::new(BufferManager::new());

/// Find previous free region - exact port of FindPrevFreeRegion
fn find_prev_free_region(
    address: *mut c_void,
    min_addr: *mut c_void,
    allocation_granularity: u32,
) -> *mut c_void {
    let mut try_addr = address as usize;

    // Round down to the allocation granularity
    try_addr -= try_addr % allocation_granularity as usize;

    // Start from the previous allocation granularity multiply
    try_addr = try_addr.saturating_sub(allocation_granularity as usize);

    while try_addr >= (min_addr as usize) {
        unsafe {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
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

            try_addr =
                (mbi.AllocationBase as usize).saturating_sub(allocation_granularity as usize);
        }
    }

    ptr::null_mut()
}

/// Find next free region - exact port of FindNextFreeRegion
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

    while try_addr <= (max_addr as usize) {
        unsafe {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
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

/// Initialize the buffer system - port of InitializeBuffer
pub fn initialize_buffer() {
    if let Ok(mut manager) = BUFFER_MANAGER.lock() {
        manager.initialize();
    }
}

/// Uninitialize the buffer system - port of UninitializeBuffer
pub fn uninitialize_buffer() {
    if let Ok(mut manager) = BUFFER_MANAGER.lock() {
        manager.uninitialize();
    }
}

/// Allocate executable memory near the origin - port of AllocateBuffer
pub fn allocate_buffer(origin: *mut c_void) -> Result<*mut c_void> {
    BUFFER_MANAGER
        .lock()
        .map_err(|_| HookError::MemoryAlloc)?
        .allocate(origin)
}

/// Free allocated buffer - port of FreeBuffer
pub fn free_buffer(buffer: *mut c_void) {
    if let Ok(mut manager) = BUFFER_MANAGER.lock() {
        manager.free(buffer);
    }
}

/// Check if address is executable - port of IsExecutableAddress
pub fn is_executable_address(address: *mut c_void) -> bool {
    unsafe {
        let mut mi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        VirtualQuery(
            address as *const c_void,
            &mut mi,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        );

        mi.State == MEM_COMMIT && (mi.Protect & PAGE_EXECUTE_FLAGS) != 0
    }
}

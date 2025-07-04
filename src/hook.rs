//! Hook management for MinHook-rs
//!
//! This module provides the main API for creating, enabling, and managing function hooks.
//! Direct port of hook.c, maintaining exact compatibility with original MinHook.

use crate::buffer::{free_buffer, initialize_buffer, is_executable_address, uninitialize_buffer};
use crate::error::{HookError, Result};
use crate::instruction::*;
use crate::trampoline::allocate_trampoline;
use std::ffi::c_void;
use std::ptr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("Hook module only supports x86_64 architecture");

/// Initial capacity of the HOOK_ENTRY buffer
const INITIAL_HOOK_CAPACITY: usize = 32;

/// Initial capacity of the thread IDs buffer
const INITIAL_THREAD_CAPACITY: usize = 128;

/// Special hook position values (matching C code)
const INVALID_HOOK_POS: usize = usize::MAX;
const ALL_HOOKS_POS: usize = usize::MAX;

/// Freeze() action argument defines (matching C code)
const ACTION_DISABLE: u32 = 0;
const ACTION_ENABLE: u32 = 1;
const ACTION_APPLY_QUEUED: u32 = 2;

/// Thread access rights for suspending/resuming threads
const THREAD_ACCESS: u32 =
    THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT;

/// Hook information - exact port of C HOOK_ENTRY
#[derive(Debug, Clone)]
struct HookEntry {
    /// Address of the target function
    target: *mut c_void,
    /// Address of the detour or relay function
    detour: *mut c_void,
    /// Address of the trampoline function
    trampoline: *mut c_void,
    /// Original prologue of the target function
    backup: [u8; 8],

    /// Uses the hot patch area
    patch_above: bool,
    /// Enabled
    is_enabled: bool,
    /// Queued for enabling/disabling when != is_enabled
    queue_enable: bool,

    /// Count of the instruction boundaries
    n_ip: u32,
    /// Instruction boundaries of the target function
    old_ips: [u8; 8],
    /// Instruction boundaries of the trampoline function
    new_ips: [u8; 8],
}

/// Suspended threads for Freeze()/Unfreeze() - exact port of C FROZEN_THREADS
struct FrozenThreads {
    /// Data heap
    items: Vec<u32>,
    /// Size of allocated data heap, items
    capacity: usize,
    /// Actual number of data items
    size: usize,
}

/// Hook entries collection - exact port of C g_hooks structure
struct HookCollection {
    /// Data heap
    items: Vec<HookEntry>,
    /// Size of allocated data heap, items
    capacity: usize,
    /// Actual number of data items
    size: usize,
}

/// Global hook manager - exact port of C global variables
struct HookManager {
    /// Private heap handle equivalent. If false, this library is not initialized.
    heap: bool,
    /// Hook entries
    hooks: HookCollection,
}

/// Spin lock flag for enter_spin_lock()/leave_spin_lock()
static G_IS_LOCKED: AtomicBool = AtomicBool::new(false);

/// Global hook manager instance
static HOOK_MANAGER: Mutex<HookManager> = Mutex::new(HookManager::new());

impl HookEntry {
    fn new() -> Self {
        Self {
            target: ptr::null_mut(),
            detour: ptr::null_mut(),
            trampoline: ptr::null_mut(),
            backup: [0; 8],
            patch_above: false,
            is_enabled: false,
            queue_enable: false,
            n_ip: 0,
            old_ips: [0; 8],
            new_ips: [0; 8],
        }
    }
}

impl FrozenThreads {
    fn new() -> Self {
        Self {
            items: Vec::new(),
            capacity: 0,
            size: 0,
        }
    }
}

impl HookCollection {
    fn new() -> Self {
        Self {
            items: Vec::new(),
            capacity: 0,
            size: 0,
        }
    }
}

impl HookManager {
    const fn new() -> Self {
        Self {
            heap: false,
            hooks: HookCollection {
                items: Vec::new(),
                capacity: 0,
                size: 0,
            },
        }
    }

    /// Returns INVALID_HOOK_POS if not found - exact port of FindHookEntry
    fn find_hook_entry(&self, target: *mut c_void) -> usize {
        for i in 0..self.hooks.size {
            if std::ptr::eq(target, self.hooks.items[i].target) {
                return i;
            }
        }
        INVALID_HOOK_POS
    }

    /// Add hook entry - exact port of AddHookEntry
    fn add_hook_entry(&mut self) -> Option<&mut HookEntry> {
        if self.hooks.items.is_empty() {
            self.hooks.capacity = INITIAL_HOOK_CAPACITY;
            self.hooks.items.reserve(self.hooks.capacity);
            if self.hooks.items.capacity() == 0 {
                return None;
            }
        } else if self.hooks.size >= self.hooks.capacity {
            self.hooks.capacity *= 2;
            self.hooks.items.reserve(self.hooks.capacity);
            if self.hooks.items.capacity() < self.hooks.capacity {
                return None;
            }
        }

        self.hooks.items.push(HookEntry::new());
        self.hooks.size += 1;
        Some(&mut self.hooks.items[self.hooks.size - 1])
    }

    /// Delete hook entry - exact port of DeleteHookEntry
    fn delete_hook_entry(&mut self, pos: usize) {
        if pos < self.hooks.size - 1 {
            self.hooks.items[pos] = self.hooks.items[self.hooks.size - 1].clone();
        }

        self.hooks.size -= 1;
        self.hooks.items.truncate(self.hooks.size);

        if self.hooks.capacity / 2 >= INITIAL_HOOK_CAPACITY
            && self.hooks.capacity / 2 >= self.hooks.size
        {
            self.hooks.capacity /= 2;
            self.hooks.items.shrink_to(self.hooks.capacity);
        }
    }

    /// Find old IP from new IP - exact port of FindOldIP
    fn find_old_ip(&self, hook: &HookEntry, ip: usize) -> usize {
        if hook.patch_above && ip == (hook.target as usize - size_of::<JmpRel>()) {
            return hook.target as usize;
        }

        for i in 0..hook.n_ip as usize {
            if ip == (hook.trampoline as usize + hook.new_ips[i] as usize) {
                return hook.target as usize + hook.old_ips[i] as usize;
            }
        }

        // Check relay function
        if ip == hook.detour as usize {
            return hook.target as usize;
        }

        0
    }

    /// Find new IP from old IP - exact port of FindNewIP
    fn find_new_ip(&self, hook: &HookEntry, ip: usize) -> usize {
        for i in 0..hook.n_ip as usize {
            if ip == (hook.target as usize + hook.old_ips[i] as usize) {
                return hook.trampoline as usize + hook.new_ips[i] as usize;
            }
        }
        0
    }

    /// Process thread IPs - exact port of ProcessThreadIPs
    fn process_thread_ips(&self, thread: HANDLE, pos: usize, action: u32) {
        // If the thread suspended in the overwritten area,
        // move IP to the proper address.

        let mut context = unsafe { std::mem::zeroed::<CONTEXT>() };
        context.ContextFlags = CONTEXT_CONTROL_AMD64;

        unsafe {
            if GetThreadContext(thread, &mut context) == 0 {
                return;
            }
        }

        let (start_pos, count) = if pos == ALL_HOOKS_POS {
            (0, self.hooks.size)
        } else {
            (pos, pos + 1)
        };

        for i in start_pos..count {
            let hook = &self.hooks.items[i];
            let enable = match action {
                ACTION_DISABLE => false,
                ACTION_ENABLE => true,
                _ => hook.queue_enable, // ACTION_APPLY_QUEUED
            };

            if hook.is_enabled == enable {
                continue;
            }

            let ip = if enable {
                self.find_new_ip(hook, context.Rip as usize)
            } else {
                self.find_old_ip(hook, context.Rip as usize)
            };

            if ip != 0 {
                context.Rip = ip as u64;
                unsafe {
                    SetThreadContext(thread, &context);
                }
            }
        }
    }

    /// Enumerate threads - exact port of EnumerateThreads
    fn enumerate_threads(&self, threads: &mut FrozenThreads) -> bool {
        let mut succeeded = false;

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                return false;
            }

            let mut te = THREADENTRY32 {
                dwSize: size_of::<THREADENTRY32>() as u32,
                cntUsage: 0,
                th32ThreadID: 0,
                th32OwnerProcessID: 0,
                tpBasePri: 0,
                tpDeltaPri: 0,
                dwFlags: 0,
            };

            if Thread32First(snapshot, &mut te) != 0 {
                succeeded = true;
                loop {
                    if te.dwSize >= 16 // FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(DWORD)
                        && te.th32OwnerProcessID == GetCurrentProcessId()
                        && te.th32ThreadID != GetCurrentThreadId()
                    {
                        if threads.items.is_empty() {
                            threads.capacity = INITIAL_THREAD_CAPACITY;
                            threads.items.reserve(threads.capacity);
                            if threads.items.capacity() == 0 {
                                succeeded = false;
                                break;
                            }
                        } else if threads.size >= threads.capacity {
                            threads.capacity *= 2;
                            threads.items.reserve(threads.capacity);
                            if threads.items.capacity() < threads.capacity {
                                succeeded = false;
                                break;
                            }
                        }
                        threads.items.push(te.th32ThreadID);
                        threads.size += 1;
                    }

                    te.dwSize = size_of::<THREADENTRY32>() as u32;
                    if Thread32Next(snapshot, &mut te) == 0 {
                        break;
                    }
                }

                if succeeded && GetLastError() != ERROR_NO_MORE_FILES {
                    succeeded = false;
                }

                if !succeeded {
                    threads.items.clear();
                }
            }
            CloseHandle(snapshot);
        }

        succeeded
    }

    /// Freeze threads - exact port of Freeze
    fn freeze(&self, threads: &mut FrozenThreads, pos: usize, action: u32) -> Result<()> {
        *threads = FrozenThreads::new();

        if !self.enumerate_threads(threads) {
            return Err(HookError::MemoryAlloc);
        }

        if !threads.items.is_empty() {
            for i in 0..threads.size {
                unsafe {
                    let thread_handle = OpenThread(THREAD_ACCESS, FALSE, threads.items[i]);
                    let mut suspended = false;

                    if !thread_handle.is_null() {
                        let result = SuspendThread(thread_handle);
                        if result != 0xFFFFFFFF {
                            suspended = true;
                            self.process_thread_ips(thread_handle, pos, action);
                        }
                        CloseHandle(thread_handle);
                    }

                    if !suspended {
                        // Mark thread as not suspended, so it's not resumed later on
                        threads.items[i] = 0;
                    }
                }
            }
        }

        Ok(())
    }

    /// Unfreeze threads - exact port of Unfreeze
    fn unfreeze(&self, threads: &FrozenThreads) {
        if !threads.items.is_empty() {
            for i in 0..threads.size {
                let thread_id = threads.items[i];
                if thread_id != 0 {
                    unsafe {
                        let thread_handle = OpenThread(THREAD_ACCESS, FALSE, thread_id);
                        if !thread_handle.is_null() {
                            ResumeThread(thread_handle);
                            CloseHandle(thread_handle);
                        }
                    }
                }
            }
        }
    }

    /// Enable hook at low level - exact port of EnableHookLL
    fn enable_hook_ll(&mut self, pos: usize, enable: bool) -> Result<()> {
        let hook = &mut self.hooks.items[pos];
        let mut old_protect = 0u32;
        let patch_size = if hook.patch_above {
            size_of::<JmpRel>() + size_of::<JmpRelShort>()
        } else {
            size_of::<JmpRel>()
        };
        let patch_target = if hook.patch_above {
            unsafe { (hook.target as *mut u8).sub(size_of::<JmpRel>()) }
        } else {
            hook.target as *mut u8
        };

        unsafe {
            if VirtualProtect(
                patch_target as *mut c_void,
                patch_size,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            ) == 0
            {
                return Err(HookError::MemoryProtect);
            }

            if enable {
                // Create JMP_REL
                let jmp = JmpRel::new_jmp(
                    (hook.detour as isize - (patch_target as isize + size_of::<JmpRel>() as isize))
                        as i32,
                );
                ptr::copy_nonoverlapping(
                    &jmp as *const JmpRel as *const u8,
                    patch_target,
                    size_of::<JmpRel>(),
                );

                if hook.patch_above {
                    // Create short jump at original location
                    let short_jmp = JmpRelShort::new(
                        -(size_of::<JmpRelShort>() as i8 + size_of::<JmpRel>() as i8),
                    );
                    ptr::copy_nonoverlapping(
                        &short_jmp as *const JmpRelShort as *const u8,
                        hook.target as *mut u8,
                        size_of::<JmpRelShort>(),
                    );
                }
            } else if hook.patch_above {
                ptr::copy_nonoverlapping(
                    hook.backup.as_ptr(),
                    patch_target,
                    size_of::<JmpRel>() + size_of::<JmpRelShort>(),
                );
            } else {
                ptr::copy_nonoverlapping(hook.backup.as_ptr(), patch_target, size_of::<JmpRel>());
            }

            VirtualProtect(
                patch_target as *mut c_void,
                patch_size,
                old_protect,
                &mut old_protect,
            );

            // Just-in-case measure
            FlushInstructionCache(GetCurrentProcess(), patch_target as *mut c_void, patch_size);
        }

        hook.is_enabled = enable;
        hook.queue_enable = enable;

        Ok(())
    }

    /// Enable all hooks at low level - exact port of EnableAllHooksLL
    fn enable_all_hooks_ll(&mut self, enable: bool) -> Result<()> {
        let mut first = INVALID_HOOK_POS;

        for i in 0..self.hooks.size {
            if self.hooks.items[i].is_enabled != enable {
                first = i;
                break;
            }
        }

        if first != INVALID_HOOK_POS {
            let mut threads = FrozenThreads::new();
            self.freeze(
                &mut threads,
                ALL_HOOKS_POS,
                if enable {
                    ACTION_ENABLE
                } else {
                    ACTION_DISABLE
                },
            )?;

            let mut result = Ok(());
            for i in first..self.hooks.size {
                if self.hooks.items[i].is_enabled != enable {
                    if let Err(e) = self.enable_hook_ll(i, enable) {
                        result = Err(e);
                        break;
                    }
                }
            }

            self.unfreeze(&threads);
            result
        } else {
            Ok(())
        }
    }

    /// Enable/disable hook - exact port of EnableHook
    fn enable_hook(&mut self, target: *mut c_void, enable: bool) -> Result<()> {
        if !self.heap {
            return Err(HookError::NotInitialized);
        }

        if target == ALL_HOOKS {
            self.enable_all_hooks_ll(enable)
        } else {
            let pos = self.find_hook_entry(target);
            if pos != INVALID_HOOK_POS {
                if self.hooks.items[pos].is_enabled != enable {
                    let mut threads = FrozenThreads::new();
                    self.freeze(&mut threads, pos, ACTION_ENABLE)?;

                    let result = self.enable_hook_ll(pos, enable);
                    self.unfreeze(&threads);
                    result
                } else {
                    Err(if enable {
                        HookError::Enabled
                    } else {
                        HookError::Disabled
                    })
                }
            } else {
                Err(HookError::NotCreated)
            }
        }
    }

    /// Queue hook for enable/disable - exact port of QueueHook
    fn queue_hook(&mut self, target: *mut c_void, queue_enable: bool) -> Result<()> {
        if !self.heap {
            return Err(HookError::NotInitialized);
        }

        if target == ALL_HOOKS {
            for i in 0..self.hooks.size {
                self.hooks.items[i].queue_enable = queue_enable;
            }
        } else {
            let pos = self.find_hook_entry(target);
            if pos != INVALID_HOOK_POS {
                self.hooks.items[pos].queue_enable = queue_enable;
            } else {
                return Err(HookError::NotCreated);
            }
        }

        Ok(())
    }

    /// Apply queued operations - exact port of MH_ApplyQueued
    fn apply_queued(&mut self) -> Result<()> {
        if !self.heap {
            return Err(HookError::NotInitialized);
        }

        let mut first = INVALID_HOOK_POS;

        for i in 0..self.hooks.size {
            if self.hooks.items[i].is_enabled != self.hooks.items[i].queue_enable {
                first = i;
                break;
            }
        }

        if first != INVALID_HOOK_POS {
            let mut threads = FrozenThreads::new();
            self.freeze(&mut threads, ALL_HOOKS_POS, ACTION_APPLY_QUEUED)?;

            let mut result = Ok(());
            for i in first..self.hooks.size {
                let hook = &self.hooks.items[i];
                if hook.is_enabled != hook.queue_enable {
                    if let Err(e) = self.enable_hook_ll(i, hook.queue_enable) {
                        result = Err(e);
                        break;
                    }
                }
            }

            self.unfreeze(&threads);
            result
        } else {
            Ok(())
        }
    }

    /// Initialize - exact port of MH_Initialize
    fn initialize(&mut self) -> Result<()> {
        if self.heap {
            return Err(HookError::AlreadyInitialized);
        }

        // Initialize the internal function buffer
        initialize_buffer();
        self.heap = true;

        Ok(())
    }

    /// Uninitialize - exact port of MH_Uninitialize
    fn uninitialize(&mut self) -> Result<()> {
        if !self.heap {
            return Err(HookError::NotInitialized);
        }

        self.enable_all_hooks_ll(false)?;

        // Free the internal function buffer
        uninitialize_buffer();

        // Clear hooks
        self.hooks.items.clear();
        self.hooks.capacity = 0;
        self.hooks.size = 0;
        self.heap = false;

        Ok(())
    }

    /// Create hook - exact port of MH_CreateHook
    fn create_hook(&mut self, target: *mut c_void, detour: *mut c_void) -> Result<*mut c_void> {
        if !self.heap {
            return Err(HookError::NotInitialized);
        }

        if !is_executable_address(target) || !is_executable_address(detour) {
            return Err(HookError::NotExecutable);
        }

        let pos = self.find_hook_entry(target);
        if pos != INVALID_HOOK_POS {
            return Err(HookError::AlreadyCreated);
        }

        let trampoline = allocate_trampoline(target, detour)?;

        let hook_entry = self.add_hook_entry().ok_or(HookError::MemoryAlloc)?;

        hook_entry.target = target;
        hook_entry.detour = trampoline.relay; // Use relay for x64
        hook_entry.trampoline = trampoline.trampoline;
        hook_entry.patch_above = trampoline.patch_above;
        hook_entry.is_enabled = false;
        hook_entry.queue_enable = false;
        hook_entry.n_ip = trampoline.n_ip;
        hook_entry.old_ips = trampoline.old_ips;
        hook_entry.new_ips = trampoline.new_ips;

        // Back up the target function
        unsafe {
            if trampoline.patch_above {
                ptr::copy_nonoverlapping(
                    (target as *const u8).sub(size_of::<JmpRel>()),
                    hook_entry.backup.as_mut_ptr(),
                    size_of::<JmpRel>() + size_of::<JmpRelShort>(),
                );
            } else {
                ptr::copy_nonoverlapping(
                    target as *const u8,
                    hook_entry.backup.as_mut_ptr(),
                    size_of::<JmpRel>(),
                );
            }
        }

        Ok(hook_entry.trampoline)
    }

    /// Remove hook - exact port of MH_RemoveHook
    fn remove_hook(&mut self, target: *mut c_void) -> Result<()> {
        if !self.heap {
            return Err(HookError::NotInitialized);
        }

        let pos = self.find_hook_entry(target);
        if pos == INVALID_HOOK_POS {
            return Err(HookError::NotCreated);
        }

        if self.hooks.items[pos].is_enabled {
            let mut threads = FrozenThreads::new();
            self.freeze(&mut threads, pos, ACTION_DISABLE)?;
            self.enable_hook_ll(pos, false)?;
            self.unfreeze(&threads);
        }

        let trampoline = self.hooks.items[pos].trampoline;
        free_buffer(trampoline);
        self.delete_hook_entry(pos);

        Ok(())
    }
}

/// Enter spin lock - exact port of EnterSpinLock
fn enter_spin_lock() {
    let mut spin_count = 0;

    // Wait until the flag is FALSE
    while G_IS_LOCKED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        // Prevent the loop from being too busy
        if spin_count < 32 {
            unsafe { Sleep(0) };
        } else {
            unsafe { Sleep(1) };
        }
        spin_count += 1;
    }
}

/// Leave spin lock - exact port of LeaveSpinLock
fn leave_spin_lock() {
    G_IS_LOCKED.store(false, Ordering::SeqCst);
}

/// Mark as thread-safe
unsafe impl Send for HookManager {}
unsafe impl Sync for HookManager {}

/// Special value representing all hooks - exact port of MH_ALL_HOOKS
pub const ALL_HOOKS: *mut c_void = ptr::null_mut();

//=============================================================================
// Public API Functions - exact ports of MinHook C API
//=============================================================================

/// Initialize the MinHook library - exact port of MH_Initialize
pub fn initialize() -> Result<()> {
    enter_spin_lock();
    let result = HOOK_MANAGER
        .lock()
        .map_err(|_| HookError::Unknown)?
        .initialize();
    leave_spin_lock();
    result
}

/// Uninitialize the MinHook library - exact port of MH_Uninitialize
pub fn uninitialize() -> Result<()> {
    enter_spin_lock();
    let result = HOOK_MANAGER
        .lock()
        .map_err(|_| HookError::Unknown)?
        .uninitialize();
    leave_spin_lock();
    result
}

/// Create a hook for the specified target function - exact port of MH_CreateHook
pub fn create_hook(target: *mut c_void, detour: *mut c_void) -> Result<*mut c_void> {
    enter_spin_lock();
    let result = HOOK_MANAGER
        .lock()
        .map_err(|_| HookError::Unknown)?
        .create_hook(target, detour);
    leave_spin_lock();
    result
}

/// Remove an already created hook - exact port of MH_RemoveHook
pub fn remove_hook(target: *mut c_void) -> Result<()> {
    enter_spin_lock();
    let result = HOOK_MANAGER
        .lock()
        .map_err(|_| HookError::Unknown)?
        .remove_hook(target);
    leave_spin_lock();
    result
}

/// Enable an already created hook - exact port of MH_EnableHook
pub fn enable_hook(target: *mut c_void) -> Result<()> {
    enter_spin_lock();
    let result = HOOK_MANAGER
        .lock()
        .map_err(|_| HookError::Unknown)?
        .enable_hook(target, true);
    leave_spin_lock();
    result
}

/// Disable an already created hook - exact port of MH_DisableHook
pub fn disable_hook(target: *mut c_void) -> Result<()> {
    enter_spin_lock();
    let result = HOOK_MANAGER
        .lock()
        .map_err(|_| HookError::Unknown)?
        .enable_hook(target, false);
    leave_spin_lock();
    result
}

/// Queue to enable an already created hook - exact port of MH_QueueEnableHook
pub fn queue_enable_hook(target: *mut c_void) -> Result<()> {
    enter_spin_lock();
    let result = HOOK_MANAGER
        .lock()
        .map_err(|_| HookError::Unknown)?
        .queue_hook(target, true);
    leave_spin_lock();
    result
}

/// Queue to disable an already created hook - exact port of MH_QueueDisableHook
pub fn queue_disable_hook(target: *mut c_void) -> Result<()> {
    enter_spin_lock();
    let result = HOOK_MANAGER
        .lock()
        .map_err(|_| HookError::Unknown)?
        .queue_hook(target, false);
    leave_spin_lock();
    result
}

/// Apply all queued enable/disable operations - exact port of MH_ApplyQueued
pub fn apply_queued() -> Result<()> {
    enter_spin_lock();
    let result = HOOK_MANAGER
        .lock()
        .map_err(|_| HookError::Unknown)?
        .apply_queued();
    leave_spin_lock();
    result
}

/// Create a hook for the specified API function - exact port of MH_CreateHookApiEx
pub fn create_hook_api_ex(
    module_name: &str,
    proc_name: &str,
    detour: *mut c_void,
) -> Result<(*mut c_void, *mut c_void)> {
    let module_wide = string_to_wide(module_name);
    let proc_c_str = string_to_c_string(proc_name);

    let hmodule = unsafe { GetModuleHandleW(module_wide.as_ptr()) };
    if hmodule.is_null() {
        return Err(HookError::ModuleNotFound);
    }

    let target = unsafe { GetProcAddress(hmodule, proc_c_str.as_ptr()) };
    if target.is_none() {
        return Err(HookError::FunctionNotFound);
    }

    let target_ptr = target.unwrap() as *mut c_void;
    let trampoline = create_hook(target_ptr, detour)?;

    Ok((trampoline, target_ptr))
}

/// Create a hook for the specified API function - exact port of MH_CreateHookApi
pub fn create_hook_api(
    module_name: &str,
    proc_name: &str,
    detour: *mut c_void,
) -> Result<(*mut c_void, *mut c_void)> {
    create_hook_api_ex(module_name, proc_name, detour)
}

/// Convert error code to string representation - exact port of MH_StatusToString
pub fn status_to_string(error: HookError) -> &'static str {
    error.as_str()
}

//=============================================================================
// Helper Functions
//=============================================================================

/// Convert Rust string to wide string for Windows API
fn string_to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Convert Rust string to C string for Windows API
fn string_to_c_string(s: &str) -> Vec<u8> {
    s.bytes().chain(std::iter::once(0)).collect()
}

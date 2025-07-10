//! Hook management for MinHook-rs
//!
//! This module provides the main API for creating, enabling, disabling, and managing function hooks.
//! It is a direct port of MinHook's hook.c, maintaining compatibility with the original C implementation.
//!
//! The core logic includes:
//! - Global hook manager with thread-safe access (using Mutex)
//! - Dynamic allocation and management of hook entries
//! - Thread freezing and context adjustment for safe patching
//! - API for creating, removing, enabling, disabling, and queuing hooks
//! - Utility for working with Windows modules and function addresses

use crate::buffer::{free_buffer, initialize_buffer, is_executable_address, uninitialize_buffer};
use crate::error::{HookError, Result};
use crate::instruction::*;
use crate::trampoline::create_trampoline;
use std::ffi::c_void;
use std::ptr;
use std::sync::{Mutex, OnceLock};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("Hook module only supports x86_64 architecture");

/// Initial capacity for the hook entry buffer.
const INITIAL_HOOK_CAPACITY: usize = 32;
/// Initial capacity for the thread ID buffer.
const INITIAL_THREAD_CAPACITY: usize = 128;
/// Special value indicating an invalid hook position.
const INVALID_HOOK_POS: usize = usize::MAX;
/// Special value indicating all hooks.
const ALL_HOOKS_POS: usize = usize::MAX;
/// Action code for disabling hooks.
const ACTION_DISABLE: u32 = 0;
/// Action code for enabling hooks.
const ACTION_ENABLE: u32 = 1;
/// Action code for applying queued hook changes.
const ACTION_APPLY_QUEUED: u32 = 2;
/// Thread access rights for suspending/resuming threads.
const THREAD_ACCESS: u32 =
    THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT;

/// Represents a single hook entry.
#[derive(Debug, Clone)]
struct HookEntry {
    /// Address of the target function.
    target: *mut c_void,
    /// Address of the detour or relay function.
    detour: *mut c_void,
    /// Address of the trampoline function.
    trampoline: *mut c_void,
    /// Backup of the original prologue of the target function.
    backup: [u8; 8],
    /// Whether the hot patch area is used.
    patch_above: bool,
    /// Whether the hook is currently enabled.
    is_enabled: bool,
    /// Whether the hook is queued for enabling/disabling.
    queue_enable: bool,
    /// Number of instruction boundaries.
    n_ip: u32,
    /// Instruction boundaries of the target function.
    old_ips: [u8; 8],
    /// Instruction boundaries of the trampoline function.
    new_ips: [u8; 8],
}

/// Stores thread IDs and allocation info for thread freezing.
struct FrozenThreads {
    items: Vec<u32>,
    capacity: usize,
    size: usize,
}

/// Stores all hook entries and allocation info.
struct HookCollection {
    items: Vec<HookEntry>,
    capacity: usize,
    size: usize,
}

/// Global hook manager, responsible for all hook operations.
struct HookManager {
    /// Indicates if the library is initialized.
    heap: bool,
    /// Collection of all hook entries.
    hooks: HookCollection,
}

/// Global singleton for the hook manager, protected by a Mutex.
static HOOK_MANAGER: OnceLock<Mutex<HookManager>> = OnceLock::new();

impl HookEntry {
    /// Creates a new, empty hook entry.
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
    /// Creates a new, empty frozen threads structure.
    fn new() -> Self {
        Self {
            items: Vec::new(),
            capacity: 0,
            size: 0,
        }
    }
}

impl HookManager {
    /// Creates a new, uninitialized hook manager.
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

    /// Finds the index of a hook entry by target address.
    fn find_hook_entry(&self, target: *mut c_void) -> usize {
        for i in 0..self.hooks.size {
            if std::ptr::eq(target, self.hooks.items[i].target) {
                return i;
            }
        }
        INVALID_HOOK_POS
    }

    /// Adds a new hook entry, growing the buffer if needed.
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

    /// Deletes a hook entry at the given index, shrinking the buffer if needed.
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

    /// Finds the original instruction pointer for a thread, used when disabling a hook.
    fn find_old_ip(&self, hook: &HookEntry, ip: usize) -> usize {
        if hook.patch_above && ip == (hook.target as usize - size_of::<JmpRel>()) {
            return hook.target as usize;
        }
        for i in 0..hook.n_ip as usize {
            if ip == (hook.trampoline as usize + hook.new_ips[i] as usize) {
                return hook.target as usize + hook.old_ips[i] as usize;
            }
        }
        if ip == hook.detour as usize {
            return hook.target as usize;
        }
        0
    }

    /// Finds the new instruction pointer for a thread, used when enabling a hook.
    fn find_new_ip(&self, hook: &HookEntry, ip: usize) -> usize {
        for i in 0..hook.n_ip as usize {
            if ip == (hook.target as usize + hook.old_ips[i] as usize) {
                return hook.trampoline as usize + hook.new_ips[i] as usize;
            }
        }
        0
    }

    /// Adjusts thread instruction pointers if they are suspended in a patched region.
    fn process_thread_ips(&self, thread: HANDLE, pos: usize, action: u32) {
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
                _ => hook.queue_enable,
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

    /// Enumerates all threads in the current process except the current thread.
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
                    if te.dwSize >= 16
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

    /// Suspends all threads (except current), and adjusts their instruction pointers if needed.
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
                        threads.items[i] = 0;
                    }
                }
            }
        }
        Ok(())
    }

    /// Resumes all previously suspended threads.
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

    /// Actually enables or disables a hook at the given index, patching code as needed.
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
            FlushInstructionCache(GetCurrentProcess(), patch_target as *mut c_void, patch_size);
        }
        hook.is_enabled = enable;
        hook.queue_enable = enable;
        Ok(())
    }

    /// Enables or disables all hooks.
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

    /// Public API: enables or disables a specific hook or all hooks.
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

    /// Queues a hook for enabling or disabling.
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

    /// Applies all queued hook enable/disable operations.
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

    /// Initializes the hook manager and internal buffer.
    fn initialize(&mut self) -> Result<()> {
        if self.heap {
            return Err(HookError::AlreadyInitialized);
        }
        initialize_buffer();
        self.heap = true;
        Ok(())
    }

    /// Uninitializes the hook manager and releases all resources.
    fn uninitialize(&mut self) -> Result<()> {
        if !self.heap {
            return Err(HookError::NotInitialized);
        }
        self.enable_all_hooks_ll(false)?;
        uninitialize_buffer();
        self.hooks.items.clear();
        self.hooks.capacity = 0;
        self.hooks.size = 0;
        self.heap = false;
        Ok(())
    }

    /// Creates a new hook for the specified target and detour.
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
        let mut trampoline = Trampoline::new(target, detour, ptr::null_mut());
        create_trampoline(&mut trampoline)?;
        let hook_entry = self.add_hook_entry().ok_or(HookError::MemoryAlloc)?;
        hook_entry.target = target;
        hook_entry.detour = trampoline.relay;
        hook_entry.trampoline = trampoline.trampoline;
        hook_entry.patch_above = trampoline.patch_above;
        hook_entry.is_enabled = false;
        hook_entry.queue_enable = false;
        hook_entry.n_ip = trampoline.n_ip;
        hook_entry.old_ips = trampoline.old_ips;
        hook_entry.new_ips = trampoline.new_ips;
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

    /// Removes a hook for the specified target.
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

unsafe impl Send for HookManager {}
unsafe impl Sync for HookManager {}

/// Special value for targeting all hooks.
pub const ALL_HOOKS: *mut c_void = ptr::null_mut();

/// Returns a reference to the global hook manager.
fn get_manager() -> &'static Mutex<HookManager> {
    HOOK_MANAGER.get_or_init(|| Mutex::new(HookManager::new()))
}

/// Initializes the MinHook library.
pub fn initialize() -> Result<()> {
    get_manager()
        .lock()
        .map_err(|_| HookError::Unknown)?
        .initialize()
}

/// Uninitializes the MinHook library and releases all resources.
pub fn uninitialize() -> Result<()> {
    get_manager()
        .lock()
        .map_err(|_| HookError::Unknown)?
        .uninitialize()
}

/// Creates a hook for the specified target and detour.
pub fn create_hook(target: *mut c_void, detour: *mut c_void) -> Result<*mut c_void> {
    get_manager()
        .lock()
        .map_err(|_| HookError::Unknown)?
        .create_hook(target, detour)
}

/// Removes a hook for the specified target.
pub fn remove_hook(target: *mut c_void) -> Result<()> {
    get_manager()
        .lock()
        .map_err(|_| HookError::Unknown)?
        .remove_hook(target)
}

/// Enables a hook for the specified target.
pub fn enable_hook(target: *mut c_void) -> Result<()> {
    get_manager()
        .lock()
        .map_err(|_| HookError::Unknown)?
        .enable_hook(target, true)
}

/// Disables a hook for the specified target.
pub fn disable_hook(target: *mut c_void) -> Result<()> {
    get_manager()
        .lock()
        .map_err(|_| HookError::Unknown)?
        .enable_hook(target, false)
}

/// Queues a hook to be enabled for the specified target.
pub fn queue_enable_hook(target: *mut c_void) -> Result<()> {
    get_manager()
        .lock()
        .map_err(|_| HookError::Unknown)?
        .queue_hook(target, true)
}

/// Queues a hook to be disabled for the specified target.
pub fn queue_disable_hook(target: *mut c_void) -> Result<()> {
    get_manager()
        .lock()
        .map_err(|_| HookError::Unknown)?
        .queue_hook(target, false)
}

/// Applies all queued hook enable/disable operations.
pub fn apply_queued() -> Result<()> {
    get_manager()
        .lock()
        .map_err(|_| HookError::Unknown)?
        .apply_queued()
}

/// Creates a hook for a function in a specific module by name, returning the trampoline and target.
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

/// Creates a hook for a function in a specific module by name.
pub fn create_hook_api(
    module_name: &str,
    proc_name: &str,
    detour: *mut c_void,
) -> Result<(*mut c_void, *mut c_void)> {
    create_hook_api_ex(module_name, proc_name, detour)
}

/// Converts a HookError to a static string.
pub fn status_to_string(error: HookError) -> &'static str {
    error.as_str()
}

/// Converts a Rust string to a wide (UTF-16) null-terminated string for Windows APIs.
fn string_to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Converts a Rust string to a C-style null-terminated string for Windows APIs.
fn string_to_c_string(s: &str) -> Vec<u8> {
    s.bytes().chain(std::iter::once(0)).collect()
}

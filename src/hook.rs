//! Hook management for MinHook-rs
//!
//! This module provides the main API for creating, enabling, and managing function hooks.
//! It corresponds to the original MinHook's hook.c functionality.

use crate::buffer::{free_buffer, initialize_buffer, is_executable_address, uninitialize_buffer};
use crate::error::{HookError, Result};
use crate::instruction::*;
use crate::trampoline::allocate_trampoline;
use std::ffi::c_void;
use std::ptr;
use std::sync::Mutex;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("Hook module only supports x86_64 architecture");

/// Initial capacity of the hook entries buffer
const INITIAL_HOOK_CAPACITY: usize = 32;

/// Initial capacity of the thread IDs buffer
const INITIAL_THREAD_CAPACITY: usize = 128;

/// Special hook position values
const ALL_HOOKS_POS: usize = usize::MAX;

/// Thread access rights for suspending/resuming threads
const THREAD_ACCESS: u32 =
    THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT;

/// Freeze action types
#[derive(Debug, Clone, Copy, PartialEq)]
enum FreezeAction {
    Disable = 0,
    Enable = 1,
    ApplyQueued = 2,
}

/// Hook entry information
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
    /// Hook is enabled
    is_enabled: bool,
    /// Queued for enabling/disabling when != is_enabled
    queue_enable: bool,

    /// Count of the instruction boundaries
    n_ip: u8,
    /// Instruction boundaries of the target function
    old_ips: [u8; 8],
    /// Instruction boundaries of the trampoline function
    new_ips: [u8; 8],
}

/// Suspended threads for freeze/unfreeze operations
struct FrozenThreads {
    /// Thread IDs
    thread_ids: Vec<u32>,
    /// Thread handles for resuming
    thread_handles: Vec<HANDLE>,
}

/// Global hook manager
struct HookManager {
    /// Hook entries
    hooks: Vec<HookEntry>,
    /// Is the manager initialized?
    initialized: bool,
}

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
            thread_ids: Vec::with_capacity(INITIAL_THREAD_CAPACITY),
            thread_handles: Vec::with_capacity(INITIAL_THREAD_CAPACITY),
        }
    }
}

impl HookManager {
    const fn new() -> Self {
        Self {
            hooks: Vec::new(),
            initialized: false,
        }
    }

    /// Initialize the hook manager
    fn initialize(&mut self) -> Result<()> {
        if self.initialized {
            return Err(HookError::AlreadyInitialized);
        }

        // Initialize the internal function buffer
        initialize_buffer();

        // Initialize hook entries with initial capacity
        self.hooks = Vec::with_capacity(INITIAL_HOOK_CAPACITY);
        self.initialized = true;

        Ok(())
    }

    /// Uninitialize the hook manager
    fn uninitialize(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(HookError::NotInitialized);
        }

        // Disable all hooks first
        self.enable_all_hooks_ll(false)?;

        // Free all trampoline buffers
        for hook in &self.hooks {
            if !hook.trampoline.is_null() {
                free_buffer(hook.trampoline);
            }
        }

        // Clear hooks and reset state
        self.hooks.clear();
        self.initialized = false;

        // Uninitialize the buffer system
        uninitialize_buffer();

        Ok(())
    }

    /// Find hook entry by target address
    fn find_hook_entry(&self, target: *mut c_void) -> Option<usize> {
        self.hooks.iter().position(|entry| entry.target == target)
    }

    /// Add a new hook entry
    fn add_hook_entry(&mut self) -> Result<&mut HookEntry> {
        if !self.initialized {
            return Err(HookError::NotInitialized);
        }

        self.hooks.push(HookEntry::new());
        Ok(self.hooks.last_mut().unwrap())
    }

    /// Delete hook entry at position
    fn delete_hook_entry(&mut self, pos: usize) -> Result<()> {
        if pos >= self.hooks.len() {
            return Err(HookError::NotCreated);
        }

        self.hooks.remove(pos);
        Ok(())
    }

    /// Create a new hook
    fn create_hook(&mut self, target: *mut c_void, detour: *mut c_void) -> Result<*mut c_void> {
        if !self.initialized {
            return Err(HookError::NotInitialized);
        }

        // Check if target and detour are executable
        if !is_executable_address(target) || !is_executable_address(detour) {
            return Err(HookError::NotExecutable);
        }

        // Check if hook already exists
        if self.find_hook_entry(target).is_some() {
            return Err(HookError::AlreadyCreated);
        }

        // Allocate trampoline buffer near the target
        let trampoline = allocate_trampoline(target, detour)?;

        // Add hook entry
        let hook_entry = self.add_hook_entry()?;

        // Fill hook entry information
        hook_entry.target = target;
        hook_entry.detour = trampoline.relay; // Use relay for x64
        hook_entry.trampoline = trampoline.trampoline;
        hook_entry.patch_above = trampoline.patch_above;
        hook_entry.is_enabled = false;
        hook_entry.queue_enable = false;
        hook_entry.n_ip = trampoline.n_ip as u8;
        hook_entry.old_ips = trampoline.old_ips;
        hook_entry.new_ips = trampoline.new_ips;

        // Back up the target function
        unsafe {
            if trampoline.patch_above {
                ptr::copy_nonoverlapping(
                    (target as *const u8).sub(5),
                    hook_entry.backup.as_mut_ptr(),
                    7, // JMP_REL + JMP_REL_SHORT
                );
            } else {
                ptr::copy_nonoverlapping(
                    target as *const u8,
                    hook_entry.backup.as_mut_ptr(),
                    5, // JMP_REL
                );
            }
        }

        Ok(trampoline.trampoline)
    }

    /// Remove an existing hook
    fn remove_hook(&mut self, target: *mut c_void) -> Result<()> {
        if !self.initialized {
            return Err(HookError::NotInitialized);
        }

        let pos = self.find_hook_entry(target).ok_or(HookError::NotCreated)?;

        // Store hook info for cleanup (avoiding borrow conflict)
        let is_enabled = self.hooks[pos].is_enabled;
        let trampoline = self.hooks[pos].trampoline;

        // Disable hook if enabled
        if is_enabled {
            let frozen_threads = self.freeze_threads(pos, FreezeAction::Disable)?;
            self.enable_hook_ll(pos, false)?;
            self.unfreeze_threads(frozen_threads)?;
        }

        // Free trampoline buffer
        if !trampoline.is_null() {
            free_buffer(trampoline);
        }

        // Remove hook entry
        self.delete_hook_entry(pos)?;

        Ok(())
    }

    /// Enable/disable all hooks at low level
    fn enable_all_hooks_ll(&mut self, enable: bool) -> Result<()> {
        // Find first hook that needs to be changed
        let first_pos = self.hooks.iter().position(|hook| hook.is_enabled != enable);

        if let Some(first) = first_pos {
            // Freeze threads for all hooks
            let frozen_threads = self.freeze_threads(
                ALL_HOOKS_POS,
                if enable {
                    FreezeAction::Enable
                } else {
                    FreezeAction::Disable
                },
            )?;

            // Enable/disable hooks starting from first
            for i in first..self.hooks.len() {
                if self.hooks[i].is_enabled != enable {
                    self.enable_hook_ll(i, enable)?;
                }
            }

            // Unfreeze threads
            self.unfreeze_threads(frozen_threads)?;
        }

        Ok(())
    }

    /// Enable hook at low level (without thread management)
    fn enable_hook_ll(&mut self, pos: usize, enable: bool) -> Result<()> {
        if pos >= self.hooks.len() {
            return Err(HookError::NotCreated);
        }

        let hook = &mut self.hooks[pos];
        let patch_size = if hook.patch_above { 7 } else { 5 }; // JMP_REL + JMP_REL_SHORT or just JMP_REL
        let patch_target = if hook.patch_above {
            unsafe { (hook.target as *mut u8).sub(5) }
        } else {
            hook.target as *mut u8
        };

        // Change memory protection
        let mut old_protect = 0u32;
        let protect_result = unsafe {
            VirtualProtect(
                patch_target as *mut c_void,
                patch_size,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            )
        };

        if protect_result == 0 {
            return Err(HookError::MemoryProtect);
        }

        unsafe {
            if enable {
                // Write hook jump
                let jmp_rel =
                    JmpRel::new_jmp((hook.detour as isize - (patch_target as isize + 5)) as i32);

                ptr::copy_nonoverlapping(&jmp_rel as *const JmpRel as *const u8, patch_target, 5);

                if hook.patch_above {
                    // Write short jump at original location
                    let short_jmp = JmpRelShort::new(-(5 + 2) as i8);
                    ptr::copy_nonoverlapping(
                        &short_jmp as *const JmpRelShort as *const u8,
                        hook.target as *mut u8,
                        2,
                    );
                }
            } else {
                // Restore original bytes
                ptr::copy_nonoverlapping(hook.backup.as_ptr(), patch_target, patch_size);
            }
        }

        // Restore memory protection
        unsafe {
            VirtualProtect(
                patch_target as *mut c_void,
                patch_size,
                old_protect,
                &mut old_protect,
            );

            // Flush instruction cache
            FlushInstructionCache(GetCurrentProcess(), patch_target as *mut c_void, patch_size);
        }

        hook.is_enabled = enable;
        hook.queue_enable = enable;

        Ok(())
    }

    /// Enumerate all threads in current process
    fn enumerate_threads(&self, frozen_threads: &mut FrozenThreads) -> Result<()> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(HookError::Unknown);
            }

            let mut te = THREADENTRY32 {
                dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
                cntUsage: 0,
                th32ThreadID: 0,
                th32OwnerProcessID: 0,
                tpBasePri: 0,
                tpDeltaPri: 0,
                dwFlags: 0,
            };

            if Thread32First(snapshot, &mut te) != 0 {
                loop {
                    // Check if this thread belongs to current process and is not current thread
                    if te.th32OwnerProcessID == GetCurrentProcessId()
                        && te.th32ThreadID != GetCurrentThreadId()
                    {
                        frozen_threads.thread_ids.push(te.th32ThreadID);
                    }

                    te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                    if Thread32Next(snapshot, &mut te) == 0 {
                        break;
                    }
                }
            }

            CloseHandle(snapshot);
        }

        Ok(())
    }

    /// Freeze threads for safe hook operations
    fn freeze_threads(&self, pos: usize, action: FreezeAction) -> Result<FrozenThreads> {
        let mut frozen_threads = FrozenThreads::new();

        // Enumerate all threads
        self.enumerate_threads(&mut frozen_threads)?;

        // Suspend threads and process their IPs
        for &thread_id in &frozen_threads.thread_ids {
            unsafe {
                let thread_handle = OpenThread(THREAD_ACCESS, FALSE, thread_id);
                if !thread_handle.is_null() {
                    let suspend_result = SuspendThread(thread_handle);
                    if suspend_result != u32::MAX {
                        // Process thread IP if suspension successful
                        let _ = self.process_thread_ips(thread_handle, pos, action);
                        frozen_threads.thread_handles.push(thread_handle);
                    } else {
                        // Failed to suspend, close handle
                        CloseHandle(thread_handle);
                    }
                } else {
                    // Mark as not suspended by pushing null handle
                    frozen_threads.thread_handles.push(ptr::null_mut());
                }
            }
        }

        Ok(frozen_threads)
    }

    /// Unfreeze previously frozen threads
    fn unfreeze_threads(&self, frozen_threads: FrozenThreads) -> Result<()> {
        unsafe {
            for handle in frozen_threads.thread_handles {
                if !handle.is_null() {
                    ResumeThread(handle);
                    CloseHandle(handle);
                }
            }
        }

        Ok(())
    }

    /// Process thread IPs during freeze/unfreeze
    fn process_thread_ips(
        &self,
        thread_handle: HANDLE,
        pos: usize,
        action: FreezeAction,
    ) -> Result<()> {
        unsafe {
            let mut context = CONTEXT {
                ContextFlags: CONTEXT_CONTROL_AMD64,
                ..std::mem::zeroed()
            };

            if GetThreadContext(thread_handle, &mut context) == 0 {
                return Ok(()); // Not critical, just return
            }

            let count = if pos == ALL_HOOKS_POS {
                self.hooks.len()
            } else {
                pos + 1
            };
            let start_pos = if pos == ALL_HOOKS_POS { 0 } else { pos };

            for i in start_pos..count {
                let hook = &self.hooks[i];
                let enable = match action {
                    FreezeAction::Disable => false,
                    FreezeAction::Enable => true,
                    FreezeAction::ApplyQueued => hook.queue_enable,
                };

                if hook.is_enabled == enable {
                    continue;
                }

                let new_ip = if enable {
                    self.find_new_ip(hook, context.Rip as usize)
                } else {
                    self.find_old_ip(hook, context.Rip as usize)
                };

                if let Some(ip) = new_ip {
                    context.Rip = ip as u64;
                    SetThreadContext(thread_handle, &context);
                }
            }
        }

        Ok(())
    }

    /// Find old IP from new IP for thread context fixing
    #[allow(dead_code)]
    fn find_old_ip(&self, hook_entry: &HookEntry, ip: usize) -> Option<usize> {
        // Check if IP is in patch above area
        if hook_entry.patch_above && ip == hook_entry.target as usize - 5 {
            return Some(hook_entry.target as usize);
        }

        // Check instruction boundaries
        for i in 0..hook_entry.n_ip as usize {
            if ip == hook_entry.trampoline as usize + hook_entry.new_ips[i] as usize {
                return Some(hook_entry.target as usize + hook_entry.old_ips[i] as usize);
            }
        }

        // Check relay function
        if ip == hook_entry.detour as usize {
            return Some(hook_entry.target as usize);
        }

        None
    }

    /// Find new IP from old IP for thread context fixing
    #[allow(dead_code)]
    fn find_new_ip(&self, hook_entry: &HookEntry, ip: usize) -> Option<usize> {
        for i in 0..hook_entry.n_ip as usize {
            if ip == hook_entry.target as usize + hook_entry.old_ips[i] as usize {
                return Some(hook_entry.trampoline as usize + hook_entry.new_ips[i] as usize);
            }
        }

        None
    }

    /// Enable/disable a hook
    fn enable_hook(&mut self, target: *mut c_void, enable: bool) -> Result<()> {
        if !self.initialized {
            return Err(HookError::NotInitialized);
        }

        if target == ALL_HOOKS {
            self.enable_all_hooks_ll(enable)
        } else {
            let pos = self.find_hook_entry(target).ok_or(HookError::NotCreated)?;

            if self.hooks[pos].is_enabled == enable {
                return Err(if enable {
                    HookError::Enabled
                } else {
                    HookError::Disabled
                });
            }

            let frozen_threads = self.freeze_threads(
                pos,
                if enable {
                    FreezeAction::Enable
                } else {
                    FreezeAction::Disable
                },
            )?;

            self.enable_hook_ll(pos, enable)?;
            self.unfreeze_threads(frozen_threads)?;

            Ok(())
        }
    }

    /// Queue a hook for enable/disable
    fn queue_hook(&mut self, target: *mut c_void, queue_enable: bool) -> Result<()> {
        if !self.initialized {
            return Err(HookError::NotInitialized);
        }

        if target == ALL_HOOKS {
            for hook in &mut self.hooks {
                hook.queue_enable = queue_enable;
            }
        } else {
            let pos = self.find_hook_entry(target).ok_or(HookError::NotCreated)?;
            self.hooks[pos].queue_enable = queue_enable;
        }

        Ok(())
    }

    /// Apply all queued hook operations
    fn apply_queued(&mut self) -> Result<()> {
        if !self.initialized {
            return Err(HookError::NotInitialized);
        }

        // Find first hook that needs to be changed
        let first_pos = self
            .hooks
            .iter()
            .position(|hook| hook.is_enabled != hook.queue_enable);

        if let Some(first) = first_pos {
            // Freeze threads for all hooks
            let frozen_threads = self.freeze_threads(ALL_HOOKS_POS, FreezeAction::ApplyQueued)?;

            // Apply queued operations starting from first
            for i in first..self.hooks.len() {
                if self.hooks[i].is_enabled != self.hooks[i].queue_enable {
                    self.enable_hook_ll(i, self.hooks[i].queue_enable)?;
                }
            }

            // Unfreeze threads
            self.unfreeze_threads(frozen_threads)?;
        }

        Ok(())
    }
}

// Mark the manager as thread-safe
unsafe impl Send for HookManager {}
unsafe impl Sync for HookManager {}

/// Global hook manager instance
static HOOK_MANAGER: Mutex<HookManager> = Mutex::new(HookManager::new());

/// Special value representing all hooks
pub const ALL_HOOKS: *mut c_void = ptr::null_mut();

//=============================================================================
// Public API Functions
//=============================================================================

/// Initialize the MinHook library
///
/// You must call this function EXACTLY ONCE at the beginning of your program.
pub fn initialize() -> Result<()> {
    HOOK_MANAGER
        .lock()
        .map_err(|_| HookError::Unknown)?
        .initialize()
}

/// Uninitialize the MinHook library
///
/// You must call this function EXACTLY ONCE at the end of your program.
pub fn uninitialize() -> Result<()> {
    HOOK_MANAGER
        .lock()
        .map_err(|_| HookError::Unknown)?
        .uninitialize()
}

/// Create a hook for the specified target function
///
/// # Arguments
/// * `target` - A pointer to the target function
/// * `detour` - A pointer to the detour function
///
/// # Returns
/// * `Ok(trampoline)` - Pointer to the trampoline function on success
/// * `Err(error)` - Error code on failure
pub fn create_hook(target: *mut c_void, detour: *mut c_void) -> Result<*mut c_void> {
    HOOK_MANAGER
        .lock()
        .map_err(|_| HookError::Unknown)?
        .create_hook(target, detour)
}

/// Remove an already created hook
///
/// # Arguments
/// * `target` - A pointer to the target function
pub fn remove_hook(target: *mut c_void) -> Result<()> {
    HOOK_MANAGER
        .lock()
        .map_err(|_| HookError::Unknown)?
        .remove_hook(target)
}

/// Enable an already created hook
///
/// # Arguments
/// * `target` - A pointer to the target function, or `ALL_HOOKS` to enable all hooks
pub fn enable_hook(target: *mut c_void) -> Result<()> {
    HOOK_MANAGER
        .lock()
        .map_err(|_| HookError::Unknown)?
        .enable_hook(target, true)
}

/// Disable an already created hook
///
/// # Arguments
/// * `target` - A pointer to the target function, or `ALL_HOOKS` to disable all hooks
pub fn disable_hook(target: *mut c_void) -> Result<()> {
    HOOK_MANAGER
        .lock()
        .map_err(|_| HookError::Unknown)?
        .enable_hook(target, false)
}

/// Queue to enable an already created hook
///
/// # Arguments
/// * `target` - A pointer to the target function, or `ALL_HOOKS` to queue all hooks
pub fn queue_enable_hook(target: *mut c_void) -> Result<()> {
    HOOK_MANAGER
        .lock()
        .map_err(|_| HookError::Unknown)?
        .queue_hook(target, true)
}

/// Queue to disable an already created hook
///
/// # Arguments
/// * `target` - A pointer to the target function, or `ALL_HOOKS` to queue all hooks
pub fn queue_disable_hook(target: *mut c_void) -> Result<()> {
    HOOK_MANAGER
        .lock()
        .map_err(|_| HookError::Unknown)?
        .queue_hook(target, false)
}

/// Apply all queued enable/disable operations
pub fn apply_queued() -> Result<()> {
    HOOK_MANAGER
        .lock()
        .map_err(|_| HookError::Unknown)?
        .apply_queued()
}

/// Create a hook for the specified API function by module and function name
///
/// # Arguments
/// * `module_name` - The name of the module (e.g., "user32", "kernel32")
/// * `proc_name` - The name of the function to hook
/// * `detour` - A pointer to the detour function
///
/// # Returns
/// * `Ok((trampoline, target))` - Pointers to the trampoline and target functions on success
/// * `Err(error)` - Error code on failure
pub fn create_hook_api(
    module_name: &str,
    proc_name: &str,
    detour: *mut c_void,
) -> Result<(*mut c_void, *mut c_void)> {
    // Convert strings for Windows API
    let module_wide = string_to_wide(module_name);
    let proc_c_str = string_to_c_string(proc_name);

    // Get module handle
    let hmodule = unsafe { GetModuleHandleW(module_wide.as_ptr()) };

    if hmodule.is_null() {
        return Err(HookError::ModuleNotFound);
    }

    // Get function address
    let target = unsafe { GetProcAddress(hmodule, proc_c_str.as_ptr()) };

    if target.is_none() {
        return Err(HookError::FunctionNotFound);
    }

    let target_ptr = target.unwrap() as *mut c_void;

    // Create hook
    let trampoline = create_hook(target_ptr, detour)?;

    Ok((trampoline, target_ptr))
}

/// Create a hook for the specified API function by module and function name (extended version)
///
/// # Arguments
/// * `module_name` - The name of the module (e.g., "user32", "kernel32")
/// * `proc_name` - The name of the function to hook
/// * `detour` - A pointer to the detour function
///
/// # Returns
/// * `Ok((trampoline, target))` - Pointers to the trampoline and target functions on success
/// * `Err(error)` - Error code on failure
pub fn create_hook_api_ex(
    module_name: &str,
    proc_name: &str,
    detour: *mut c_void,
) -> Result<(*mut c_void, *mut c_void)> {
    // For now, just use the same implementation as create_hook_api
    create_hook_api(module_name, proc_name, detour)
}

/// Convert error code to string representation
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

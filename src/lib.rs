//! # MinHook-rs
//!
//! A Rust implementation of MinHook library for Windows x64 function hooking.
//! 
//! This library provides a simple, thread-safe API for intercepting Win32 functions
//! with precise instruction decoding and minimal overhead.
//!
//! ## Features
//!
//! - **Precise instruction decoder** - Custom x64 disassembler optimized for hook creation
//! - **Thread-safe operations** - All APIs are thread-safe with proper synchronization
//! - **Memory efficient** - Optimized data structures with minimal memory footprint
//! - **Comprehensive error handling** - Detailed error reporting for all edge cases
//! - **Production ready** - Extensively tested with multiple hook scenarios
//! - **Zero-copy design** - Efficient instruction processing without unnecessary allocations
//!
//! ## Basic Usage
//!
//! The typical workflow involves initialization, hook creation, activation, and cleanup:
//!
//! ```rust,no_run
//! use min_hook_rs::*;
//! use std::ffi::c_void;
//! use std::ptr;
//! use windows_sys::Win32::UI::WindowsAndMessaging::*;
//!
//! // Define function signature
//! type MessageBoxAFn = unsafe extern "system" fn(HWND, PCSTR, PCSTR, u32) -> i32;
//! static mut ORIGINAL_MESSAGEBOX: Option<MessageBoxAFn> = None;
//!
//! // Hook function
//! unsafe extern "system" fn hooked_messagebox(
//!     hwnd: HWND, _text: PCSTR, _caption: PCSTR, utype: u32
//! ) -> i32 {
//!     let new_text = "Hooked by MinHook-rs!\0";
//!     let new_caption = "Hook Demo\0";
//!     
//!     // Call original function safely
//!     let original = ptr::addr_of!(ORIGINAL_MESSAGEBOX).read().unwrap();
//!     original(hwnd, new_text.as_ptr(), new_caption.as_ptr(), utype)
//! }
//!
//! fn main() -> Result<()> {
//!     // Initialize the hooking system
//!     initialize()?;
//!
//!     // Create hook by API name
//!     let (trampoline, target) = create_hook_api(
//!         "user32", 
//!         "MessageBoxA", 
//!         hooked_messagebox as *mut c_void
//!     )?;
//!
//!     // Store original function for later use
//!     unsafe {
//!         ORIGINAL_MESSAGEBOX = Some(std::mem::transmute(trampoline));
//!     }
//!
//!     // Activate the hook
//!     enable_hook(target)?;
//!
//!     // Test the hook
//!     unsafe {
//!         MessageBoxA(ptr::null_mut(), "Test\0".as_ptr(), "Title\0".as_ptr(), MB_OK);
//!     }
//!
//!     // Cleanup
//!     disable_hook(target)?;
//!     remove_hook(target)?;
//!     uninitialize()?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Hook by Function Address
//!
//! You can also hook functions by their memory address:
//!
//! ```rust,no_run
//! # use min_hook_rs::*;
//! # use std::ffi::c_void;
//! # unsafe fn my_hook() {}
//! # fn main() -> Result<()> {
//! // Get function address (example)
//! let target_address = 0x12345678 as *mut c_void;
//!
//! // Create hook by address
//! let (trampoline, target) = create_hook(target_address, my_hook as *mut c_void)?;
//!
//! // Enable the hook
//! enable_hook(target)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Multiple Hook Management
//!
//! MinHook-rs supports managing multiple hooks simultaneously:
//!
//! ```rust,no_run
//! # use min_hook_rs::*;
//! # use std::ffi::c_void;
//! # unsafe fn hook1() {}
//! # unsafe fn hook2() {}
//! # fn main() -> Result<()> {
//! // Create multiple hooks
//! let (_, target1) = create_hook_api("user32", "MessageBoxA", hook1 as *mut c_void)?;
//! let (_, target2) = create_hook_api("kernel32", "GetTickCount", hook2 as *mut c_void)?;
//!
//! // Enable all hooks at once
//! enable_hook(ALL_HOOKS)?;
//!
//! // Your code here...
//!
//! // Disable all hooks at once
//! disable_hook(ALL_HOOKS)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Queued Operations
//!
//! For atomic operations on multiple hooks, use queued operations:
//!
//! ```rust,no_run
//! # use min_hook_rs::*;
//! # use std::ffi::c_void;
//! # fn main() -> Result<()> {
//! # let target = std::ptr::null_mut();
//! // Queue multiple operations
//! queue_enable_hook(target)?;
//! queue_disable_hook(target)?;
//! queue_enable_hook(target)?;
//!
//! // Apply all operations atomically
//! apply_queued()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Error Handling
//!
//! MinHook-rs provides comprehensive error handling for all edge cases:
//!
//! ```rust,no_run
//! # use min_hook_rs::*;
//! # use std::ffi::c_void;
//! # unsafe fn hook_fn() {}
//! match create_hook_api("user32", "MessageBoxA", hook_fn as *mut c_void) {
//!     Ok((trampoline, target)) => {
//!         println!("Hook created at {:p}", target);
//!     },
//!     Err(HookError::ModuleNotFound) => {
//!         println!("Module not loaded");
//!     },
//!     Err(HookError::FunctionNotFound) => {
//!         println!("Function not exported");
//!     },
//!     Err(HookError::AlreadyCreated) => {
//!         println!("Hook already exists");
//!     },
//!     Err(e) => {
//!         println!("Other error: {}", status_to_string(&e));
//!     }
//! }
//! ```
//!
//! ## Advanced Usage
//!
//! ### Custom Hook Detection
//!
//! ```rust,no_run
//! # use min_hook_rs::*;
//! # fn main() -> Result<()> {
//! // Check if a code region can be safely hooked
//! let code_bytes = &[0x48, 0x83, 0xEC, 0x28]; // SUB RSP, 28h
//! if can_hook_safely(code_bytes, 5) {
//!     println!("Safe to install 5-byte hook");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### Instruction Analysis
//!
//! ```rust,no_run
//! # use min_hook_rs::*;
//! let code_bytes = &[0x48, 0x8B, 0x05, 0x12, 0x34, 0x56, 0x78]; // MOV RAX, [RIP+12345678h]
//! let inst = decode_instruction(code_bytes);
//!
//! println!("Instruction length: {}", inst.len);
//! println!("Is RIP-relative: {}", inst.is_rip_relative());
//! println!("Displacement: 0x{:08X}", inst.displacement);
//! ```
//!
//! ## Hook Function Guidelines
//!
//! When writing hook functions, follow these guidelines:
//!
//! 1. **Match signatures exactly**: Hook functions must have the same calling convention and signature as the target
//! 2. **Store originals safely**: Use `ptr::addr_of!` for thread-safe access to original function pointers
//! 3. **Handle errors gracefully**: Always check for null pointers and handle edge cases
//! 4. **Minimize hook overhead**: Keep hook functions lightweight to avoid performance impact
//!
//! ## Safety Considerations
//!
//! This library uses unsafe operations for low-level memory manipulation.
//! Users must ensure:
//!
//! - Hook functions have the exact same signature as target functions
//! - Target functions are valid and executable
//! - Proper initialization and cleanup order
//! - Thread-safe access to shared hook state
//!
//! ## Platform Requirements
//!
//! - **Architecture**: x86_64 only
//! - **Operating System**: Windows only
//! - **Minimum Rust Version**: 1.85.0

#[cfg(not(target_arch = "x86_64"))]
compile_error!("This crate only supports x86_64 architecture");

#[cfg(not(target_os = "windows"))]
compile_error!("This crate only supports Windows");

pub mod buffer;
pub mod disasm;
pub mod error;
pub mod hook;
pub mod instruction;
pub mod trampoline;

// Re-export main API
pub use error::{HookError, Result};
pub use hook::{
    ALL_HOOKS, apply_queued, create_hook, create_hook_api, create_hook_api_ex, disable_hook,
    enable_hook, initialize, queue_disable_hook, queue_enable_hook, remove_hook, status_to_string,
    uninitialize,
};

// Re-export for advanced usage
pub use disasm::{decode_instruction, can_hook_safely, HookInstruction};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Check if the current platform is supported
///
/// Returns `true` if running on x86_64 Windows, `false` otherwise.
///
/// # Example
///
/// ```rust
/// # use min_hook_rs::is_supported;
/// if !is_supported() {
///     eprintln!("MinHook-rs only supports x86_64 Windows");
///     return;
/// }
/// ```
pub fn is_supported() -> bool {
    cfg!(target_arch = "x86_64") && cfg!(target_os = "windows")
}

/// Get library version string
///
/// Returns the current version of MinHook-rs.
///
/// # Example
///
/// ```rust
/// # use min_hook_rs::get_version;
/// println!("MinHook-rs version: {}", get_version());
/// ```
pub fn get_version() -> &'static str {
    VERSION
}
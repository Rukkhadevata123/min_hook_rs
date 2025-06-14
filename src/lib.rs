//! MinHook-rs: A Rust port of the MinHook API hooking library
//!
//! MinHook-rs is a minimalistic API hooking library for Windows x64.
//! It provides a simple and easy-to-use API for intercepting Win32 functions.
//!
//! # Features
//!
//! - **Simple**: Extremely simple to use. Just call a few APIs.
//! - **Thread-safe**: All APIs are thread-safe and can be called from multiple threads.
//! - **Memory efficient**: Uses minimal memory footprint.
//! - **x64 support**: Full support for 64-bit Windows applications.
//!
//! # Example
//!
//! ```rust,no_run
//! use min_hook_rs::*;
//! use std::ffi::c_void;
//!
//! // Original function type
//! type MessageBoxW = unsafe extern "system" fn(
//!     hwnd: *mut c_void,
//!     text: *const u16,
//!     caption: *const u16,
//!     utype: u32,
//! ) -> i32;
//!
//! // Our detour function
//! static mut ORIGINAL_MESSAGEBOX: Option<MessageBoxW> = None;
//!
//! unsafe extern "system" fn detour_messagebox(
//!     hwnd: *mut c_void,
//!     text: *const u16,
//!     caption: *const u16,
//!     utype: u32,
//! ) -> i32 {
//!     // Call original function
//!     if let Some(original) = ORIGINAL_MESSAGEBOX {
//!         original(hwnd, text, caption, utype)
//!     } else {
//!         0
//!     }
//! }
//!
//! fn main() -> Result<(), HookError> {
//!     // Initialize MinHook
//!     initialize()?;
//!
//!     // Create hook for MessageBoxW
//!     let (trampoline, target) = create_hook_api(
//!         "user32",
//!         "MessageBoxW",
//!         detour_messagebox as *mut c_void,
//!     )?;
//!
//!     // Store the trampoline (original function)
//!     unsafe {
//!         ORIGINAL_MESSAGEBOX = Some(std::mem::transmute(trampoline));
//!     }
//!
//!     // Enable the hook
//!     enable_hook(target)?;
//!
//!     // Your application code here...
//!
//!     // Clean up
//!     disable_hook(target)?;
//!     remove_hook(target)?;
//!     uninitialize()?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Safety
//!
//! This library uses unsafe operations extensively for low-level memory manipulation
//! and code patching. Users must ensure:
//!
//! - Target functions are valid and executable
//! - Detour functions have the same calling convention and signature
//! - Proper initialization and cleanup
//! - Thread safety when using hooks from multiple threads

pub mod buffer;
pub mod disasm;
pub mod error;
pub mod hook;
pub mod instruction;
pub mod trampoline;

// Re-export the main API
pub use error::{HookError, Result};
pub use hook::{
    ALL_HOOKS, apply_queued, create_hook, create_hook_api, create_hook_api_ex, disable_hook,
    enable_hook, initialize, queue_disable_hook, queue_enable_hook, remove_hook, status_to_string,
    uninitialize,
};

/// Library version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Check if the current platform is supported
pub fn is_supported() -> bool {
    cfg!(target_arch = "x86_64") && cfg!(target_os = "windows")
}

/// Get library information
pub fn get_version() -> &'static str {
    VERSION
}

//! # MinHook-rs
//!
//! A Rust implementation of MinHook library for Windows x64 function hooking.
//!
//! ## Documentation
//!
//! For complete documentation, examples, and technical details, see the [README.md](https://github.com/Rukkhadevata123/min_hook_rs/blob/main/README.md).
//!
//! ## Quick Example
//!
//! ```rust,no_run
//! use min_hook_rs::*;
//! use std::ffi::c_void;
//!
//! unsafe extern "system" fn my_hook() -> i32 { 42 }
//!
//! fn main() -> Result<()> {
//!     initialize()?;
//!     let trampoline = create_hook(0x12345678 as *mut c_void, my_hook as *mut c_void)?;
//!     enable_hook(0x12345678 as *mut c_void)?;
//!     // Function is now hooked
//!     Ok(())
//! }
//! ```

#[cfg(not(target_arch = "x86_64"))]
compile_error!("This crate only supports x86_64 architecture");

#[cfg(not(target_os = "windows"))]
compile_error!("This crate only supports Windows");

// Core modules
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
pub use buffer::{MEMORY_SLOT_SIZE, allocate_buffer, free_buffer, is_executable_address};
pub use disasm::{HookInstruction, decode_instruction};
pub use instruction::{CallAbs, JccAbs, JccRel, JmpAbs, JmpRel, JmpRelShort, Trampoline};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const LIBRARY_NAME: &str = "MinHook-rs";

/// Check if the current platform is supported
#[inline]
pub fn is_supported() -> bool {
    cfg!(target_arch = "x86_64") && cfg!(target_os = "windows")
}

/// Get library version string
#[inline]
pub fn get_version() -> &'static str {
    VERSION
}

/// Get library name
#[inline]
pub fn get_library_name() -> &'static str {
    LIBRARY_NAME
}

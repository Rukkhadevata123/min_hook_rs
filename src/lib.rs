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

// Re-export core types
pub use error::{HookError, Result};

// Re-export main API functions (Rust-style only)
#[rustfmt::skip]
pub use hook::{
    initialize,
    uninitialize,
    create_hook,
    create_hook_api,
    create_hook_api_ex,
    remove_hook,
    enable_hook,
    disable_hook,
    queue_enable_hook,
    queue_disable_hook,
    apply_queued,
    status_to_string,
    ALL_HOOKS,
};

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

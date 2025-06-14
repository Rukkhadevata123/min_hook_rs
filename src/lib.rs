//! MinHook-rs: A Rust port of the MinHook API hooking library
//!
//! MinHook-rs is a minimalistic API hooking library for Windows x64.
//! It provides a simple interface for intercepting Win32 functions.
//!
//! # Features
//!
//! - **Simple**: Easy to use with just a few API calls
//! - **Thread-safe**: All APIs are thread-safe
//! - **Memory efficient**: Minimal memory footprint
//! - **x64 support**: Full support for 64-bit Windows applications
//! - **Rust safety**: Memory-safe implementation with error handling
//!
//! # Usage
//!
//! The basic workflow is:
//! 1. Call `initialize()` to initialize the library
//! 2. Call `create_hook()` or `create_hook_api()` to create a hook
//! 3. Call `enable_hook()` to activate the hook
//! 4. Your hook function will intercept calls to the target function
//! 5. Call `disable_hook()` and `remove_hook()` to clean up
//! 6. Call `uninitialize()` to cleanup the library
//!
//! # Examples
//!
//! See `examples/basic_hook.rs` for a complete working example demonstrating:
//! - Hook creation and installation
//! - Function interception and modification
//! - Dynamic enable/disable functionality
//! - Proper cleanup and resource management
//!
//! # Safety
//!
//! This library uses unsafe operations for low-level memory manipulation.
//! Users must ensure:
//! - Hook functions have the exact same signature as target functions
//! - Target functions are valid and executable
//! - Proper initialization and cleanup
//!
//! # Architecture
//!
//! MinHook-rs works by:
//! 1. Analyzing the target function's machine code
//! 2. Creating a "trampoline" function with the original prologue
//! 3. Patching the target function with a jump to your hook
//! 4. Your hook can call the trampoline to execute the original function

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

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Check if the current platform is supported
///
/// Returns `true` if running on x86_64 Windows, `false` otherwise.
pub fn is_supported() -> bool {
    cfg!(target_arch = "x86_64") && cfg!(target_os = "windows")
}

/// Get library version
pub fn get_version() -> &'static str {
    VERSION
}

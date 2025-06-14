//! Error handling for MinHook-rs
//!
//! This module provides error types that correspond to the original C library's error codes.

use std::fmt;

/// Result type for MinHook operations
pub type Result<T> = std::result::Result<T, HookError>;

/// Error codes returned by MinHook operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum HookError {
    /// Unknown error (should not be returned)
    Unknown = -1,

    /// MinHook is already initialized
    AlreadyInitialized = 1,

    /// MinHook is not initialized yet, or already uninitialized
    NotInitialized = 2,

    /// The hook for the specified target function is already created
    AlreadyCreated = 3,

    /// The hook for the specified target function is not created yet
    NotCreated = 4,

    /// The hook for the specified target function is already enabled
    Enabled = 5,

    /// The hook for the specified target function is not enabled yet, or already disabled
    Disabled = 6,

    /// The specified pointer is invalid (points to non-allocated and/or non-executable region)
    NotExecutable = 7,

    /// The specified target function cannot be hooked
    UnsupportedFunction = 8,

    /// Failed to allocate memory
    MemoryAlloc = 9,

    /// Failed to change the memory protection
    MemoryProtect = 10,

    /// The specified module is not loaded
    ModuleNotFound = 11,

    /// The specified function is not found
    FunctionNotFound = 12,
}

impl HookError {
    /// Convert error to string representation
    pub fn as_str(self) -> &'static str {
        match self {
            HookError::Unknown => "Unknown error",
            HookError::AlreadyInitialized => "Already initialized",
            HookError::NotInitialized => "Not initialized",
            HookError::AlreadyCreated => "Already created",
            HookError::NotCreated => "Not created",
            HookError::Enabled => "Already enabled",
            HookError::Disabled => "Already disabled",
            HookError::NotExecutable => "Not executable",
            HookError::UnsupportedFunction => "Unsupported function",
            HookError::MemoryAlloc => "Memory allocation failed",
            HookError::MemoryProtect => "Memory protection failed",
            HookError::ModuleNotFound => "Module not found",
            HookError::FunctionNotFound => "Function not found",
        }
    }

    /// Convert from C-style error code
    pub fn from_code(code: i32) -> Self {
        match code {
            -1 => HookError::Unknown,
            1 => HookError::AlreadyInitialized,
            2 => HookError::NotInitialized,
            3 => HookError::AlreadyCreated,
            4 => HookError::NotCreated,
            5 => HookError::Enabled,
            6 => HookError::Disabled,
            7 => HookError::NotExecutable,
            8 => HookError::UnsupportedFunction,
            9 => HookError::MemoryAlloc,
            10 => HookError::MemoryProtect,
            11 => HookError::ModuleNotFound,
            12 => HookError::FunctionNotFound,
            _ => HookError::Unknown,
        }
    }
}

impl fmt::Display for HookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::error::Error for HookError {}

/// Success status (equivalent to MH_OK)
pub const OK: i32 = 0;

/// Helper function to create Ok result
pub fn ok<T>(value: T) -> Result<T> {
    Ok(value)
}

/// Helper function to create error result
pub fn err<T>(error: HookError) -> Result<T> {
    Err(error)
}

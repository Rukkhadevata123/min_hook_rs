// hutao_seh.rs
use std::ffi::c_void;
use std::mem::MaybeUninit;

const MS_SUCCEEDED: u32 = 0x0;

// Simplified exception information structure - only essential info
#[repr(C)]
pub struct Exception {
    pub code: u32,
    pub address: *mut c_void,
}

impl Exception {
    fn empty() -> Self {
        Self {
            code: 0,
            address: std::ptr::null_mut(),
        }
    }
}

// Function executor type
type ProcExecutor = unsafe extern "system" fn(*mut c_void);

// Internal function executor
#[inline(always)]
unsafe extern "system" fn proc_executor<F>(proc: *mut c_void)
where
    F: FnMut(),
{
    // The procedure may be equal to std::ptr::null_mut() if the compiler optimized it away.
    if let Some(proc) = unsafe { proc.cast::<F>().as_mut() } {
        proc();
    }
}

// Tell Rust to link the pre-compiled static library
#[cfg(target_arch = "x86_64")]
#[link(name = "hutao_seh_stub", kind = "static")]
unsafe extern "C" {
    #[link_name = "__hutao_seh_HandlerStub"]
    unsafe fn handler_stub(
        proc_executor: ProcExecutor,
        proc: *mut c_void,
        exception: *mut Exception,
    ) -> u32;
}

// Primary execution orchestrator
fn do_call_stub<F>(mut proc: F) -> Result<(), Exception>
where
    F: FnMut(),
{
    let mut exception = Exception::empty();
    let proc = &mut proc as *mut _ as *mut c_void;

    match unsafe { handler_stub(proc_executor::<F>, proc, &mut exception) } {
        MS_SUCCEEDED => Ok(()),
        _ => Err(exception),
    }
}

// Core SEH function
#[inline(always)]
pub fn try_seh<F, R>(mut proc: F) -> Result<R, u32>
where
    F: FnMut() -> R,
{
    let mut ret_val = MaybeUninit::<R>::uninit();

    match do_call_stub(|| {
        ret_val.write(proc());
    }) {
        Ok(_) => {
            // SAFETY: We should only reach this point if the inner closure has returned
            //         without throwing an exception, so `ret_val` should be initialized.
            Ok(unsafe { ret_val.assume_init() })
        }
        Err(exception) => Err(exception.code),
    }
}

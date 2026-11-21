//! C ABI over `ivar-api`.
//!
//! The host writes a JSON request into memory it got from `ivar_alloc`, calls
//! `ivar_call(ptr, len)`, and receives a packed u64: the high 32 bits are the
//! response pointer, the low 32 bits its length. The host reads the JSON
//! response and releases it with `ivar_free`. One request shape serves every
//! host language:
//!
//! `{"op": "core.process", "handle": 1, "args": {...}}`
//!
//! Objects (cores, local sensors, sinks) live in a handle table, so a host can
//! keep several and free them with `{"op": "free", "handle": n}`.

mod dispatch;

use std::alloc::{alloc, dealloc, Layout};

/// Allocate `len` bytes for the host to write a request into.
#[no_mangle]
pub extern "C" fn ivar_alloc(len: u32) -> *mut u8 {
    if len == 0 {
        return std::ptr::null_mut();
    }
    unsafe { alloc(Layout::from_size_align(len as usize, 1).expect("layout")) }
}

/// Release memory returned by `ivar_alloc` or by `ivar_call`.
///
/// # Safety
///
/// `ptr` must be null or a pointer returned by `ivar_alloc` or inside the
/// result of `ivar_call`, with the same `len`, and not freed before.
#[no_mangle]
pub unsafe extern "C" fn ivar_free(ptr: *mut u8, len: u32) {
    if ptr.is_null() || len == 0 {
        return;
    }
    unsafe { dealloc(ptr, Layout::from_size_align(len as usize, 1).expect("layout")) }
}

/// Handle one JSON request; returns (response_ptr << 32) | response_len.
/// An empty or null request is answered with an error, never read.
///
/// # Safety
///
/// `ptr` must be null or point to `len` readable bytes, normally memory
/// from `ivar_alloc` that the host wrote the request into.
#[no_mangle]
pub unsafe extern "C" fn ivar_call(ptr: *const u8, len: u32) -> u64 {
    let input: &[u8] = if ptr.is_null() || len == 0 { &[] } else { unsafe { std::slice::from_raw_parts(ptr, len as usize) } };
    let response = dispatch::handle(input).into_bytes();
    if response.is_empty() {
        return 0;
    }
    let out_len = response.len() as u32;
    let out = ivar_alloc(out_len);
    unsafe { std::ptr::copy_nonoverlapping(response.as_ptr(), out, response.len()) };
    ((out as u64) << 32) | out_len as u64
}

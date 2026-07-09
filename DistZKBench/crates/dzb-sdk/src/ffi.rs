#![allow(unsafe_code)]
#![allow(clippy::missing_safety_doc)]

use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uchar, c_uint, c_ulonglong};
use std::ptr;

use crate::{Dzb, init};

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

#[repr(C)]
pub struct DzbBuffer {
    pub ptr: *mut c_uchar,
    pub len: usize,
}

fn set_last_error(error: impl ToString) {
    let sanitized = error.to_string().replace('\0', " ");
    if let Ok(value) = CString::new(sanitized) {
        LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(value));
    }
}

fn clear_last_error() {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
}

#[unsafe(no_mangle)]
pub extern "C" fn dzb_init() -> *mut Dzb {
    match init() {
        Ok(handle) => {
            clear_last_error();
            Box::into_raw(Box::new(handle))
        }
        Err(error) => {
            set_last_error(error);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dzb_free(handle: *mut Dzb) {
    if !handle.is_null() {
        drop(unsafe { Box::from_raw(handle) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dzb_send(
    handle: *mut Dzb,
    dst: c_uint,
    tag: c_uint,
    ptr: *const c_uchar,
    len: usize,
) -> i32 {
    let Some(dzb) = (unsafe { handle.as_mut() }) else {
        set_last_error("dzb_send received null handle");
        return -1;
    };
    if ptr.is_null() && len != 0 {
        set_last_error("dzb_send received null payload");
        return -1;
    }
    let payload = unsafe { std::slice::from_raw_parts(ptr, len) };
    match dzb.send(dst, tag, payload) {
        Ok(()) => {
            clear_last_error();
            0
        }
        Err(error) => {
            set_last_error(error);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dzb_rank(handle: *mut Dzb) -> c_uint {
    unsafe { handle.as_ref() }.map_or(c_uint::MAX, |dzb| dzb.context().rank() as c_uint)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dzb_world_size(handle: *mut Dzb) -> c_uint {
    unsafe { handle.as_ref() }.map_or(0, |dzb| dzb.context().world_size() as c_uint)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dzb_master_rank(handle: *mut Dzb) -> c_uint {
    unsafe { handle.as_ref() }.map_or(c_uint::MAX, |dzb| dzb.context().master_rank() as c_uint)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dzb_recv(handle: *mut Dzb, src: c_uint, tag: c_uint) -> DzbBuffer {
    let Some(dzb) = (unsafe { handle.as_mut() }) else {
        set_last_error("dzb_recv received null handle");
        return DzbBuffer {
            ptr: ptr::null_mut(),
            len: 0,
        };
    };
    match dzb.recv(src, tag) {
        Ok(mut bytes) => {
            let out = DzbBuffer {
                ptr: bytes.as_mut_ptr(),
                len: bytes.len(),
            };
            std::mem::forget(bytes);
            clear_last_error();
            out
        }
        Err(error) => {
            set_last_error(error);
            DzbBuffer {
                ptr: ptr::null_mut(),
                len: 0,
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dzb_buf_free(buffer: DzbBuffer) {
    if !buffer.ptr.is_null() {
        let _ = unsafe { Vec::from_raw_parts(buffer.ptr, buffer.len, buffer.len) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dzb_phase_start(handle: *mut Dzb, name: *const c_char) -> i32 {
    let Some(dzb) = (unsafe { handle.as_mut() }) else {
        set_last_error("dzb_phase_start received null handle");
        return -1;
    };
    let Some(name) = (unsafe { read_c_string(name) }) else {
        set_last_error("dzb_phase_start received invalid name");
        return -1;
    };
    dzb.metrics.start_phase(name);
    clear_last_error();
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dzb_phase_end(handle: *mut Dzb) -> i32 {
    let Some(dzb) = (unsafe { handle.as_mut() }) else {
        set_last_error("dzb_phase_end received null handle");
        return -1;
    };
    match dzb.metrics.end_phase() {
        Ok(()) => {
            clear_last_error();
            0
        }
        Err(error) => {
            set_last_error(error);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dzb_metric_u64(
    handle: *mut Dzb,
    name: *const c_char,
    value: c_ulonglong,
) -> i32 {
    let Some(dzb) = (unsafe { handle.as_mut() }) else {
        set_last_error("dzb_metric_u64 received null handle");
        return -1;
    };
    let Some(name) = (unsafe { read_c_string(name) }) else {
        set_last_error("dzb_metric_u64 received invalid name");
        return -1;
    };
    dzb.metrics.counter(name, value);
    clear_last_error();
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dzb_artifact_write(
    handle: *mut Dzb,
    name: *const c_char,
    ptr: *const c_uchar,
    len: usize,
) -> i32 {
    let Some(dzb) = (unsafe { handle.as_mut() }) else {
        set_last_error("dzb_artifact_write received null handle");
        return -1;
    };
    let Some(name) = (unsafe { read_c_string(name) }) else {
        set_last_error("dzb_artifact_write received invalid name");
        return -1;
    };
    let payload = unsafe { std::slice::from_raw_parts(ptr, len) };
    match dzb.artifacts.write_artifact(name, payload) {
        Ok(_) => {
            clear_last_error();
            0
        }
        Err(error) => {
            set_last_error(error);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dzb_publish_proof_bytes(
    handle: *mut Dzb,
    ptr: *const c_uchar,
    len: usize,
) -> i32 {
    let Some(dzb) = (unsafe { handle.as_mut() }) else {
        set_last_error("dzb_publish_proof_bytes received null handle");
        return -1;
    };
    let payload = unsafe { std::slice::from_raw_parts(ptr, len) };
    match dzb.artifacts.publish_proof_bytes(payload.to_vec()) {
        Ok(_) => {
            clear_last_error();
            0
        }
        Err(error) => {
            set_last_error(error);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dzb_finish(handle: *mut Dzb) -> i32 {
    if handle.is_null() {
        set_last_error("dzb_finish received null handle");
        return -1;
    }
    let dzb = unsafe { Box::from_raw(handle) };
    match dzb.finish() {
        Ok(_) => {
            clear_last_error();
            0
        }
        Err(error) => {
            set_last_error(error);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dzb_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| {
        slot.borrow()
            .as_ref()
            .map_or(ptr::null(), |error| error.as_ptr())
    })
}

unsafe fn read_c_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

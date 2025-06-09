use crossbeam_channel::{Receiver, Sender};
use std::io;
use std::mem;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::LazyLock;

use super::SysStack;

#[path = "overflow_unix.rs"]
pub mod overflow;

#[cfg(any(
    target_os = "openbsd",
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "illumos",
    target_os = "solaris"
))]
const MAP_STACK: libc::c_int = 0;

#[cfg(not(any(
    target_os = "openbsd",
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "illumos",
    target_os = "solaris"
)))]
const MAP_STACK: libc::c_int = libc::MAP_STACK;

struct Bin {
    send: Sender<SysStack>,
    recv: Receiver<SysStack>,
}

static BINS: LazyLock<[Bin; usize::BITS as usize]> = LazyLock::new(|| {
    std::array::from_fn(|_| {
        let (send, recv) = crossbeam_channel::unbounded();
        Bin { send, recv }
    })
});

fn bin_for_size(size: usize) -> &'static Bin {
    &BINS[size.max(1).ilog2() as usize]
}

pub unsafe fn allocate_stack(size: usize) -> io::Result<SysStack> {
    const NULL: *mut libc::c_void = 0 as *mut libc::c_void;
    const PROT: libc::c_int = libc::PROT_READ | libc::PROT_WRITE;
    const TYPE: libc::c_int = libc::MAP_PRIVATE | libc::MAP_ANON | MAP_STACK;

    // Reuse an existing allocation if possible
    let bin = bin_for_size(size);
    if let Ok(stack) = bin.recv.try_recv() {
        return Ok(stack);
    }

    let ptr = libc::mmap(NULL, size, PROT, TYPE, -1, 0);

    if std::ptr::eq(ptr, libc::MAP_FAILED) {
        return Err(io::Error::last_os_error());
    }

    let stack = SysStack::new((ptr as usize + size) as *mut c_void, ptr as *mut c_void);

    if let Err(error) = protect_stack_real(&stack) {
        deallocate_stack(stack.bottom, stack.top.offset_from(stack.bottom) as usize);
        return Err(error);
    }

    Ok(stack)
}

pub unsafe fn protect_stack(stack: &SysStack) -> io::Result<SysStack> {
    // `allocate_stack` now implicitly protects the stack
    Ok(exclude_guard(stack))
}

unsafe fn protect_stack_real(stack: &SysStack) -> io::Result<()> {
    let page_size = page_size();

    debug_assert!(stack.len() % page_size == 0 && stack.len() != 0);

    let ret = {
        let bottom = stack.bottom();
        libc::mprotect(bottom, page_size, libc::PROT_NONE)
    };

    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

unsafe fn exclude_guard(stack: &SysStack) -> SysStack {
    let page_size = page_size();

    debug_assert!(stack.len() % page_size == 0 && stack.len() != 0);

    let bottom = (stack.bottom() as usize + page_size) as *mut c_void;
    SysStack::new(stack.top(), bottom)
}

pub unsafe fn deallocate_stack(ptr: *mut c_void, size: usize) {
    let bin = bin_for_size(size);
    bin.send
        .send(SysStack::new(ptr.wrapping_add(size), ptr))
        .unwrap();
}

pub fn page_size() -> usize {
    static PAGE_SIZE: AtomicUsize = AtomicUsize::new(0);

    let mut ret = PAGE_SIZE.load(Ordering::Relaxed);

    if ret == 0 {
        unsafe {
            ret = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        }

        PAGE_SIZE.store(ret, Ordering::Relaxed);
    }

    ret
}

pub fn min_stack_size() -> usize {
    // Previously libc::SIGSTKSZ has been used for this, but it proofed to be very unreliable,
    // because the resulting values varied greatly between platforms.
    page_size()
}

#[cfg(not(target_os = "fuchsia"))]
pub fn max_stack_size() -> usize {
    static PAGE_SIZE: AtomicUsize = AtomicUsize::new(0);

    let mut ret = PAGE_SIZE.load(Ordering::Relaxed);

    if ret == 0 {
        let mut limit = mem::MaybeUninit::uninit();
        let limitret = unsafe { libc::getrlimit(libc::RLIMIT_STACK, limit.as_mut_ptr()) };
        let limit = unsafe { limit.assume_init() };

        if limitret == 0 {
            ret = if limit.rlim_max == libc::RLIM_INFINITY
                || limit.rlim_max > (usize::MAX as libc::rlim_t)
            {
                usize::MAX
            } else {
                limit.rlim_max as usize
            };

            PAGE_SIZE.store(ret, Ordering::Relaxed);
        } else {
            ret = 1024 * 1024 * 1024;
        }
    }

    ret
}

#[cfg(target_os = "fuchsia")]
pub fn max_stack_size() -> usize {
    // Fuchsia doesn't have a platform defined hard cap.
    usize::MAX
}

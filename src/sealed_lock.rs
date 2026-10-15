//! Cross-process locks for sealed store records, isolated to the current Windows user.

use std::time::Duration;

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};

use crate::sealed::SealError;
use crate::utils::hex;

pub(crate) struct TargetLock(HANDLE);

pub(crate) fn lock_target(target: &str) -> Result<TargetLock, SealError> {
    lock_target_with_timeout(target, Duration::from_secs(30))
}

/// Caps the wait at the largest interval `WaitForSingleObject` accepts as finite.
fn wait_millis(timeout: Duration) -> u32 {
    u32::try_from(timeout.as_millis()).map_or(u32::MAX - 1, |ms| ms.min(u32::MAX - 1))
}

pub(crate) fn lock_target_with_timeout(
    target: &str,
    timeout: Duration,
) -> Result<TargetLock, SealError> {
    let name = crate::user_lock::object_name(&hex(&Sha256::digest(target.as_bytes())))
        .map_err(|error| SealError::Platform(error.to_string()))?;
    // SAFETY: `name` is NUL-terminated and outlives the call, and null security attributes are allowed.
    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    if handle.is_null() {
        return Err(last_error("create credential mutex"));
    }
    let millis = wait_millis(timeout);
    // SAFETY: `handle` is a live mutex handle owned here, and the finite wait excludes `INFINITE`.
    match unsafe { WaitForSingleObject(handle, millis) } {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(TargetLock(handle)),
        wait => {
            let error = if wait == WAIT_TIMEOUT {
                SealError::TimedOut
            } else {
                last_error("wait for credential mutex")
            };
            // SAFETY: `handle` is owned here and not used again after closing.
            unsafe { CloseHandle(handle) };
            Err(error)
        }
    }
}

fn last_error(operation: &str) -> SealError {
    // SAFETY: reads this thread's last-error value with no preconditions.
    let code = unsafe { GetLastError() };
    SealError::Platform(format!("{operation} failed with {code}"))
}

impl Drop for TargetLock {
    fn drop(&mut self) {
        // SAFETY: the guard owns a mutex acquired by this thread and releases and closes it once.
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}

/// Panics unless a dropped `TargetLock` is free for another thread.
///
/// The check runs once per process, so every test built on store locks fails at once instead of
/// waiting out the lock timeout when locks are not released.
#[cfg(test)]
pub(crate) fn assert_target_lock_released() {
    crate::user_lock::assert_names_distinct();
    static RELEASED: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
        let target = format!("released-{}", fastrand::u64(..));
        drop(lock_target_with_timeout(&target, Duration::from_secs(5)).expect("the target lock"));
        std::thread::scope(|scope| {
            scope
                .spawn(|| lock_target_with_timeout(&target, Duration::from_secs(5)).is_ok())
                .join()
                .unwrap()
        })
    });
    assert!(*RELEASED, "a dropped target lock stays held");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Instant;

    /// Fails the test if `worker` is still running when the deadline passes.
    fn join_before(worker: std::thread::JoinHandle<()>, deadline: Duration) {
        let limit = Instant::now() + deadline;
        while !worker.is_finished() {
            if Instant::now() >= limit {
                panic!("the lock worker is still running after {deadline:?}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        worker.join().unwrap();
    }

    #[test]
    fn a_global_squatter_cannot_hold_store_locks() {
        let target = format!("squat-{}", fastrand::u64(..));
        let digest = hex(&Sha256::digest(target.as_bytes()));
        let squatted: Vec<u16> = format!("Global\\windows-native-keyring-store-v1-{digest}\0")
            .encode_utf16()
            .collect();
        // SAFETY: the name is NUL-terminated, and this thread takes initial ownership.
        let squatter = unsafe { CreateMutexW(std::ptr::null(), 1, squatted.as_ptr()) };
        assert!(!squatter.is_null());
        let (tx, rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let acquired = lock_target_with_timeout(&target, Duration::from_secs(2)).is_ok();
            tx.send(acquired).unwrap();
        });
        let acquired = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        join_before(worker, Duration::from_secs(5));
        // SAFETY: this thread owns `squatter` and releases and closes it once.
        unsafe {
            ReleaseMutex(squatter);
            CloseHandle(squatter);
        }
        assert!(
            acquired,
            "a same-named machine-global mutex blocked the store lock"
        );
    }

    #[test]
    fn the_user_namespace_lock_is_acquirable() {
        let target = format!("lock-{}", fastrand::u64(..));
        assert!(lock_target_with_timeout(&target, Duration::from_secs(2)).is_ok());
    }

    #[test]
    fn a_dropped_lock_is_free_for_another_thread() {
        assert_target_lock_released();
    }

    #[test]
    fn a_contended_lock_times_out_after_the_requested_wait() {
        let target = format!("expire-{}", fastrand::u64(..));
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        // Windows mutexes are reentrant, so another thread holds the lock.
        let holder = {
            let target = target.clone();
            std::thread::spawn(move || {
                let _held = lock_target_with_timeout(&target, Duration::from_secs(2)).unwrap();
                held_tx.send(()).unwrap();
                let _ = release_rx.recv_timeout(Duration::from_secs(5));
            })
        };
        held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let started = Instant::now();
        let probe = lock_target_with_timeout(&target, Duration::from_millis(50));
        let waited = started.elapsed();
        release_tx.send(()).unwrap();
        join_before(holder, Duration::from_secs(5));
        assert!(matches!(probe, Err(SealError::TimedOut)));
        assert!(
            waited >= Duration::from_millis(25),
            "the timed-out wait returned before the requested interval elapsed"
        );
    }

    #[test]
    fn the_wait_interval_is_capped_below_infinite() {
        assert_eq!(wait_millis(Duration::from_millis(200)), 200);
        assert_eq!(wait_millis(Duration::from_secs(30)), 30_000);
        assert_eq!(
            wait_millis(Duration::from_millis(u64::from(u32::MAX))),
            u32::MAX - 1
        );
        assert_eq!(
            wait_millis(Duration::from_millis(u64::from(u32::MAX) + 1)),
            u32::MAX - 1
        );
    }
}

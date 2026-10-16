//! Named kernel objects in a private namespace that only the effective Windows user can create.
//!
//! Any local account can create a machine-global object first under a name derived from another
//! user's `SID`, and then block or deny that user. The namespace here has the user's `SID` as its
//! boundary and a DACL that admits only that user, so no other account can create or open it.

use std::ptr;
use std::sync::{Mutex, PoisonError};

use keyring_core::error::Result;
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetLengthSid, GetTokenInformation, PSID, SECURITY_ATTRIBUTES, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Threading::{
    AddSIDToBoundaryDescriptor, CreateBoundaryDescriptorW, CreatePrivateNamespaceW,
    DeleteBoundaryDescriptor, OpenPrivateNamespaceW,
};

use crate::utils::{decode_error, from_wstr, hex};

const PREFIX: &str = "windows-native-keyring-store-v1";

/// The NUL-terminated name of `object` in the effective user's private namespace.
///
/// The process enters each user's namespace once and never closes it, so the name stays
/// resolvable for the life of the process. Opening a namespace this process already holds fails
/// with `ERROR_DUP_NAME`, which is why entries are remembered.
pub(crate) fn object_name(object: &str) -> Result<Vec<u16>> {
    // The `SID` of every user whose namespace this process has entered.
    static ENTERED: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());
    let user = EffectiveUser::read()?;
    let alias = format!("{PREFIX}-{}", hex(user.sid_bytes()));
    let mut entered = ENTERED.lock().unwrap_or_else(PoisonError::into_inner);
    if !entered.iter().any(|sid| sid == user.sid_bytes()) {
        enter(user.sid(), &alias)?;
        entered.push(user.sid_bytes().to_vec());
    }
    Ok(format!("{alias}\\{object}\0").encode_utf16().collect())
}

/// Panics unless different objects get different NUL-terminated names.
///
/// The check runs once per process, so every test built on these names fails at once instead of
/// waiting out lock timeouts when all objects share one name.
#[cfg(test)]
pub(crate) fn assert_names_distinct() {
    static DISTINCT: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
        let (Ok(first), Ok(second)) = (object_name("first"), object_name("second")) else {
            return false;
        };
        first != second && first.last() == Some(&0) && second.last() == Some(&0)
    });
    assert!(*DISTINCT, "lock objects share a name or lack a terminator");
}

/// The `SID` of the user whose token is in effect for this thread, which selects the credential
/// set.
struct EffectiveUser {
    /// `SECURITY_MAX_SID_SIZE` bytes, stored at the alignment of the `SID` sub-authorities.
    sid: [u32; 17],
    length: usize,
}

impl EffectiveUser {
    fn read() -> Result<Self> {
        // `GetCurrentThreadEffectiveToken()` pseudo-handle from `processthreadsapi.h`, the
        // thread token while impersonating and the process token otherwise.
        let token = ptr::without_provenance_mut((-6isize).cast_unsigned());
        let mut buffer = [0usize; 16];
        let size = u32::try_from(size_of_val(&buffer)).expect("the buffer size fits u32");
        let mut written = 0;
        // SAFETY: Queryable pseudo-token, writable aligned buffer of `size` bytes and result pointer.
        let queried = unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size,
                &mut written,
            )
        };
        if queried == 0 {
            return Err(decode_error());
        }
        // SAFETY: Success wrote a `TOKEN_USER` whose `SID` lies inside `buffer`.
        let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        // SAFETY: `sid` is a valid `SID` inside `buffer`.
        let length =
            usize::try_from(unsafe { GetLengthSid(sid) }).expect("a SID length fits usize");
        let mut user = Self {
            sid: [0; 17],
            length,
        };
        assert!(
            length <= size_of_val(&user.sid),
            "a SID never exceeds SECURITY_MAX_SID_SIZE"
        );
        // SAFETY: `GetLengthSid` bounds the source inside `buffer`, the asserted length fits the
        // destination, and the two buffers are distinct.
        unsafe {
            ptr::copy_nonoverlapping(sid.cast::<u8>(), user.sid.as_mut_ptr().cast::<u8>(), length);
        }
        Ok(user)
    }

    /// The `SID` for APIs that take a `PSID` and only read through it.
    fn sid(&self) -> PSID {
        self.sid.as_ptr().cast_mut().cast()
    }

    fn sid_bytes(&self) -> &[u8] {
        // SAFETY: `read` copied `length` bytes of the `SID` into `self.sid`.
        unsafe { std::slice::from_raw_parts(self.sid.as_ptr().cast::<u8>(), self.length) }
    }
}

/// Memory a Win32 call allocated with `LocalAlloc`, freed once on drop.
struct LocalMemory(*mut core::ffi::c_void);

impl Drop for LocalMemory {
    fn drop(&mut self) {
        // SAFETY: The pointer came from a Win32 allocation with `LocalAlloc` and is freed once.
        unsafe { LocalFree(self.0) };
    }
}

/// A boundary descriptor, deleted once on drop.
struct Boundary(HANDLE);

impl Drop for Boundary {
    fn drop(&mut self) {
        // SAFETY: The handle came from `CreateBoundaryDescriptorW` and is deleted once.
        unsafe { DeleteBoundaryDescriptor(self.0) };
    }
}

/// A non-null handle is the only kind this module treats as live.
fn handle_is_live(handle: HANDLE) -> bool {
    !handle.is_null()
}

/// Creates the user's namespace, or opens it when another process of the user already did.
fn enter(sid: PSID, alias: &str) -> Result<()> {
    let descriptor = user_only_descriptor(sid)?;
    let name: Vec<u16> = format!("{alias}\0").encode_utf16().collect();
    // SAFETY: `name` is NUL-terminated.
    let boundary = unsafe { CreateBoundaryDescriptorW(name.as_ptr(), 0) };
    if boundary.is_null() {
        return Err(decode_error());
    }
    let mut boundary = Boundary(boundary);
    // SAFETY: `boundary` is a live boundary descriptor and `sid` is a valid `SID`.
    if unsafe { AddSIDToBoundaryDescriptor(&mut boundary.0, sid) } == 0 {
        return Err(decode_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).expect("the size fits u32"),
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // The last other holder can exit between a refused create and the open, so retry a few times.
    for _ in 0..8 {
        // SAFETY: `attributes`, `boundary` and the NUL-terminated `name` are live for the call.
        let created = unsafe { CreatePrivateNamespaceW(&attributes, boundary.0, name.as_ptr()) };
        if handle_is_live(created) {
            return Ok(());
        }
        // SAFETY: Reads this thread's last-error value.
        if unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
            return Err(decode_error());
        }
        // SAFETY: `boundary` and the NUL-terminated `name` are live for the call.
        if handle_is_live(unsafe { OpenPrivateNamespaceW(boundary.0, name.as_ptr()) }) {
            return Ok(());
        }
    }
    Err(decode_error())
}

/// A security descriptor whose DACL grants all access to `sid` alone.
fn user_only_descriptor(sid: PSID) -> Result<LocalMemory> {
    let mut text = ptr::null_mut();
    // SAFETY: `sid` is a valid `SID` and the out pointer is writable.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(decode_error());
    }
    let text = LocalMemory(text.cast());
    // SAFETY: The conversion returned a NUL-terminated string that `text` keeps alive.
    let sid_text = unsafe { from_wstr(text.0.cast()) };
    let sddl: Vec<u16> = format!("D:P(A;;GA;;;{sid_text})\0")
        .encode_utf16()
        .collect();
    let mut descriptor = ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated and the out pointer is writable.
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if converted == 0 {
        return Err(decode_error());
    }
    Ok(LocalMemory(descriptor))
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Read};
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Threading::CreateMutexW;

    use super::{assert_names_distinct, handle_is_live, object_name};

    const HOLD_ENV: &str = "KEYRING_TEST_HOLD_LOCK_NAMESPACE";
    const PROBE_ENV: &str = "KEYRING_TEST_PROBE_LOCK_NAMESPACE";
    /// Printed by the holder, which libtest may append to its `test ... ` line.
    const HELD: &str = "lock namespace held";

    /// This test binary running only `test`, with `env` set so that test does its work.
    fn sibling(test: &str, env: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", test, "--test-threads", "1", "--nocapture"])
            .env(env, "1");
        command
    }

    /// Fails the test if `child` is still running when the deadline passes.
    fn exit_before(child: &mut Child, deadline: Duration) -> ExitStatus {
        let limit = Instant::now() + deadline;
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() >= limit {
                let _ = child.kill();
                panic!("the sibling process is still running after {deadline:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Whether a mutex named `object` can be created in the user's namespace.
    fn a_mutex_opens(object: &str) -> bool {
        let Ok(name) = object_name(object) else {
            return false;
        };
        // SAFETY: `name` is NUL-terminated and the API accepts a null descriptor.
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            return false;
        }
        // SAFETY: `handle` is a live mutex handle closed once.
        unsafe { CloseHandle(handle) };
        true
    }

    #[test]
    fn only_a_non_null_handle_is_live() {
        assert!(!handle_is_live(HANDLE::default()));
        assert!(handle_is_live(std::ptr::with_exposed_provenance_mut(1)));
    }

    #[test]
    fn different_objects_get_distinct_terminated_names() {
        assert_names_distinct();
    }

    #[test]
    fn hold_the_namespace_for_a_sibling() {
        if std::env::var_os(HOLD_ENV).is_none() {
            return;
        }
        assert!(a_mutex_opens("hold"));
        println!("{HELD}");
        let (closed_tx, closed_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = std::io::stdin().read_to_end(&mut Vec::new());
            let _ = closed_tx.send(());
        });
        let _ = closed_rx.recv_timeout(Duration::from_secs(10));
    }

    #[test]
    fn probe_the_namespace_of_a_sibling() {
        if std::env::var_os(PROBE_ENV).is_none() {
            return;
        }
        assert!(a_mutex_opens("probe"));
    }

    #[test]
    fn a_namespace_another_process_created_is_opened() {
        let mut holder = sibling(
            "user_lock::tests::hold_the_namespace_for_a_sibling",
            HOLD_ENV,
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
        let stdout = holder.stdout.take().unwrap();
        let (held_tx, held_rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if line.is_ok_and(|line| line.contains(HELD)) {
                    let _ = held_tx.send(());
                }
            }
        });
        let held = held_rx.recv_timeout(Duration::from_secs(10));
        let probed = held.is_ok().then(|| {
            let mut prober = sibling(
                "user_lock::tests::probe_the_namespace_of_a_sibling",
                PROBE_ENV,
            )
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
            exit_before(&mut prober, Duration::from_secs(10))
        });
        drop(holder.stdin.take());
        let released = exit_before(&mut holder, Duration::from_secs(10));
        assert!(held.is_ok(), "the holder never entered the namespace");
        assert!(
            probed.is_some_and(|status| status.success()),
            "a second process of this user failed to open the existing namespace"
        );
        assert!(released.success());
    }
}

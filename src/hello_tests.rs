use std::sync::Arc;
use std::time::Duration;

use keyring_core::{Entry, Error, api::CredentialStoreApi};
use windows_sys::Win32::Foundation::HWND;

use crate::hello::{HelloCancellation, HelloStore, HelloWindow};
use crate::utils::{delete_credential, extract_from_credential, extract_secret, save_credential};
use crate::{CredPersist, SealError, SealedStore};

const DISCARD_TIMEOUT: Duration = Duration::from_secs(10);

fn target_of(entry: &Entry) -> String {
    let cred = entry.as_any().downcast_ref::<crate::cred::Cred>();
    cred.unwrap().target_name.clone()
}

fn raw(target: &str) -> keyring_core::Result<Vec<u8>> {
    extract_from_credential(target, extract_secret)
}

fn write_raw(target: &str, bytes: &[u8]) {
    save_credential(target, "", "", "", bytes, &CredPersist::Local).unwrap();
}

fn refused_with<T>(result: keyring_core::Result<T>, expected: &SealError) -> bool {
    match result {
        Err(Error::NoStorageAccess(reason)) => reason.downcast_ref::<SealError>() == Some(expected),
        _ => false,
    }
}

/// A Hello store with a fresh name whose records are deleted when the test ends.
struct Scope {
    application: String,
    // Unique per scope, so migration only ever meets plain entries this scope wrote.
    service: String,
    store: Arc<HelloStore>,
    targets: Vec<String>,
}

impl Scope {
    fn new(name: &str) -> Self {
        let application = format!("hello-test-{}", fastrand::u64(..));
        let store = HelloStore::new(&application, name).unwrap();
        store.assert_usable();
        Self {
            store,
            service: format!("{application}-service"),
            application,
            targets: Vec::new(),
        }
    }

    fn entry(&mut self, user: &str) -> Entry {
        let entry = self.store.build(&self.service, user, None).unwrap();
        self.targets.push(target_of(&entry));
        entry
    }

    fn record(&self, suffix: &str) -> String {
        format!("{}{suffix}", self.store.id())
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        let records = ["metadata", "control", "keycheck"].map(|suffix| self.record(suffix));
        for target in self.targets.iter().chain(&records) {
            let _ = delete_credential(target);
        }
    }
}

struct MissingWindow;

impl HelloWindow for MissingWindow {
    fn hwnd(&self) -> windows_sys::Win32::Foundation::HWND {
        std::ptr::null_mut()
    }
}

/// A hidden window that is created and destroyed on the test thread, which it cannot leave.
struct HiddenWindow {
    hwnd: HWND,
    destroyed: bool,
}

/// A reference to a [`HiddenWindow`] that unlock workers may hold, never destroying it.
struct WindowHandle(usize);

impl HelloWindow for WindowHandle {
    fn hwnd(&self) -> HWND {
        self.0 as HWND
    }
}

impl HiddenWindow {
    fn new() -> Self {
        use windows_sys::Win32::UI::WindowsAndMessaging::CreateWindowExW;
        let class: Vec<u16> = "STATIC\0".encode_utf16().collect();
        // SAFETY: the class name is a NUL-terminated built-in window class, and every other
        // argument is zero or null.
        let hwnd = unsafe {
            CreateWindowExW(
                0,
                class.as_ptr(),
                std::ptr::null(),
                0,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        assert!(!hwnd.is_null(), "static window creation failed");
        Self {
            hwnd,
            destroyed: false,
        }
    }

    fn handle(&self) -> Arc<dyn HelloWindow> {
        Arc::new(WindowHandle(self.hwnd as usize))
    }

    /// Destroys the window, reporting whether Windows accepted it.
    fn destroy(&mut self) -> bool {
        self.destroyed = true;
        // SAFETY: `HWND` keeps this guard on the creating thread, and the window is destroyed once.
        unsafe { windows_sys::Win32::UI::WindowsAndMessaging::DestroyWindow(self.hwnd) != 0 }
    }
}

impl Drop for HiddenWindow {
    fn drop(&mut self) {
        if !self.destroyed {
            self.destroy();
        }
    }
}

#[test]
fn locked_hello_store_refuses_secret_operations() {
    let mut scope = Scope::new("locked");
    let entry = scope.entry("user");
    assert!(refused_with(entry.get_secret(), &SealError::Locked));
    assert!(refused_with(
        entry.set_secret(b"secret"),
        &SealError::Locked
    ));
    assert!(matches!(raw(&target_of(&entry)), Err(Error::NoEntry)));
}

#[test]
fn hello_and_sealed_stores_with_the_same_names_never_share_entries() {
    let hello = HelloStore::new("shared-names", "store").unwrap();
    let sealed = SealedStore::new("shared-names", "store").unwrap();
    assert_ne!(hello.id(), sealed.id());
    assert_ne!(
        target_of(&hello.build("svc", "user", None).unwrap()),
        target_of(&sealed.build("svc", "user", None).unwrap())
    );
}

#[test]
fn unlock_without_a_live_owner_fails_before_any_record_is_written() {
    let scope = Scope::new("missing-owner");
    let result = scope.store.unlock(
        Arc::new(MissingWindow),
        &HelloCancellation::new(),
        Duration::from_secs(5),
    );
    assert_eq!(result, Err(SealError::MissingOwner));
    assert!(matches!(
        raw(&scope.record("metadata")),
        Err(Error::NoEntry)
    ));
}

#[test]
fn round_trip_after_unlock_stores_only_ciphertext() {
    let mut scope = Scope::new("round-trip");
    scope.store.install_test_key([3; 32]);
    let entry = scope.entry("user");
    entry.set_password("refresh-token").unwrap();
    assert_eq!(entry.get_password().unwrap(), "refresh-token");
    assert!(crate::sealed_crypto::is_protected(
        &raw(&target_of(&entry)).unwrap()
    ));
    scope.store.lock();
    assert!(refused_with(entry.get_password(), &SealError::Locked));
}

#[test]
fn dropping_the_store_locks_retained_entries() {
    let mut scope = Scope::new("drop");
    scope.store.install_test_key([71; 32]);
    let entry = scope.entry("user");
    let store = std::mem::replace(
        &mut scope.store,
        HelloStore::new(&scope.application, "drop").unwrap(),
    );
    drop(store);
    assert!(refused_with(
        entry.set_secret(b"secret"),
        &SealError::Locked
    ));
}

#[test]
fn locked_delete_removes_the_entry_without_a_prompt() {
    let mut scope = Scope::new("delete");
    scope.store.install_test_key([44; 32]);
    let entry = scope.entry("user");
    entry.set_secret(b"sealed").unwrap();
    scope.store.lock();
    entry.delete_credential().unwrap();
    assert!(matches!(raw(&target_of(&entry)), Err(Error::NoEntry)));
    assert!(matches!(entry.delete_credential(), Err(Error::NoEntry)));
}

#[test]
fn discard_retires_old_handles_and_preserves_another_named_store() {
    let mut first = Scope::new("first");
    let mut second = Scope::new("second");
    first.store.install_test_key([12; 32]);
    second.store.install_test_key([13; 32]);
    let old = first.entry("item");
    let neighbor = second.entry("item");
    old.set_secret(b"first").unwrap();
    neighbor.set_secret(b"second").unwrap();

    first.store.discard(DISCARD_TIMEOUT).unwrap();
    assert!(matches!(raw(&target_of(&old)), Err(Error::NoEntry)));
    assert_eq!(neighbor.get_secret().unwrap(), b"second");
    assert!(refused_with(
        old.set_secret(b"stale"),
        &SealError::Discarded
    ));
    assert!(refused_with(old.delete_credential(), &SealError::Discarded));

    let fresh = HelloStore::new(&first.application, "first").unwrap();
    fresh.install_test_key([17; 32]);
    let replacement = fresh.build(&first.service, "item", None).unwrap();
    replacement.set_secret(b"replacement").unwrap();
    assert_eq!(replacement.get_secret().unwrap(), b"replacement");
}

#[test]
fn discard_recovers_from_corrupt_enrollment_metadata() {
    let mut scope = Scope::new("metadata");
    scope.store.install_test_key([21; 32]);
    let entry = scope.entry("item");
    entry.set_secret(b"sealed").unwrap();
    write_raw(&scope.record("metadata"), b"not enrollment metadata");

    scope.store.discard(DISCARD_TIMEOUT).unwrap();
    for removed in [target_of(&entry), scope.record("metadata")] {
        assert!(matches!(raw(&removed), Err(Error::NoEntry)));
    }
}

#[test]
fn entries_without_enrollment_metadata_report_a_lost_passkey_on_unlock() {
    let mut scope = Scope::new("orphan");
    scope.store.install_test_key([22; 32]);
    scope.entry("item").set_secret(b"sealed").unwrap();
    let reopened = HelloStore::new(&scope.application, "orphan").unwrap();
    let mut window = HiddenWindow::new();
    let result = reopened.unlock(
        window.handle(),
        &HelloCancellation::new(),
        Duration::from_secs(5),
    );
    assert_eq!(result, Err(SealError::KeyLost));
    assert_eq!(reopened.protection(), crate::Protection::Lost);
    assert!(
        window.destroy(),
        "the test thread could not destroy its window"
    );
    // SAFETY: `IsWindow` accepts any handle value, including destroyed ones.
    let alive = unsafe { windows_sys::Win32::UI::WindowsAndMessaging::IsWindow(window.hwnd) };
    assert_eq!(alive, 0, "the owner window outlived the test");
}

#[test]
fn discard_times_out_at_a_held_metadata_lease_and_a_later_discard_resumes() {
    let mut scope = Scope::new("lease");
    scope.store.install_test_key([23; 32]);
    let entry = scope.entry("item");
    entry.set_secret(b"kept").unwrap();
    let metadata = scope.record("metadata");
    let (held, holding) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        let _lease = crate::sealed_lock::lock_target(&metadata).unwrap();
        held.send(()).unwrap();
        released.recv_timeout(crate::pause::BOUND).unwrap();
    });
    holding.recv_timeout(crate::pause::BOUND).unwrap();

    let timed_out = scope.store.discard(Duration::from_millis(300));
    let other = HelloStore::new(&scope.application, "lease").unwrap();
    let refused = other
        .build(&scope.service, "item", None)
        .unwrap()
        .get_secret();
    let preserved = raw(&target_of(&entry));
    release.send(()).unwrap();
    holder.join().unwrap();
    assert_eq!(timed_out, Err(SealError::TimedOut));
    assert!(refused_with(refused, &SealError::Discarding));
    assert!(preserved.is_ok());

    other.discard(DISCARD_TIMEOUT).unwrap();
    assert!(matches!(raw(&target_of(&entry)), Err(Error::NoEntry)));
    assert!(refused_with(entry.get_secret(), &SealError::Discarded));
}

#[test]
fn an_unlock_timing_out_on_a_held_enrollment_lease_writes_nothing() {
    let scope = Scope::new("expired");
    let metadata = scope.record("metadata");
    let finished = crate::pause::arm(&scope.store.id(), "unlock.finished");
    let (held, holding) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let holder = {
        let metadata = metadata.clone();
        std::thread::spawn(move || {
            let _lease = crate::sealed_lock::lock_target(&metadata).unwrap();
            held.send(()).unwrap();
            released.recv_timeout(crate::pause::BOUND).unwrap();
        })
    };
    holding.recv_timeout(crate::pause::BOUND).unwrap();

    let window = HiddenWindow::new();
    let result = scope.store.unlock(
        window.handle(),
        &HelloCancellation::new(),
        Duration::from_millis(300),
    );
    release.send(()).unwrap();
    holder.join().unwrap();
    // Assert before the pause, since a refused unlock leaves no worker to release it.
    assert_eq!(result, Err(SealError::TimedOut));
    assert!(matches!(raw(&metadata), Err(Error::NoEntry)));
    assert_eq!(scope.store.protection(), crate::Protection::Locked);
    finished.next().resume();
}

/// Runs `HelloStore::unlock` on another thread, reporting its result on the returned channel.
fn start_unlock(
    store: &Arc<HelloStore>,
    window: &HiddenWindow,
    token: &HelloCancellation,
    timeout: Duration,
) -> std::sync::mpsc::Receiver<Result<(), SealError>> {
    let (sender, receiver) = std::sync::mpsc::channel();
    let (store, owner, token) = (Arc::clone(store), window.handle(), token.clone());
    std::thread::spawn(move || {
        let _ = sender.send(store.unlock(owner, &token, timeout));
    });
    receiver
}

#[test]
fn an_unlock_cancelled_after_reading_metadata_writes_nothing() {
    let scope = Scope::new("prepared");
    let metadata = scope.record("metadata");
    let reading = crate::pause::arm(&scope.store.id(), "unlock.metadata");
    let finished = crate::pause::arm(&scope.store.id(), "unlock.finished");
    let window = HiddenWindow::new();
    let token = HelloCancellation::new();
    let results = start_unlock(&scope.store, &window, &token, crate::pause::BOUND);
    // A refused unlock leaves no request, so no thread can reach the armed pause points.
    let Some(paused) = reading.within(Duration::from_millis(5000)) else {
        let result = results.recv_timeout(crate::pause::BOUND);
        panic!("unlock never reached its pause point: {result:?}");
    };
    token.cancel();
    let result = results.recv_timeout(crate::pause::BOUND).unwrap();
    paused.resume();
    finished.next().resume();
    assert_eq!(result, Err(SealError::Cancelled));
    assert!(matches!(raw(&metadata), Err(Error::NoEntry)));
}

#[test]
fn an_unlock_expiring_after_reading_metadata_writes_nothing() {
    let scope = Scope::new("expiring");
    let metadata = scope.record("metadata");
    let waiting = crate::pause::arm(&scope.store.id(), "unlock.waiting");
    let reading = crate::pause::arm(&scope.store.id(), "unlock.metadata");
    let finished = crate::pause::arm(&scope.store.id(), "unlock.finished");
    let window = HiddenWindow::new();
    let budget = Duration::from_millis(300);
    let results = start_unlock(&scope.store, &window, &HelloCancellation::new(), budget);
    // A refused unlock leaves no request, so no thread can reach the armed pause points.
    let Some(owner) = waiting.within(Duration::from_millis(5000)) else {
        let result = results.recv_timeout(crate::pause::BOUND);
        panic!("unlock never reached its pause point: {result:?}");
    };
    let worker = reading.next();
    // The deadline was set before both arrivals, so a full budget from here spends it.
    std::thread::sleep(budget);
    worker.resume();
    finished.next().resume();
    owner.resume();
    let result = results.recv_timeout(crate::pause::BOUND).unwrap();
    assert_eq!(result, Err(SealError::TimedOut));
    assert!(matches!(raw(&metadata), Err(Error::NoEntry)));
}

#[test]
fn an_unlock_on_a_host_without_hello_prf_writes_nothing_and_discard_succeeds() {
    if !matches!(crate::hello::capability(), Err(SealError::Unsupported(_))) {
        eprintln!("skipped: this host does not report Windows Hello PRF as unsupported");
        return;
    }
    let scope = Scope::new("unsupported");
    let window = HiddenWindow::new();
    let result = scope.store.unlock(
        window.handle(),
        &HelloCancellation::new(),
        Duration::from_secs(5),
    );
    assert!(matches!(result, Err(SealError::Unsupported(_))));
    assert!(matches!(
        raw(&scope.record("metadata")),
        Err(Error::NoEntry)
    ));
    assert_eq!(scope.store.discard(DISCARD_TIMEOUT), Ok(()));
}

#[cfg(feature = "search")]
#[test]
fn hello_search_lists_entries_of_this_store_only() {
    let mut scope = Scope::new("search");
    let sealed = SealedStore::new(&scope.application, "search").unwrap();
    scope.store.install_test_key([81; 32]);
    let entry = scope.entry("user");
    entry.set_secret(b"hello").unwrap();
    assert!(
        sealed
            .search(&std::collections::HashMap::new())
            .unwrap()
            .is_empty()
    );
    let found = scope
        .store
        .search(&std::collections::HashMap::new())
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].get_secret().unwrap(), b"hello");
}

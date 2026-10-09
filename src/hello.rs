//! Windows Hello support for sealed stores.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use keyring_core::api::{CredentialPersistence, CredentialStoreApi};
use keyring_core::{Entry, Result};
use sha2::{Digest, Sha256};
use windows_sys::Win32::UI::WindowsAndMessaging::IsWindow;
use zeroize::Zeroizing;

use crate::hello_native::{self, Ceremony, MAX_CREDENTIAL_ID};
pub use crate::hello_native::{DEFAULT_ABORT_INTERVAL, HelloCancellation, HelloWindow};
use crate::sealed::{
    Gate, Kind, Protection, SealError, SealResult, deadline, delete_owned, platform, read_raw,
    remaining, unpoison,
};
use crate::sealed_lock::{lock_target, lock_target_with_timeout};
use crate::utils::{CredPersist, hex, save_credential};

/// Check that Windows Hello can protect a sealed store on this machine, without prompting.
///
/// This needs WebAuthn API 9, a user-verifying platform authenticator, and exactly one
/// Windows Hello entry in the WebAuthn authenticator list. PRF support is only confirmed by
/// the first unlock.
///
/// # Errors
///
/// [`SealError::Unsupported`] when any requirement is missing, [`SealError::Locked`] when
/// Windows Hello is locked, [`SealError::Conflict`] when several Windows Hello authenticators
/// are listed, and [`SealError::Platform`] when WebAuthn fails.
pub fn capability() -> std::result::Result<(), SealError> {
    hello_native::available()
}

const META_MAGIC: &[u8; 5] = b"HPRF1";
const MAX_WAIT: Duration = Duration::from_secs(240);

/// The enrollment record, pending until its credential id is known.
struct Metadata {
    salt: [u8; 32],
    user_id: [u8; 32],
    credential_id: Option<Vec<u8>>,
}

/// One in-flight unlock that every concurrent caller of the same store joins.
struct Request {
    cancellation: HelloCancellation,
    state: Mutex<RequestState>,
    changed: Condvar,
}

/// The request's one terminal decision, and whether its worker has finished.
#[derive(Default)]
struct RequestState {
    decision: Option<SealResult<()>>,
    finished: bool,
}

/// How often waiters recheck their own cancellation token.
const POLL: Duration = Duration::from_millis(50);

impl Request {
    fn new(cancellation: HelloCancellation) -> Self {
        Self {
            cancellation,
            state: Mutex::default(),
            changed: Condvar::new(),
        }
    }

    /// Waits for the decision. The owner's cancel or timeout becomes that decision.
    fn wait(&self, deadline: Instant, caller: &HelloCancellation, owns: bool) -> SealResult<()> {
        let mut state = unpoison(self.state.lock());
        loop {
            if let Some(decision) = &state.decision {
                return decision.clone();
            }
            let abort = if caller.is_cancelled() {
                Some(SealError::Cancelled)
            } else if remaining(deadline).is_zero() {
                Some(SealError::TimedOut)
            } else {
                None
            };
            if let Some(error) = abort {
                if owns {
                    // Recorded under the same mutex as publication, so the worker cannot publish.
                    state.decision = Some(Err(error.clone()));
                    self.changed.notify_all();
                    drop(state);
                    self.cancellation.cancel();
                }
                return Err(error);
            }
            let slice = remaining(deadline).min(POLL);
            state = unpoison(self.changed.wait_timeout(state, slice)).0;
        }
    }

    /// Waits until the worker of an aborted request has finished, then reports it cancelled.
    fn wait_finished(&self, deadline: Instant, caller: &HelloCancellation) -> SealResult<()> {
        let mut state = unpoison(self.state.lock());
        loop {
            if state.finished {
                return Err(SealError::Cancelled);
            }
            if caller.is_cancelled() {
                return Err(SealError::Cancelled);
            }
            if remaining(deadline).is_zero() {
                return Err(SealError::TimedOut);
            }
            let slice = remaining(deadline).min(POLL);
            state = unpoison(self.changed.wait_timeout(state, slice)).0;
        }
    }
}

/// State shared by a `HelloStore` and its in-flight unlock worker.
struct Shared {
    gate: Arc<Gate>,
    rp_id: String,
    active: Mutex<Option<Arc<Request>>>,
}

/// A named store whose entries are sealed under a key from a Windows Hello passkey's PRF.
///
/// One Windows Hello approval in [`HelloStore::unlock`] opens every entry until
/// [`HelloStore::lock`]. The first unlock of an empty store enrolls the passkey.
pub struct HelloStore {
    id: String,
    shared: Arc<Shared>,
}

impl HelloStore {
    /// Create the store named `store` for `application`, starting locked.
    pub fn new(application: &str, store: &str) -> Result<Arc<Self>> {
        let gate = Gate::new(Kind::Hello, application, store)?;
        let id = gate.id();
        let digest = Sha256::digest(id.as_bytes());
        let rp_id = format!("{}.{}.invalid", hex(&digest[..16]), hex(&digest[16..]));
        Ok(Arc::new(Self {
            id,
            shared: Arc::new(Shared {
                gate,
                rp_id,
                active: Mutex::new(None),
            }),
        }))
    }

    /// Unlock with one Windows Hello approval anchored to `owner`, enrolling on first use.
    ///
    /// Concurrent callers share one request. `timeout` is capped at four minutes and covers the
    /// whole call, including any wait behind another operation on the store. When the
    /// caller that started the request cancels or times out, the request ends without
    /// unlocking the store. Any other caller that cancels or times out stops only its own wait.
    ///
    /// Windows may ignore the cancellation of the first unlock, which enrolls the passkey.
    /// The call still returns at once and unlocks nothing, but the Windows Hello prompt can
    /// stay on screen until the user dismisses it, and [`HelloStore::discard`] waits for it
    /// up to its own timeout.
    ///
    /// # Errors
    ///
    /// [`SealError::MissingOwner`] before any prompt if `owner` is not a live window,
    /// [`SealError::Cancelled`] or [`SealError::TimedOut`] if the request ends early,
    /// [`SealError::KeyLost`] if the store's passkey is gone,
    /// [`SealError::Discarding`] or [`SealError::Discarded`] around a discard by any handle, and
    /// [`SealError::Unsupported`] if this machine cannot use Windows Hello PRF.
    pub fn unlock(
        &self,
        owner: Arc<dyn HelloWindow>,
        cancellation: &HelloCancellation,
        timeout: Duration,
    ) -> std::result::Result<(), SealError> {
        // Refuse before any record is touched, ahead of the native check at the prompt.
        // SAFETY: `IsWindow` accepts any handle value, including null or stale handles.
        if unsafe { IsWindow(owner.hwnd()) } == 0 {
            return Err(SealError::MissingOwner);
        }
        let timeout = timeout.min(MAX_WAIT);
        if timeout.is_zero() {
            return Err(SealError::TimedOut);
        }
        self.shared.unlock_with(
            cancellation,
            timeout,
            move |shared, cancellation, deadline| {
                shared.perform_unlock(owner, cancellation, deadline)
            },
        )
    }

    /// Erase the key and cancel any pending Windows Hello request.
    pub fn lock(&self) {
        self.shared.lock();
    }

    /// Delete this store's entries, enrollment and passkey, retiring every existing handle.
    ///
    /// No Windows Hello approval is needed. A discard waits, up to `timeout`, for any Windows
    /// Hello prompt of this store still on screen, including one whose unlock was cancelled.
    ///
    /// # Errors
    ///
    /// [`SealError::TimedOut`] if the store's locks are not free within `timeout`, and
    /// [`SealError::Discarded`] if this handle predates an earlier discard.
    pub fn discard(&self, timeout: Duration) -> std::result::Result<(), SealError> {
        let deadline = deadline(timeout)?;
        let gate = &self.shared.gate;
        let control = gate.control_target();
        let marker = {
            let _store = lock_target_with_timeout(&control, remaining(deadline))?;
            gate.mark_discarding()?
        };
        self.lock();
        let metadata = gate.metadata_target();
        // An unlock holds this lease for its whole ceremony, so the passkey is idle afterwards.
        let _lease = lock_target_with_timeout(&metadata, remaining(deadline))?;
        let _store = lock_target_with_timeout(&control, remaining(deadline))?;
        if !gate.still_discarding(&marker)? {
            return Ok(());
        }
        self.shared.remove_enrollment_credential(&metadata)?;
        gate.delete_entries()?;
        delete_owned(&metadata)?;
        gate.publish_generation()
    }

    /// Report whether this store holds its key, or has lost its passkey.
    pub fn protection(&self) -> Protection {
        self.shared.gate.protection()
    }

    #[cfg(test)]
    pub(crate) fn install_test_key(&self, key: [u8; 32]) {
        self.shared.gate.install_key(key);
    }
}

impl Shared {
    fn lock(&self) {
        self.gate.lock();
        if let Some(request) = unpoison(self.active.lock()).as_ref() {
            request.cancellation.cancel();
        }
    }

    /// Runs `work` as the store's single request, or joins the one already running.
    fn unlock_with<F>(
        self: &Arc<Self>,
        cancellation: &HelloCancellation,
        timeout: Duration,
        work: F,
    ) -> SealResult<()>
    where
        F: FnOnce(&Shared, &HelloCancellation, Instant) -> SealResult<Zeroizing<[u8; 32]>>
            + Send
            + 'static,
    {
        if cancellation.is_cancelled() {
            return Err(SealError::Cancelled);
        }
        // One budget for every stage below, so waiting for the lock leaves less for the request.
        let until = deadline(timeout)?;
        {
            // Publication and discard markers are written under this lock, so the answer holds.
            let _store = lock_target_with_timeout(&self.gate.control_target(), remaining(until))?;
            self.gate.check_control()?;
            if let Some(settled) = self.settled() {
                return settled;
            }
        }
        #[cfg(test)]
        crate::pause::reached(&self.gate.id(), "unlock.joining")?;
        let mut active = unpoison(self.active.lock());
        // A request may have published since the check above, which it did under the control lock.
        if let Some(settled) = self.settled() {
            return settled;
        }
        let (request, owns) = match &*active {
            Some(request) if request.cancellation.is_cancelled() => {
                let request = Arc::clone(request);
                drop(active);
                #[cfg(test)]
                crate::pause::reached(&self.gate.id(), "unlock.waiting")?;
                return request.wait_finished(until, cancellation);
            }
            Some(request) => (Arc::clone(request), false),
            None => {
                if remaining(until).is_zero() {
                    return Err(SealError::TimedOut);
                }
                let request = Arc::new(Request::new(cancellation.clone()));
                *active = Some(Arc::clone(&request));
                let epoch = self.gate.epoch();
                let shared = Arc::clone(self);
                let worker = Arc::clone(&request);
                std::thread::spawn(move || {
                    let result = work(&shared, &worker.cancellation, until);
                    #[cfg(test)]
                    let _ = crate::pause::reached(&shared.gate.id(), "unlock.publication");
                    shared.publish(&worker, epoch, result);
                    shared.retire(&worker);
                    #[cfg(test)]
                    let _ = crate::pause::reached(&shared.gate.id(), "unlock.finished");
                });
                (request, true)
            }
        };
        drop(active);
        #[cfg(test)]
        crate::pause::reached(&self.gate.id(), "unlock.waiting")?;
        request.wait(until, cancellation, owns)
    }

    /// The answer for a store that no longer needs a request.
    fn settled(&self) -> Option<SealResult<()>> {
        match self.gate.protection() {
            Protection::Unlocked => Some(Ok(())),
            Protection::Lost => Some(Err(SealError::KeyLost)),
            Protection::Locked => None,
        }
    }

    /// Records the request's decision, publishing its key only if nothing aborted it first.
    fn publish(&self, request: &Request, epoch: u64, result: SealResult<Zeroizing<[u8; 32]>>) {
        // Under the control lock, so a discard marker is either seen here or written afterwards.
        let store = lock_target(&self.gate.control_target());
        let mut state = unpoison(request.state.lock());
        if state.decision.is_some() {
            return;
        }
        let decision = match &store {
            Err(error) => Err(error.clone()),
            Ok(_) if request.cancellation.is_cancelled() => Err(SealError::Cancelled),
            Ok(_) => self
                .gate
                .check_control()
                .and_then(|()| self.gate.settle(epoch, result)),
        };
        state.decision = Some(decision);
        request.changed.notify_all();
    }

    /// Clears `request` from the store if it is still the active one, then marks it finished.
    fn retire(&self, request: &Arc<Request>) {
        let mut active = unpoison(self.active.lock());
        if active
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, request))
        {
            *active = None;
        }
        drop(active);
        unpoison(request.state.lock()).finished = true;
        request.changed.notify_all();
    }

    fn perform_unlock(
        &self,
        owner: Arc<dyn HelloWindow>,
        cancellation: &HelloCancellation,
        deadline: Instant,
    ) -> SealResult<Zeroizing<[u8; 32]>> {
        let metadata_target = self.gate.metadata_target();
        // Discard waits on this lease before removing enrollment state.
        let _lease = lock_target_with_timeout(&metadata_target, remaining(deadline))?;
        // An owner that gave up during the wait has returned, so nothing may be read or written.
        still_wanted(cancellation, deadline)?;
        self.gate.check_control()?;
        self.open_or_enroll(&metadata_target, owner, cancellation, deadline)
    }

    fn open_or_enroll(
        &self,
        metadata_target: &str,
        owner: Arc<dyn HelloWindow>,
        cancellation: &HelloCancellation,
        deadline: Instant,
    ) -> SealResult<Zeroizing<[u8; 32]>> {
        let stored = read_raw(metadata_target)?;
        #[cfg(test)]
        crate::pause::reached(&self.gate.id(), "unlock.metadata")?;
        if let Some(bytes) = stored {
            let mut metadata = parse_metadata(&bytes)?;
            if metadata.credential_id.is_none() {
                if self.gate.has_scoped_entries()? {
                    return Err(SealError::KeyLost);
                }
                // A failed lookup keeps the record, since the credential may still exist.
                metadata.credential_id =
                    hello_native::recover_created(&self.rp_id, &metadata.user_id)?;
                still_wanted(cancellation, deadline)?;
                match metadata.credential_id {
                    Some(_) => save_metadata(metadata_target, &metadata)?,
                    None => delete_owned(metadata_target)?,
                }
            }
            if let Some(id) = &metadata.credential_id {
                let ceremony = Ceremony::begin(owner, cancellation)?;
                return hello_native::assert_prf(
                    ceremony,
                    &self.rp_id,
                    id,
                    &metadata.salt,
                    cancellation,
                    deadline,
                );
            }
        } else if self.gate.has_scoped_entries()? {
            return Err(SealError::KeyLost);
        }
        still_wanted(cancellation, deadline)?;
        // Preflight before the pending record, so a host that cannot enroll writes nothing.
        let ceremony = Ceremony::begin(owner, cancellation)?;
        still_wanted(cancellation, deadline)?;
        let mut user_id = [0u8; 32];
        let mut salt = [0u8; 32];
        getrandom::fill(&mut user_id).map_err(platform)?;
        getrandom::fill(&mut salt).map_err(platform)?;
        let pending = Metadata {
            salt,
            user_id,
            credential_id: None,
        };
        save_metadata(metadata_target, &pending)?;
        let created = hello_native::enroll(
            ceremony,
            &self.rp_id,
            &user_id,
            &salt,
            cancellation,
            deadline,
        )?;
        let complete = Metadata {
            credential_id: Some(created.credential_id),
            ..pending
        };
        if let Err(error) = save_metadata(metadata_target, &complete) {
            if let Some(id) = &complete.credential_id {
                hello_native::remove_exact(&self.rp_id, id)?;
            }
            delete_owned(metadata_target)?;
            return Err(error);
        }
        Ok(created.key)
    }

    /// Removes the store's passkey, by its recorded id or else by the store's RP.
    fn remove_enrollment_credential(&self, metadata_target: &str) -> SealResult<()> {
        let Some(bytes) = read_raw(metadata_target)? else {
            return hello_native::remove_all_for_rp(&self.rp_id);
        };
        let metadata = match parse_metadata(&bytes) {
            Ok(metadata) => metadata,
            // The RP is derived from this store alone, so it still identifies its passkeys.
            Err(SealError::Corrupt(_)) => return hello_native::remove_all_for_rp(&self.rp_id),
            Err(error) => return Err(error),
        };
        let credential_id = match metadata.credential_id {
            Some(id) => Some(id),
            None => hello_native::recover_created(&self.rp_id, &metadata.user_id)?,
        };
        match credential_id {
            Some(id) => hello_native::remove_exact(&self.rp_id, &id),
            None => Ok(()),
        }
    }
}

impl Drop for HelloStore {
    fn drop(&mut self) {
        self.lock();
    }
}

impl std::fmt::Debug for HelloStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelloStore").field("id", &self.id).finish()
    }
}

impl CredentialStoreApi for HelloStore {
    fn vendor(&self) -> String {
        "Windows Hello PRF, https://crates.io/crates/windows-native-keyring-store".into()
    }

    fn id(&self) -> String {
        self.id.clone()
    }

    fn build(
        &self,
        service: &str,
        user: &str,
        modifiers: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        self.shared.gate.build(service, user, modifiers)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::UntilDelete
    }

    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// Refuses a request whose token was cancelled or whose deadline passed, before its next write.
fn still_wanted(cancellation: &HelloCancellation, deadline: Instant) -> SealResult<()> {
    if cancellation.is_cancelled() {
        Err(SealError::Cancelled)
    } else if remaining(deadline).is_zero() {
        Err(SealError::TimedOut)
    } else {
        Ok(())
    }
}

fn parse_metadata(blob: &[u8]) -> SealResult<Metadata> {
    if blob.len() < 70 || &blob[..5] != META_MAGIC {
        return Err(SealError::Corrupt("invalid enrollment record".into()));
    }
    let salt: [u8; 32] = blob[6..38]
        .try_into()
        .map_err(|_| SealError::Corrupt("invalid salt".into()))?;
    let user_id: [u8; 32] = blob[38..70]
        .try_into()
        .map_err(|_| SealError::Corrupt("invalid user ID".into()))?;
    let credential_id = match blob[5] {
        0 if blob.len() == 70 => None,
        1 if blob.len() >= 73 => {
            let length = usize::from(u16::from_le_bytes([blob[70], blob[71]]));
            if !(1..=MAX_CREDENTIAL_ID).contains(&length) || blob.len() != 72 + length {
                return Err(SealError::Corrupt("invalid credential ID length".into()));
            }
            Some(blob[72..].to_vec())
        }
        _ => return Err(SealError::Corrupt("invalid enrollment state".into())),
    };
    Ok(Metadata {
        salt,
        user_id,
        credential_id,
    })
}

fn save_metadata(target: &str, metadata: &Metadata) -> SealResult<()> {
    let mut bytes = Vec::with_capacity(72 + metadata.credential_id.as_ref().map_or(0, Vec::len));
    bytes.extend_from_slice(META_MAGIC);
    bytes.push(u8::from(metadata.credential_id.is_some()));
    bytes.extend_from_slice(&metadata.salt);
    bytes.extend_from_slice(&metadata.user_id);
    if let Some(id) = &metadata.credential_id {
        let length = u16::try_from(id.len())
            .map_err(|_| SealError::Corrupt("credential ID too long".into()))?;
        if length == 0 || usize::from(length) > MAX_CREDENTIAL_ID {
            return Err(SealError::Corrupt("invalid credential ID length".into()));
        }
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(id);
    }
    save_credential(target, "", "", "", &bytes, &CredPersist::Local).map_err(platform)
}

#[cfg(test)]
impl HelloStore {
    /// Panics unless this fresh store's gate and a new cancellation token behave, so a test
    /// built on either fails at once instead of waiting out its bounds.
    pub(crate) fn assert_usable(&self) {
        let gate = &self.shared.gate;
        gate.assert_usable();
        let metadata = gate.metadata_target();
        assert!(
            metadata.starts_with(&gate.id()),
            "the metadata record {metadata:?} escapes the store prefix"
        );
        let token = HelloCancellation::new();
        assert!(!token.is_cancelled(), "a new token starts cancelled");
        token.cancel();
        assert!(token.is_cancelled(), "a cancelled token reports running");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pause;
    use keyring_core::Error;
    use std::sync::mpsc;

    #[test]
    fn relying_party_identifier_has_valid_dns_label_lengths() {
        let store = HelloStore::new("application", "account").unwrap();
        let rp_id = &store.shared.rp_id;
        assert!(
            rp_id
                .split('.')
                .all(|label| !label.is_empty() && label.len() <= 63)
        );
        assert!(rp_id.ends_with(".invalid"));
    }

    #[test]
    fn the_store_reports_its_windows_hello_vendor() {
        let fresh = Fresh::new();
        assert_eq!(
            fresh.store.vendor(),
            "Windows Hello PRF, https://crates.io/crates/windows-native-keyring-store"
        );
    }

    #[test]
    fn the_store_id_matches_its_gate() {
        let fresh = Fresh::new();
        assert_eq!(fresh.store.id(), fresh.store.shared.gate.id());
    }

    #[test]
    fn enrollment_metadata_round_trips_long_platform_credential_ids() {
        let target = format!("keyring:hello-prf:test:{}", fastrand::u64(..));
        let metadata = Metadata {
            salt: [7; 32],
            user_id: [8; 32],
            credential_id: Some(vec![42; 128]),
        };
        save_metadata(&target, &metadata).unwrap();
        let read = parse_metadata(&read_raw(&target).unwrap().unwrap());
        delete_owned(&target).unwrap();
        let read = read.unwrap();
        assert_eq!(read.salt, [7; 32]);
        assert_eq!(read.user_id, [8; 32]);
        assert_eq!(read.credential_id, Some(vec![42; 128]));
    }

    #[test]
    fn save_metadata_rejects_an_empty_credential_id() {
        let target = format!("keyring:hello-prf:test:{}", fastrand::u64(..));
        let metadata = Metadata {
            salt: [7; 32],
            user_id: [8; 32],
            credential_id: Some(vec![]),
        };
        assert!(matches!(
            save_metadata(&target, &metadata),
            Err(SealError::Corrupt(_))
        ));
    }

    #[test]
    fn save_metadata_round_trips_a_maximal_credential_id() {
        let target = format!("keyring:hello-prf:test:{}", fastrand::u64(..));
        let metadata = Metadata {
            salt: [7; 32],
            user_id: [8; 32],
            credential_id: Some(vec![9; MAX_CREDENTIAL_ID]),
        };
        save_metadata(&target, &metadata).unwrap();
        let read = parse_metadata(&read_raw(&target).unwrap().unwrap());
        delete_owned(&target).unwrap();
        let read = read.unwrap();
        assert_eq!(read.credential_id, Some(vec![9; MAX_CREDENTIAL_ID]));
    }

    #[test]
    fn malformed_enrollment_metadata_is_corrupt() {
        let mut pending = META_MAGIC.to_vec();
        pending.push(0);
        pending.extend([0; 64]);
        assert!(parse_metadata(&pending).is_ok());
        for blob in [
            &pending[..69],
            &[pending.as_slice(), &[0]].concat()[..],
            &[&b"XPRF1"[..], &pending[5..]].concat()[..],
            &[&pending[..5], &[2], &pending[6..]].concat()[..],
            &[&pending[..5], &[1], &pending[6..], &[0, 0, 0]].concat()[..],
            &[&pending[..5], &[1], &pending[6..], &[2, 0, 9]].concat()[..],
            &[&pending[..5], &[1], &pending[6..]].concat()[..],
            &[&pending[..5], &[1], &pending[6..], &[1]].concat()[..],
        ] {
            assert!(matches!(parse_metadata(blob), Err(SealError::Corrupt(_))));
        }
    }

    const REQUEST: u64 = 13;

    type Work = Box<
        dyn FnOnce(&Shared, &HelloCancellation, Instant) -> SealResult<Zeroizing<[u8; 32]>> + Send,
    >;

    /// A Hello store with a fresh name whose records are deleted when the test ends.
    struct Fresh {
        application: String,
        store: Arc<HelloStore>,
    }

    impl Fresh {
        fn new() -> Self {
            let application = format!("hello-unit-{}", fastrand::u64(..));
            let store = HelloStore::new(&application, "store").unwrap();
            store.assert_usable();
            Self { store, application }
        }

        fn reopen(&self) -> Arc<HelloStore> {
            HelloStore::new(&self.application, "store").unwrap()
        }

        fn prefix(&self) -> String {
            self.store.shared.gate.id()
        }
    }

    impl Drop for Fresh {
        fn drop(&mut self) {
            for suffix in ["control", "metadata"] {
                let _ = delete_owned(&format!("{}{suffix}", self.prefix()));
            }
        }
    }

    /// Calls `unlock_with` on a named thread, reporting the result on the returned channel.
    fn start_unlock(
        store: &HelloStore,
        name: &str,
        token: HelloCancellation,
        timeout: Duration,
        work: Work,
    ) -> mpsc::Receiver<SealResult<()>> {
        let (sender, receiver) = mpsc::channel();
        let shared = Arc::clone(&store.shared);
        std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                let _ = sender.send(shared.unlock_with(&token, timeout, work));
            })
            .unwrap();
        receiver
    }

    fn key_work() -> Work {
        Box::new(|_, _, _| Ok(Zeroizing::new([9; 32])))
    }

    fn no_work(reason: &'static str) -> Work {
        Box::new(move |_, _, _| panic!("{reason}"))
    }

    fn lost_work() -> Work {
        Box::new(|_, _, _| Err(SealError::KeyLost))
    }

    /// Starts an owned unlock whose work blocks until `REQUEST` is sent on the returned sender.
    fn hold_unlock(
        store: &HelloStore,
        token: HelloCancellation,
    ) -> (mpsc::Sender<u64>, mpsc::Receiver<SealResult<()>>) {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let results = start_unlock(
            store,
            "owner",
            token,
            pause::BOUND,
            Box::new(move |_, _, _| {
                entered_tx.send(REQUEST).unwrap();
                let released = release_rx
                    .recv_timeout(pause::BOUND)
                    .map_err(|_| SealError::TimedOut)?;
                assert_eq!(released, REQUEST);
                Ok(Zeroizing::new([9; 32]))
            }),
        );
        assert_eq!(entered_rx.recv_timeout(pause::BOUND).unwrap(), REQUEST);
        (release_tx, results)
    }

    fn result(results: &mpsc::Receiver<SealResult<()>>) -> SealResult<()> {
        results.recv_timeout(pause::BOUND).unwrap()
    }

    fn refusal(store: &HelloStore) -> Option<SealError> {
        let entry = store.build("service", "user", None).unwrap();
        match entry.get_secret() {
            Err(Error::NoStorageAccess(reason)) => reason.downcast_ref::<SealError>().cloned(),
            _ => None,
        }
    }

    #[test]
    fn locking_during_unlock_prevents_late_key_publication() {
        let fresh = Fresh::new();
        let (release, results) = hold_unlock(&fresh.store, HelloCancellation::new());
        fresh.store.lock();
        release.send(REQUEST).unwrap();
        assert_eq!(result(&results), Err(SealError::Cancelled));
        assert_eq!(fresh.store.protection(), Protection::Locked);
        assert_eq!(refusal(&fresh.store), Some(SealError::Locked));
    }

    #[test]
    fn a_request_that_finishes_after_lock_cannot_publish() {
        let fresh = Fresh::new();
        let gate = &fresh.store.shared.gate;
        let epoch = gate.epoch();
        gate.lock();
        assert_eq!(
            gate.settle(epoch, Ok(Zeroizing::new([1; 32]))),
            Err(SealError::Cancelled)
        );
        assert_eq!(fresh.store.protection(), Protection::Locked);
    }

    #[test]
    fn a_lock_before_the_request_cannot_block_its_publication() {
        let fresh = Fresh::new();
        let finished = pause::arm(&fresh.prefix(), "unlock.finished");
        fresh.store.lock();
        let ok = start_unlock(
            &fresh.store,
            "owner",
            HelloCancellation::new(),
            pause::BOUND,
            key_work(),
        );
        finished.next().resume();
        assert_eq!(result(&ok), Ok(()));
        assert_eq!(fresh.store.protection(), Protection::Unlocked);
        fresh.store.lock();
    }

    #[test]
    fn cancelling_an_inflight_unlock_keeps_the_store_locked() {
        let fresh = Fresh::new();
        let finished = pause::arm(&fresh.prefix(), "unlock.finished");
        let token = HelloCancellation::new();
        let (release, results) = hold_unlock(&fresh.store, token.clone());
        token.cancel();
        assert_eq!(result(&results), Err(SealError::Cancelled));
        release.send(REQUEST).unwrap();
        finished.next().resume();
        assert_eq!(fresh.store.protection(), Protection::Locked);
    }

    #[test]
    fn owner_cancel_at_publication_never_publishes() {
        let fresh = Fresh::new();
        let publication = pause::arm(&fresh.prefix(), "unlock.publication");
        let finished = pause::arm(&fresh.prefix(), "unlock.finished");
        let token = HelloCancellation::new();
        let owner = start_unlock(
            &fresh.store,
            "owner",
            token.clone(),
            pause::BOUND,
            key_work(),
        );
        let paused = publication.next();
        token.cancel();
        assert_eq!(result(&owner), Err(SealError::Cancelled));
        paused.resume();
        finished.next().resume();
        assert_eq!(fresh.store.protection(), Protection::Locked);
        assert_eq!(refusal(&fresh.store), Some(SealError::Locked));
    }

    #[test]
    fn an_owner_cancelled_before_it_waits_never_publishes() {
        let fresh = Fresh::new();
        let waiting = pause::arm(&fresh.prefix(), "unlock.waiting");
        let publication = pause::arm(&fresh.prefix(), "unlock.publication");
        let finished = pause::arm(&fresh.prefix(), "unlock.finished");
        let token = HelloCancellation::new();
        let owner = start_unlock(
            &fresh.store,
            "owner",
            token.clone(),
            pause::BOUND,
            key_work(),
        );
        let owner_paused = waiting.next();
        let worker_paused = publication.next();
        // No decision is recorded yet, so only the worker can see this cancel.
        token.cancel();
        worker_paused.resume();
        finished.next().resume();
        owner_paused.resume();
        assert_eq!(result(&owner), Err(SealError::Cancelled));
        assert_eq!(fresh.store.protection(), Protection::Locked);
        assert_eq!(refusal(&fresh.store), Some(SealError::Locked));
    }

    #[test]
    fn a_budget_spent_before_the_request_starts_no_request() {
        let fresh = Fresh::new();
        let joining = pause::arm(&fresh.prefix(), "unlock.joining");
        let (ran, runs) = mpsc::channel();
        let budget = Duration::from_millis(200);
        let owner = start_unlock(
            &fresh.store,
            "owner",
            HelloCancellation::new(),
            budget,
            Box::new(move |_, _, _| {
                ran.send(()).unwrap();
                Ok(Zeroizing::new([9; 32]))
            }),
        );
        let paused = joining.next();
        // The owner computed its deadline before this arrival, so a full budget from here spends it.
        std::thread::sleep(budget);
        paused.resume();
        assert_eq!(result(&owner), Err(SealError::TimedOut));
        assert!(runs.try_recv().is_err());
        assert_eq!(fresh.store.protection(), Protection::Locked);
    }

    #[test]
    fn owner_timeout_at_publication_never_publishes() {
        let fresh = Fresh::new();
        let publication = pause::arm(&fresh.prefix(), "unlock.publication");
        let finished = pause::arm(&fresh.prefix(), "unlock.finished");
        let owner = start_unlock(
            &fresh.store,
            "owner",
            HelloCancellation::new(),
            Duration::from_millis(200),
            key_work(),
        );
        let paused = publication.next();
        assert_eq!(result(&owner), Err(SealError::TimedOut));
        paused.resume();
        finished.next().resume();
        assert_eq!(fresh.store.protection(), Protection::Locked);
        assert_eq!(refusal(&fresh.store), Some(SealError::Locked));
    }

    #[test]
    fn an_unlocked_handle_retired_by_another_handle_reports_discarded() {
        let fresh = Fresh::new();
        fresh.store.install_test_key([5; 32]);
        fresh.reopen().discard(pause::BOUND).unwrap();
        let again = fresh.store.shared.unlock_with(
            &HelloCancellation::new(),
            pause::BOUND,
            no_work("a retired handle must not start a request"),
        );
        assert_eq!(again, Err(SealError::Discarded));
    }

    #[test]
    fn a_lost_handle_retired_by_another_handle_reports_discarded() {
        let fresh = Fresh::new();
        let lost =
            fresh
                .store
                .shared
                .unlock_with(&HelloCancellation::new(), pause::BOUND, lost_work());
        assert_eq!(lost, Err(SealError::KeyLost));
        fresh.reopen().discard(pause::BOUND).unwrap();
        let again = fresh.store.shared.unlock_with(
            &HelloCancellation::new(),
            pause::BOUND,
            no_work("a retired handle must not start a request"),
        );
        assert_eq!(again, Err(SealError::Discarded));
    }

    #[test]
    fn a_discard_between_the_final_check_and_publication_never_publishes() {
        let fresh = Fresh::new();
        let publication = pause::arm(&fresh.prefix(), "unlock.publication");
        let finished = pause::arm(&fresh.prefix(), "unlock.finished");
        let owner = start_unlock(
            &fresh.store,
            "owner",
            HelloCancellation::new(),
            pause::BOUND,
            key_work(),
        );
        let paused = publication.next();
        fresh.reopen().discard(pause::BOUND).unwrap();
        paused.resume();
        finished.next().resume();
        assert_eq!(result(&owner), Err(SealError::Discarded));
        assert_eq!(fresh.store.protection(), Protection::Locked);
        assert_eq!(refusal(&fresh.store), Some(SealError::Discarded));
    }

    #[test]
    fn a_caller_paused_across_completion_starts_no_second_request() {
        let fresh = Fresh::new();
        let (release, first) = hold_unlock(&fresh.store, HelloCancellation::new());
        let joining = pause::arm(&fresh.prefix(), "unlock.joining");
        let finished = pause::arm(&fresh.prefix(), "unlock.finished");
        let (second_started, started) = mpsc::channel();
        let late = start_unlock(
            &fresh.store,
            "late",
            HelloCancellation::new(),
            pause::BOUND,
            Box::new(move |_, _, _| {
                second_started.send(REQUEST).unwrap();
                Ok(Zeroizing::new([7; 32]))
            }),
        );
        let paused = joining.next();
        release.send(REQUEST).unwrap();
        assert_eq!(result(&first), Ok(()));
        finished.next().resume();
        paused.resume();
        assert_eq!(result(&late), Ok(()));
        assert!(started.try_recv().is_err(), "a second request started");
        fresh.store.lock();
    }

    #[test]
    fn a_joiner_receives_the_result_of_a_request_completing_while_it_joins() {
        let fresh = Fresh::new();
        let (release, first) = hold_unlock(&fresh.store, HelloCancellation::new());
        let waiting = pause::arm(&fresh.prefix(), "unlock.waiting");
        let finished = pause::arm(&fresh.prefix(), "unlock.finished");
        let joiner = start_unlock(
            &fresh.store,
            "joiner",
            HelloCancellation::new(),
            pause::BOUND,
            no_work("a joining caller must not start a second request"),
        );
        let joined = waiting.next();
        release.send(REQUEST).unwrap();
        assert_eq!(result(&first), Ok(()));
        finished.next().resume();
        joined.resume();
        assert_eq!(result(&joiner), Ok(()));
        assert_eq!(fresh.store.protection(), Protection::Unlocked);
        fresh.store.lock();
    }

    #[test]
    fn a_joiner_that_gives_up_leaves_the_owners_request_running() {
        let fresh = Fresh::new();
        let (release, first) = hold_unlock(&fresh.store, HelloCancellation::new());
        let waiting = pause::arm(&fresh.prefix(), "unlock.waiting");
        let token = HelloCancellation::new();
        let joiner = start_unlock(
            &fresh.store,
            "joiner",
            token.clone(),
            pause::BOUND,
            no_work("a joining caller must not start a second request"),
        );
        waiting.next().resume();
        token.cancel();
        assert_eq!(result(&joiner), Err(SealError::Cancelled));
        release.send(REQUEST).unwrap();
        assert_eq!(result(&first), Ok(()));
        assert_eq!(fresh.store.protection(), Protection::Unlocked);
        fresh.store.lock();
    }

    #[test]
    fn a_caller_arriving_after_the_owner_aborted_waits_it_out_and_is_cancelled() {
        let fresh = Fresh::new();
        let token = HelloCancellation::new();
        let (release, first) = hold_unlock(&fresh.store, token.clone());
        token.cancel();
        assert_eq!(result(&first), Err(SealError::Cancelled));
        let waiting = pause::arm(&fresh.prefix(), "unlock.waiting");
        let late = start_unlock(
            &fresh.store,
            "late",
            HelloCancellation::new(),
            pause::BOUND,
            no_work("an aborted request must be waited out, not replaced"),
        );
        waiting.next().resume();
        // The aborted request's worker is still in its ceremony, so the late caller keeps waiting.
        assert!(
            late.recv_timeout(Duration::from_millis(200)).is_err(),
            "the late caller returned before the aborted request finished"
        );
        release.send(REQUEST).unwrap();
        assert_eq!(result(&late), Err(SealError::Cancelled));
        assert_eq!(fresh.store.protection(), Protection::Locked);
    }

    #[test]
    fn a_lost_passkey_marks_the_store_lost() {
        let fresh = Fresh::new();
        let finished = pause::arm(&fresh.prefix(), "unlock.finished");
        let lost = start_unlock(
            &fresh.store,
            "owner",
            HelloCancellation::new(),
            pause::BOUND,
            lost_work(),
        );
        finished.next().resume();
        assert_eq!(result(&lost), Err(SealError::KeyLost));
        assert_eq!(fresh.store.protection(), Protection::Lost);
        assert_eq!(refusal(&fresh.store), Some(SealError::KeyLost));
        let again = fresh.store.shared.unlock_with(
            &HelloCancellation::new(),
            Duration::from_millis(1000),
            no_work("a lost store must not start another request"),
        );
        assert_eq!(again, Err(SealError::KeyLost));
    }

    #[test]
    fn discarding_during_unlock_never_publishes_a_key() {
        let fresh = Fresh::new();
        let (release, results) = hold_unlock(&fresh.store, HelloCancellation::new());
        let discarded = fresh.store.discard(pause::BOUND);
        release.send(REQUEST).unwrap();
        assert_eq!(result(&results), Err(SealError::Cancelled));
        assert_eq!(discarded, Ok(()));
        assert_eq!(fresh.store.protection(), Protection::Locked);
        assert_eq!(refusal(&fresh.store), Some(SealError::Discarded));
    }
}

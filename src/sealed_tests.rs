use std::collections::HashMap;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use keyring_core::{Entry, Error, api::CredentialStoreApi};

use crate::pause;
use crate::sealed::{
    MAX_PROTECTED_PLAINTEXT, Protection, SealError, scoped_canonical, validate_protected_plaintext,
};
use crate::utils::{
    FoldedName, delete_credential, extract_from_credential, extract_secret, save_credential,
    validate_spelling,
};
use crate::{CredPersist, SealedStore, Store};

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

/// A store with a fresh name whose records are deleted when the test ends.
struct Scope {
    application: String,
    name: String,
    store: Arc<SealedStore>,
    targets: Vec<String>,
}

impl Scope {
    fn new() -> Self {
        Self::named(format!("sealed-test-{}", fastrand::u64(..)), "store")
    }

    fn named(application: String, name: &str) -> Self {
        let store = SealedStore::new(&application, name).unwrap();
        assert_store_id(&store);
        store.assert_usable();
        Self {
            store,
            application,
            name: name.into(),
            targets: Vec::new(),
        }
    }

    fn sibling(&self, name: &str) -> Self {
        Self::named(self.application.clone(), name)
    }

    fn reopen(&self) -> Arc<SealedStore> {
        SealedStore::new(&self.application, &self.name).unwrap()
    }

    fn entry(&mut self, user: &str) -> Entry {
        let entry = self.store.build("service", user, None).unwrap();
        self.targets.push(target_of(&entry));
        entry
    }

    fn keycheck(&self) -> String {
        format!("{}keycheck", self.store.id())
    }

    fn control(&self) -> String {
        format!("{}control", self.store.id())
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        for target in self
            .targets
            .iter()
            .chain([&self.keycheck(), &self.control()])
        {
            let _ = delete_credential(target);
        }
    }
}

fn refused_with<T>(result: keyring_core::Result<T>, expected: &SealError) -> bool {
    match result {
        Err(Error::NoStorageAccess(reason)) => reason.downcast_ref::<SealError>() == Some(expected),
        _ => false,
    }
}

/// The store id names the namespace of the store's records, which every test derives from.
fn assert_store_id(store: &SealedStore) {
    let id = store.id();
    assert!(
        id.starts_with("keyring:sealed:1:"),
        "the store id names its record namespace, got {id:?}"
    );
}

#[test]
fn locked_store_refuses_secret_operations() {
    let mut scope = Scope::new();
    let entry = scope.entry("user");
    assert_eq!(scope.store.protection(), Protection::Locked);
    assert!(refused_with(entry.get_secret(), &SealError::Locked));
    assert!(refused_with(
        entry.set_secret(b"secret"),
        &SealError::Locked
    ));
    assert!(refused_with(entry.get_attributes(), &SealError::Locked));
    assert!(matches!(raw(&target_of(&entry)), Err(Error::NoEntry)));
}

#[test]
fn targets_are_scoped_and_entries_require_local_persistence() {
    let first = SealedStore::new("an", "account").unwrap();
    let second = SealedStore::new("a", "naccount").unwrap();
    let first_target = target_of(&first.build("svc", "user", None).unwrap());
    assert_ne!(
        first_target,
        target_of(&second.build("svc", "user", None).unwrap())
    );
    assert!(first_target.starts_with(&first.id()));
    let reopened = SealedStore::new("an", "account").unwrap();
    assert_eq!(first.id(), reopened.id());
    assert_eq!(
        first_target,
        target_of(&reopened.build("svc", "user", None).unwrap())
    );
    for modifiers in [
        HashMap::from([("persistence", "Enterprise")]),
        HashMap::from([("persistence", "Session")]),
        HashMap::from([("target", "outside-namespace")]),
    ] {
        assert!(matches!(
            first.build("svc", "user", Some(&modifiers)),
            Err(Error::Invalid(_, _))
        ));
    }
    assert!(SealedStore::new("", "account").is_err());
    assert!(matches!(
        first.persistence(),
        keyring_core::api::CredentialPersistence::UntilDelete
    ));
}

#[test]
fn round_trip_stores_only_ciphertext_bound_to_the_store() {
    let mut scope = Scope::new();
    scope.store.unlock(&[3; 32]).unwrap();
    assert_eq!(scope.store.protection(), Protection::Unlocked);
    let entry = scope.entry("alice");
    entry.set_password("refresh-token").unwrap();
    assert_eq!(entry.get_password().unwrap(), "refresh-token");
    assert_eq!(entry.get_attributes().unwrap()["username"], "alice");

    let stored = raw(&target_of(&entry)).unwrap();
    assert!(crate::sealed_crypto::is_protected(&stored));
    let plain: Vec<u8> = "refresh-token"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert!(!stored.windows(plain.len()).any(|window| window == plain));

    scope.store.lock();
    assert!(refused_with(entry.get_password(), &SealError::Locked));
}

#[test]
fn wrong_key_leaves_the_store_locked_and_writes_nothing() {
    let mut scope = Scope::new();
    scope.store.unlock(&[5; 32]).unwrap();
    let entry = scope.entry("user");
    entry.set_secret(b"sealed").unwrap();
    scope.store.lock();
    let target = target_of(&entry);
    let (entry_before, keycheck_before) = (raw(&target).unwrap(), raw(&scope.keycheck()).unwrap());

    let other = scope.reopen();
    assert_eq!(other.unlock(&[6; 32]), Err(SealError::WrongKey));
    assert_eq!(other.protection(), Protection::Locked);
    assert_eq!(raw(&target).unwrap(), entry_before);
    assert_eq!(raw(&scope.keycheck()).unwrap(), keycheck_before);

    other.unlock(&[5; 32]).unwrap();
    let reopened = other.build("service", "user", None).unwrap();
    assert_eq!(reopened.get_secret().unwrap(), b"sealed");
}

#[test]
fn missing_or_unsealed_keycheck_with_entries_is_corrupt() {
    let mut scope = Scope::new();
    scope.store.unlock(&[8; 32]).unwrap();
    let entry = scope.entry("user");
    entry.set_secret(b"sealed").unwrap();
    scope.store.lock();

    delete_credential(&scope.keycheck()).unwrap();
    assert!(matches!(
        scope.store.unlock(&[8; 32]),
        Err(SealError::Corrupt(_))
    ));
    write_raw(&scope.keycheck(), b"plain");
    assert!(matches!(
        scope.store.unlock(&[8; 32]),
        Err(SealError::Corrupt(_))
    ));
    assert_eq!(scope.store.protection(), Protection::Locked);
    assert_eq!(raw(&scope.keycheck()).unwrap(), b"plain");
}

#[test]
fn tampered_ciphertext_never_returns_plaintext() {
    let mut scope = Scope::new();
    scope.store.unlock(&[41; 32]).unwrap();
    let entry = scope.entry("credential");
    entry.set_secret(b"sealed-token").unwrap();
    let target = target_of(&entry);

    let ordinary = Store::new()
        .unwrap()
        .build(
            "ignored",
            "ignored",
            Some(&HashMap::from([("target", target.as_str())])),
        )
        .unwrap();
    assert!(matches!(
        ordinary.get_password(),
        Err(Error::BadStoreFormat(_))
    ));

    let mut stored = raw(&target).unwrap();
    let last = stored.len() - 1;
    stored[last] ^= 0x80;
    write_raw(&target, &stored);
    assert!(matches!(entry.get_secret(), Err(Error::BadStoreFormat(_))));
}

#[test]
fn writes_never_overwrite_an_unsealed_scoped_record() {
    let mut scope = Scope::new();
    scope.store.unlock(&[9; 32]).unwrap();
    let entry = scope.entry("user");
    let target = target_of(&entry);
    write_raw(&target, b"planted");
    assert!(matches!(
        entry.set_secret(b"replacement"),
        Err(Error::BadStoreFormat(_))
    ));
    assert!(matches!(entry.get_secret(), Err(Error::BadStoreFormat(_))));
    assert_eq!(raw(&target).unwrap(), b"planted");
}

#[test]
fn rewriting_a_secret_keeps_its_attributes() {
    let mut scope = Scope::new();
    scope.store.unlock(&[10; 32]).unwrap();
    let entry = scope.entry("user");
    entry.set_secret(b"first").unwrap();
    entry
        .update_attributes(&HashMap::from([
            ("comment", "kept"),
            ("username", "renamed"),
        ]))
        .unwrap();
    entry.set_secret(b"second").unwrap();
    let attributes = entry.get_attributes().unwrap();
    assert_eq!(attributes["comment"], "kept");
    assert_eq!(attributes["username"], "renamed");
    assert_eq!(entry.get_secret().unwrap(), b"second");
}

#[test]
fn dropping_the_store_locks_retained_entries() {
    let mut scope = Scope::new();
    scope.store.unlock(&[71; 32]).unwrap();
    let entry = scope.entry("user");
    let reopened = scope.reopen();
    let store = std::mem::replace(&mut scope.store, reopened);
    drop(store);
    assert!(refused_with(
        entry.set_secret(b"secret"),
        &SealError::Locked
    ));
}

#[test]
fn locked_delete_removes_the_entry_and_absent_entries_report_no_entry() {
    let mut scope = Scope::new();
    scope.store.unlock(&[44; 32]).unwrap();
    let entry = scope.entry("user");
    entry.set_secret(b"sealed").unwrap();
    scope.store.lock();
    entry.delete_credential().unwrap();
    assert!(matches!(raw(&target_of(&entry)), Err(Error::NoEntry)));
    assert!(matches!(entry.delete_credential(), Err(Error::NoEntry)));
}

#[test]
fn secrets_up_to_the_sealed_capacity_round_trip_and_larger_ones_are_refused() {
    // Credential Manager holds 2,560 bytes, and sealing adds 31.
    const CAPACITY: usize = 2560 - 31;
    let mut scope = Scope::new();
    scope.store.unlock(&[11; 32]).unwrap();
    let entry = scope.entry("user");
    let largest = vec![0x5A; CAPACITY];
    entry.set_secret(&largest).unwrap();
    assert_eq!(entry.get_secret().unwrap(), largest);
    assert!(matches!(
        entry.set_secret(&[0x5A; CAPACITY + 1]),
        Err(Error::TooLong(_, limit)) if limit as usize == CAPACITY
    ));
    assert_eq!(entry.get_secret().unwrap(), largest);
}

#[test]
fn seal_errors_map_to_keyring_error_kinds() {
    assert!(matches!(
        Error::from(SealError::Corrupt("record".into())),
        Error::BadStoreFormat(_)
    ));
    assert!(matches!(
        Error::from(SealError::Unsupported("webauthn".into())),
        Error::NotSupportedByStore(_)
    ));
    for error in [
        SealError::Platform("service".into()),
        SealError::Conflict("authenticators".into()),
    ] {
        assert!(matches!(Error::from(error), Error::PlatformFailure(_)));
    }
    for error in [
        SealError::Locked,
        SealError::WrongKey,
        SealError::TimedOut,
        SealError::Discarding,
        SealError::Discarded,
        SealError::MissingOwner,
        SealError::Cancelled,
        SealError::KeyLost,
    ] {
        assert!(matches!(Error::from(error), Error::NoStorageAccess(_)));
    }
}

#[test]
fn the_store_lock_is_released_after_unlock() {
    let scope = Scope::new();
    scope.store.unlock(&[12; 32]).unwrap();
    let application = scope.application.clone();
    let unlocked = std::thread::spawn(move || {
        SealedStore::new(&application, "store")
            .unwrap()
            .unlock(&[12; 32])
    })
    .join()
    .unwrap();
    assert_eq!(unlocked, Ok(()));
}

#[test]
fn a_second_process_shares_the_store_and_its_locks() {
    const CHILD: &str = "SEALED_TESTS_CHILD";
    if let Ok(request) = std::env::var(CHILD) {
        let (held, application) = request.split_once(':').unwrap();
        let store = SealedStore::new(application, "store").unwrap();
        let probe = format!("{}probe", store.id());
        if held == "held" {
            let attempt = crate::sealed_lock::lock_target_with_timeout(
                &probe,
                std::time::Duration::from_millis(300),
            );
            assert!(matches!(attempt, Err(SealError::TimedOut)));
        } else {
            assert_eq!(store.unlock(&[14; 32]), Err(SealError::WrongKey));
            store.unlock(&[13; 32]).unwrap();
        }
        return;
    }
    let child = |request: String| {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sealed_tests::a_second_process_shares_the_store_and_its_locks",
                "--test-threads",
                "1",
            ])
            .env(CHILD, request)
            .status()
            .unwrap()
            .success()
    };
    let scope = Scope::new();
    scope.store.unlock(&[13; 32]).unwrap();
    let probe = crate::sealed_lock::lock_target(&format!("{}probe", scope.store.id())).unwrap();
    assert!(child(format!("held:{}", scope.application)));
    drop(probe);
    assert!(child(format!("free:{}", scope.application)));
}

#[test]
fn malformed_keycheck_records_are_corrupt_not_a_wrong_key() {
    let scope = Scope::new();
    scope.store.unlock(&[31; 32]).unwrap();
    scope.store.lock();
    let intact = raw(&scope.keycheck()).unwrap();
    let mut unsupported = intact.clone();
    unsupported[2] = 2;
    for (label, record) in [("truncated", &intact[..20]), ("unsupported", &unsupported)] {
        write_raw(&scope.keycheck(), record);
        let result = scope.reopen().unlock(&[31; 32]);
        assert!(
            matches!(result, Err(SealError::Corrupt(_))),
            "{label} keycheck gave {result:?}"
        );
    }
    write_raw(&scope.keycheck(), &intact);
    assert_eq!(scope.reopen().unlock(&[32; 32]), Err(SealError::WrongKey));
    assert_eq!(scope.reopen().unlock(&[31; 32]), Ok(()));
}

#[test]
fn spellings_credential_manager_matches_open_one_sealed_entry() {
    let mut scope = Scope::new();
    scope.store.unlock(&[91; 32]).unwrap();
    let first = scope.entry("Alice");
    first.set_password("one").unwrap();
    let second = scope.entry("ALICE");
    assert_eq!(second.get_password().unwrap(), "one");
    second.set_password("two").unwrap();
    assert_eq!(first.get_password().unwrap(), "two");
}

#[test]
fn spellings_credential_manager_keeps_apart_stay_separate_entries() {
    let mut scope = Scope::new();
    scope.store.unlock(&[92; 32]).unwrap();
    // Credential Manager folds `s` to `S` but leaves the long s `ſ` alone.
    scope.entry("\u{17f}").set_password("long").unwrap();
    assert!(matches!(
        scope.entry("s").get_password(),
        Err(Error::NoEntry)
    ));
}

#[test]
fn the_store_id_names_the_namespace_of_its_records() {
    let store = SealedStore::new("an", "account").unwrap();
    assert_store_id(&store);
}

#[test]
fn the_store_reports_its_vendor() {
    let store = SealedStore::new("an", "account").unwrap();
    assert_eq!(
        store.vendor(),
        "Windows sealed store, https://crates.io/crates/windows-native-keyring-store"
    );
}

#[test]
fn spellings_longer_than_the_attribute_capacity_are_refused() {
    let capacity = 64 * 256;
    assert!(validate_spelling(&"s".repeat(capacity)).is_ok());
    assert!(matches!(
        validate_spelling(&"s".repeat(capacity + 1)),
        Err(Error::TooLong(_, 16_384))
    ));
}

#[test]
fn only_ascii_scoped_targets_pass_the_canonical_filter() {
    let entry_prefix = "keyring:sealed:1:2:an:5:store:entry:";
    let scoped = format!("{entry_prefix}deadbeef");
    let folded = FoldedName::new(&scoped).unwrap();
    assert_eq!(
        scoped_canonical(&folded, entry_prefix).unwrap(),
        scoped.to_ascii_lowercase()
    );

    let outside = FoldedName::new("other:entry:deadbeef").unwrap();
    assert!(matches!(
        scoped_canonical(&outside, entry_prefix),
        Err(SealError::Corrupt(_))
    ));

    let accented = format!("{entry_prefix}caf\u{00e9}");
    let folded = FoldedName::new(&accented).unwrap();
    assert!(!folded.as_str().is_ascii());
    assert!(matches!(
        scoped_canonical(&folded, entry_prefix),
        Err(SealError::Corrupt(_))
    ));
}

#[test]
fn plaintexts_up_to_the_protected_capacity_pass_and_longer_ones_are_refused() {
    assert!(validate_protected_plaintext(&[0; MAX_PROTECTED_PLAINTEXT - 1]).is_ok());
    assert!(validate_protected_plaintext(&[0; MAX_PROTECTED_PLAINTEXT]).is_ok());
    assert!(matches!(
        validate_protected_plaintext(&[0; MAX_PROTECTED_PLAINTEXT + 1]),
        Err(Error::TooLong(_, limit))
            if usize::try_from(limit).expect("u32 fits usize") == MAX_PROTECTED_PLAINTEXT
    ));
}

const DISCARD_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound for every wait on a paused discarder, so a refused discard ends the test promptly.
const DISCARD_WAIT: Duration = Duration::from_secs(4);

#[test]
fn discard_retires_every_handle_and_spares_a_sibling_store() {
    let mut scope = Scope::new();
    let mut sibling = scope.sibling("other");
    scope.store.unlock(&[21; 32]).unwrap();
    sibling.store.unlock(&[21; 32]).unwrap();
    let entry = scope.entry("user");
    entry.set_secret(b"discarded").unwrap();
    let kept = sibling.entry("user");
    kept.set_secret(b"kept").unwrap();
    let second = scope.reopen();
    second.unlock(&[21; 32]).unwrap();
    let second_entry = second.build("service", "user", None).unwrap();

    scope.store.discard(DISCARD_TIMEOUT).unwrap();

    assert_eq!(scope.store.protection(), Protection::Locked);
    assert!(refused_with(entry.get_secret(), &SealError::Discarded));
    assert!(refused_with(
        second_entry.get_secret(),
        &SealError::Discarded
    ));
    assert!(refused_with(
        second_entry.delete_credential(),
        &SealError::Discarded
    ));
    assert_eq!(second.unlock(&[21; 32]), Err(SealError::Discarded));
    assert_eq!(
        scope.store.discard(DISCARD_TIMEOUT),
        Err(SealError::Discarded)
    );
    assert!(matches!(raw(&target_of(&entry)), Err(Error::NoEntry)));
    assert!(matches!(raw(&scope.keycheck()), Err(Error::NoEntry)));
    assert_eq!(kept.get_secret().unwrap(), b"kept");

    let fresh = scope.reopen();
    fresh.unlock(&[22; 32]).unwrap();
    let reborn = fresh.build("service", "user", None).unwrap();
    assert!(matches!(reborn.get_secret(), Err(Error::NoEntry)));
    reborn.set_secret(b"second generation").unwrap();

    scope.reopen().discard(DISCARD_TIMEOUT).unwrap();
    assert!(refused_with(reborn.get_secret(), &SealError::Discarded));
}

#[test]
fn corrupt_control_record_blocks_the_store_until_discard() {
    let mut scope = Scope::new();
    scope.store.unlock(&[23; 32]).unwrap();
    let entry = scope.entry("user");
    entry.set_secret(b"sealed").unwrap();
    write_raw(&scope.control(), b"garbage");

    let blocked = scope.reopen();
    assert_eq!(blocked.unlock(&[23; 32]), Err(SealError::Discarding));
    assert!(refused_with(entry.get_secret(), &SealError::Discarding));
    blocked.discard(DISCARD_TIMEOUT).unwrap();
    assert!(matches!(raw(&target_of(&entry)), Err(Error::NoEntry)));
    scope.reopen().unlock(&[24; 32]).unwrap();
}

#[test]
fn an_interrupted_discard_blocks_until_any_handle_resumes_it() {
    let mut scope = Scope::new();
    scope.store.unlock(&[25; 32]).unwrap();
    let entry = scope.entry("user");
    entry.set_secret(b"sealed").unwrap();
    let mut marker = crate::sealed::CONTROL_MAGIC.to_vec();
    marker.push(1);
    marker.extend([7; 16]);
    write_raw(&scope.control(), &marker);

    assert!(refused_with(
        entry.set_secret(b"replacement"),
        &SealError::Discarding
    ));
    assert!(refused_with(
        entry.delete_credential(),
        &SealError::Discarding
    ));
    assert_eq!(scope.store.unlock(&[25; 32]), Err(SealError::Discarding));
    scope.store.discard(DISCARD_TIMEOUT).unwrap();
    assert!(matches!(raw(&target_of(&entry)), Err(Error::NoEntry)));
    assert!(matches!(raw(&scope.keycheck()), Err(Error::NoEntry)));
    scope.reopen().unlock(&[26; 32]).unwrap();
}

#[test]
fn discard_times_out_on_a_held_store_lock_and_succeeds_once_released() {
    let scope = Scope::new();
    let control = scope.control();
    let (held, holding) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        let _lock = crate::sealed_lock::lock_target(&control).unwrap();
        held.send(()).unwrap();
        released.recv_timeout(crate::pause::BOUND).unwrap();
    });
    holding.recv_timeout(crate::pause::BOUND).unwrap();
    assert_eq!(
        scope.store.discard(Duration::from_millis(200)),
        Err(SealError::TimedOut)
    );
    release.send(()).unwrap();
    holder.join().unwrap();
    assert_eq!(scope.store.discard(DISCARD_TIMEOUT), Ok(()));
}

#[test]
fn a_deleted_control_record_never_revives_a_retired_generation() {
    let mut scope = Scope::new();
    scope.store.discard(DISCARD_TIMEOUT).unwrap();
    let current = scope.reopen();
    current.unlock(&[27; 32]).unwrap();
    let entry = current.build("service", "user", None).unwrap();
    scope.targets.push(target_of(&entry));
    delete_credential(&scope.control()).unwrap();

    assert!(refused_with(entry.get_secret(), &SealError::Discarded));
    assert_eq!(current.discard(DISCARD_TIMEOUT), Err(SealError::Discarded));
}

/// Runs `discard` on a named thread, reporting its result on `results`.
fn spawn_discard(
    store: Arc<SealedStore>,
    name: &'static str,
    results: &mpsc::Sender<(&'static str, Result<(), SealError>)>,
) {
    let results = results.clone();
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            results
                .send((name, store.discard(DISCARD_TIMEOUT)))
                .unwrap()
        })
        .unwrap();
}

/// The next arrival at `point` within `DISCARD_WAIT`, failing fast if the discarder finished first.
fn arrival_of(
    point: &pause::Arrivals,
    finished: &mpsc::Receiver<(&'static str, Result<(), SealError>)>,
    what: &str,
) -> pause::Arrival {
    let deadline = Instant::now() + DISCARD_WAIT;
    loop {
        if let Some(arrival) = point.within(Duration::from_millis(50)) {
            return arrival;
        }
        if let Ok((name, result)) = finished.try_recv() {
            panic!("{what} ended before its pause point: {name} {result:?}");
        }
        assert!(
            Instant::now() < deadline,
            "{what} never reached its pause point"
        );
    }
}

#[test]
fn overlapping_discarders_never_delete_the_next_generation() {
    let mut scope = Scope::new();
    scope.store.unlock(&[41; 32]).unwrap();
    scope.entry("user").set_secret(b"old generation").unwrap();
    let prefix = scope.store.id();
    let entered = pause::arm(&prefix, "discard.entered");
    let deleting = pause::arm(&prefix, "discard.deleting");
    let (results, finished) = mpsc::channel();

    spawn_discard(Arc::clone(&scope.store), "first", &results);
    let first_entered = entered.next();
    assert_eq!(first_entered.thread.as_deref(), Some("first"));
    first_entered.resume();
    let first_deleting = arrival_of(&deleting, &finished, "the first discard");
    assert_eq!(first_deleting.thread.as_deref(), Some("first"));
    spawn_discard(scope.reopen(), "second", &results);
    let second_entered = entered.next();
    assert_eq!(second_entered.thread.as_deref(), Some("second"));
    second_entered.resume();
    first_deleting.resume();
    assert_eq!(
        finished.recv_timeout(DISCARD_WAIT).unwrap(),
        ("first", Ok(()))
    );

    let next = scope.reopen();
    next.unlock(&[42; 32]).unwrap();
    let written = next.build("service", "user", None).unwrap();
    written.set_secret(b"next generation").unwrap();

    let deadline = Instant::now() + DISCARD_WAIT;
    let second = loop {
        if let Some(arrival) = deleting.within(Duration::from_millis(50)) {
            arrival.resume();
        }
        if let Ok(result) = finished.try_recv() {
            break result;
        }
        assert!(
            Instant::now() < deadline,
            "the second discard never finished"
        );
    };
    assert_eq!(written.get_secret().unwrap(), b"next generation");
    assert!(raw(&scope.keycheck()).is_ok());
    assert_eq!(second, ("second", Err(SealError::Discarded)));
}

#[test]
fn an_in_progress_discard_marks_its_generation_as_discarding() {
    let mut scope = Scope::new();
    scope.store.discard(DISCARD_TIMEOUT).unwrap();
    let current = scope.reopen();
    current.unlock(&[31; 32]).unwrap();
    let entry = current.build("service", "user", None).unwrap();
    scope.targets.push(target_of(&entry));
    entry.set_secret(b"second generation").unwrap();
    let mut expected = raw(&scope.control()).unwrap();
    expected[5] = 1;
    let prefix = scope.store.id();
    let entered = pause::arm(&prefix, "discard.entered");
    let deleting = pause::arm(&prefix, "discard.deleting");
    let (results, finished) = mpsc::channel();

    spawn_discard(current, "second", &results);
    arrival_of(&entered, &finished, "the discard").resume();
    let paused = arrival_of(&deleting, &finished, "the discard");
    assert_eq!(raw(&scope.control()).unwrap(), expected);
    paused.resume();
    assert_eq!(
        finished.recv_timeout(DISCARD_WAIT).unwrap(),
        ("second", Ok(()))
    );
    assert!(matches!(raw(&target_of(&entry)), Err(Error::NoEntry)));
}

#[test]
fn a_resumed_discard_keeps_the_generation_of_the_interrupted_marker() {
    let mut scope = Scope::new();
    scope.store.unlock(&[32; 32]).unwrap();
    let entry = scope.entry("user");
    entry.set_secret(b"sealed").unwrap();
    let mut marker = crate::sealed::CONTROL_MAGIC.to_vec();
    marker.push(1);
    marker.extend([7; 16]);
    write_raw(&scope.control(), &marker);
    let prefix = scope.store.id();
    let entered = pause::arm(&prefix, "discard.entered");
    let deleting = pause::arm(&prefix, "discard.deleting");
    let (results, finished) = mpsc::channel();

    spawn_discard(Arc::clone(&scope.store), "resuming", &results);
    arrival_of(&entered, &finished, "the discard").resume();
    let paused = arrival_of(&deleting, &finished, "the discard");
    assert_eq!(raw(&scope.control()).unwrap(), marker);
    paused.resume();
    assert_eq!(
        finished.recv_timeout(DISCARD_WAIT).unwrap(),
        ("resuming", Ok(()))
    );
    assert!(matches!(raw(&target_of(&entry)), Err(Error::NoEntry)));
}

/// Rewrites `target`'s record under its upper-case spelling, which Credential Manager then lists.
fn recase(target: &str) {
    let blob = raw(target).unwrap();
    delete_credential(target).unwrap();
    write_raw(&target.to_uppercase(), &blob);
}

#[test]
fn a_record_rewritten_in_another_case_stays_in_its_store() {
    let mut scope = Scope::new();
    scope.store.unlock(&[93; 32]).unwrap();
    let entry = scope.entry("user");
    entry.set_password("kept").unwrap();
    let target = target_of(&entry);
    recase(&target);
    assert_eq!(entry.get_password().unwrap(), "kept");
    scope.store.discard(DISCARD_TIMEOUT).unwrap();
    assert!(matches!(raw(&target), Err(Error::NoEntry)));
}

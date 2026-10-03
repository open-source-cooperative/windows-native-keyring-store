use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, Once};

use crate::Store;
use crate::cred::Cred;
use crate::utils::{FoldedName, validate_attributes, validate_target};
use keyring_core::{CredentialStore, Entry, Error, api::CredentialPersistence, get_default_store};
use windows_sys::Win32::Security::Credentials::{
    CRED_MAX_GENERIC_TARGET_NAME_LENGTH, CRED_MAX_STRING_LENGTH, CRED_MAX_USERNAME_LENGTH,
};

static SET_STORE: Once = Once::new();

fn usually_goes_in_main() {
    keyring_core::set_default_store(Store::new().unwrap());
}

#[test]
fn test_store_methods() {
    SET_STORE.call_once(usually_goes_in_main);
    let store = get_default_store().unwrap();
    let vendor1 = store.vendor();
    let id1 = store.id();
    let vendor2 = store.vendor();
    let id2 = store.id();
    assert_eq!(vendor1, vendor2);
    assert_eq!(id1, id2);
    let store2: Arc<CredentialStore> = Store::new().unwrap();
    let vendor3 = store2.vendor();
    let id3 = store2.id();
    assert_eq!(vendor1, vendor3);
    assert_ne!(id1, id3);
}

/// An [`Entry`] whose record is deleted when the test drops it, even on panic.
///
/// The deletion bypasses `delete_credential`, so a broken one cannot leave records behind to slow
/// later tests.
struct TestEntry(Entry);

impl Deref for TestEntry {
    type Target = Entry;

    fn deref(&self) -> &Entry {
        &self.0
    }
}

impl Drop for TestEntry {
    fn drop(&mut self) {
        if let Some(cred) = self.0.as_any().downcast_ref::<Cred>() {
            crate::utils::delete_test_record(&cred.target_name);
        }
    }
}

fn entry_new(service: &str, user: &str) -> TestEntry {
    SET_STORE.call_once(usually_goes_in_main);
    crate::utils::assert_call_lock_released();
    TestEntry(
        Entry::new(&format!("test-{service}"), user).unwrap_or_else(|err| {
            panic!("Couldn't create entry (service: {service}, user: {user}): {err:?}")
        }),
    )
}

fn entry_new_with_modifiers(
    service: &str,
    user: &str,
    modifiers: &HashMap<&str, &str>,
) -> TestEntry {
    SET_STORE.call_once(usually_goes_in_main);
    crate::utils::assert_call_lock_released();
    TestEntry(
        Entry::new_with_modifiers(&format!("test-{service}"), user, modifiers).unwrap_or_else(|err| {
            panic!("Couldn't create entry (service: {service}, user: {user}, modifiers: {modifiers:?}): {err:?})")
        }),
    )
}

fn generate_random_string_of_len(len: usize) -> String {
    use fastrand;
    use std::iter::repeat_with;
    repeat_with(fastrand::alphanumeric).take(len).collect()
}

fn generate_random_string() -> String {
    generate_random_string_of_len(12usize)
}

#[test]
fn test_reads_wait_for_the_windows_user_mutex() {
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};

    struct NativeHandle(HANDLE);

    impl Drop for NativeHandle {
        fn drop(&mut self) {
            // SAFETY: This guard exclusively owns the live handle.
            unsafe { CloseHandle(self.0) };
        }
    }

    struct UserMutex {
        handle: NativeHandle,
        owned: bool,
    }

    impl UserMutex {
        fn release(mut self) {
            // SAFETY: This thread acquired the live mutex and has not released it.
            assert_ne!(unsafe { ReleaseMutex(self.handle.0) }, 0);
            self.owned = false;
        }
    }

    impl Drop for UserMutex {
        fn drop(&mut self) {
            if self.owned {
                // SAFETY: This thread still owns the live mutex.
                unsafe { ReleaseMutex(self.handle.0) };
            }
        }
    }

    let run_id = generate_random_string();
    let entry = entry_new(&run_id, &run_id);
    std::thread::scope(|scope| {
        // `user_lock` mutations must not change the kernel mutex oracle, which names the mutex on
        // its own. `entry_new` has already entered the namespace, and a process cannot open a
        // namespace it holds a second time.
        let digits: String = process_user_sid()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let name: Vec<u16> = format!("windows-native-keyring-store-v1-{digits}\\call\0")
            .encode_utf16()
            .collect();
        // SAFETY: The UTF-16 buffer includes its terminator and the API accepts a `null` descriptor.
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        assert!(!handle.is_null());
        let handle = NativeHandle(handle);
        // SAFETY: The owned handle remains live throughout the bounded wait.
        let status = unsafe { WaitForSingleObject(handle.0, 10_000) };
        assert!(matches!(status, WAIT_OBJECT_0 | WAIT_ABANDONED));
        let mutex = UserMutex {
            handle,
            owned: true,
        };
        let (started_tx, started_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let run_id = run_id.as_str();
        let entry = &entry;
        scope.spawn(move || {
            started_tx.send(run_id).unwrap();
            result_tx.send((run_id, entry.get_password())).unwrap();
        });
        assert_eq!(
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            run_id
        );
        assert!(matches!(
            result_rx.recv_timeout(Duration::from_millis(250)),
            Err(RecvTimeoutError::Timeout)
        ));
        mutex.release();
        let (reply_id, result) = result_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(reply_id, run_id);
        assert!(matches!(result, Err(Error::NoEntry)));
    });
}

/// The user `SID` of the process token, read without the code under test.
pub(crate) fn process_user_sid() -> Vec<u8> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        GetLengthSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    // SAFETY: The current process pseudo-handle is valid and `token` is writable.
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    assert_ne!(opened, 0);
    let mut buffer = [0u64; 11];
    let mut written = 0;
    // SAFETY: The live token is queryable and the aligned buffer holds `TOKEN_USER` and a maximum-size `SID`.
    let queried = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            u32::try_from(size_of_val(&buffer)).unwrap(),
            &mut written,
        )
    };
    // SAFETY: `token` was opened above and is closed once.
    unsafe { CloseHandle(token) };
    assert_ne!(queried, 0);
    // SAFETY: The successful query initialized `TOKEN_USER` inside the aligned buffer.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: The `SID` remains valid while its token-information buffer lives.
    let length = usize::try_from(unsafe { GetLengthSid(sid) }).unwrap();
    // SAFETY: The successful query and `GetLengthSid` bound the `SID` inside the live buffer.
    unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) }.to_vec()
}

fn generate_random_bytes() -> Vec<u8> {
    use fastrand;
    use std::iter::repeat_with;
    repeat_with(|| fastrand::u8(..)).take(24).collect()
}

// A round-trip password test that doesn't delete the credential afterward
fn test_round_trip_no_delete(case: &str, entry: &Entry, in_pass: &str) {
    entry
        .set_password(in_pass)
        .unwrap_or_else(|err| panic!("Can't set password for {case}: {err:?}"));
    let out_pass = entry
        .get_password()
        .unwrap_or_else(|err| panic!("Can't get password: {case}: {err:?}"));
    assert_eq!(
        in_pass, out_pass,
        "Passwords don't match for {case}: set='{in_pass}', get='{out_pass}'",
    )
}

// A round-trip password test that does delete the credential afterward
fn test_round_trip(case: &str, entry: &Entry, in_pass: &str) {
    test_round_trip_no_delete(case, entry, in_pass);
    entry
        .delete_credential()
        .unwrap_or_else(|err| panic!("Can't delete password: {case}: {err:?}"));
    let password = entry.get_password();
    assert!(
        matches!(password, Err(Error::NoEntry)),
        "Got a deleted password: {case}",
    );
}

// A round-trip secret test that does delete the credential afterward
pub fn test_round_trip_secret(case: &str, entry: &Entry, in_secret: &[u8]) {
    entry
        .set_secret(in_secret)
        .unwrap_or_else(|err| panic!("Can't set secret for {case}: {err:?}"));
    let out_secret = entry
        .get_secret()
        .unwrap_or_else(|err| panic!("Can't get secret for {case}: {err:?}"));
    assert_eq!(
        in_secret, &out_secret,
        "Secrets don't match for {case}: set='{in_secret:?}', get='{out_secret:?}'",
    );
    entry
        .delete_credential()
        .unwrap_or_else(|err| panic!("Can't delete credential for {case}: {err:?}"));
    let secret = entry.get_secret();
    assert!(
        matches!(secret, Err(Error::NoEntry)),
        "Got a deleted password: {case}",
    );
}

#[test]
fn test_validate() {
    validate_target("target", "user").unwrap();
    validate_target("", "user").unwrap_err();
    validate_target(
        &generate_random_string_of_len(CRED_MAX_GENERIC_TARGET_NAME_LENGTH as usize + 1),
        "user",
    )
    .unwrap_err();
    validate_target(
        "target",
        &generate_random_string_of_len(CRED_MAX_USERNAME_LENGTH as usize + 1),
    )
    .unwrap_err();
    validate_attributes("username", "target_alias", "comment").unwrap();
    validate_attributes(
        &generate_random_string_of_len(CRED_MAX_USERNAME_LENGTH as usize + 1),
        "target_alias",
        "comment",
    )
    .unwrap_err();
    validate_attributes(
        "username",
        "target_alias",
        &generate_random_string_of_len(CRED_MAX_STRING_LENGTH as usize + 1),
    )
    .unwrap_err();
}

#[test]
fn test_folded_name() {
    assert_eq!(FoldedName::new("alice").unwrap().as_str(), "ALICE");
}

#[test]
fn test_invalid_parameter() {
    SET_STORE.call_once(usually_goes_in_main);
    let modifiers = HashMap::from([("target", "")]);
    let entry = Entry::new_with_modifiers("service", "user", &modifiers);
    assert!(matches!(entry, Err(Error::Invalid(_, _))));
    let entry =
        Entry::new_with_modifiers("service", "user", &HashMap::from([("persistence", "none")]));
    assert!(matches!(entry, Err(Error::Invalid(_, _))));
    let store: Arc<CredentialStore> =
        Store::new_with_configuration(&HashMap::from([("service_no_divider", "true")])).unwrap();
    let entry = store.build("ser.vice", "user", None);
    assert!(matches!(entry, Err(Error::Invalid(_, _))));
    let store: Arc<CredentialStore> = Store::new_with_configuration(&HashMap::from([
        ("service_no_divider", "true"),
        ("divider", ""),
    ]))
    .unwrap();
    let entry = store.build("service", "user", None);
    assert!(matches!(entry, Err(Error::Invalid(_, _))));
}

#[test]
fn test_missing_entry() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    assert!(matches!(entry.get_password(), Err(Error::NoEntry)))
}

#[test]
fn test_empty_password() {
    let name = generate_random_string();
    let in_pass = "";
    let entry = entry_new(&name, &name);
    entry.set_password(in_pass).unwrap();
    assert_eq!(entry.get_password().unwrap(), in_pass);
    _ = entry.delete_credential();
}

#[test]
fn test_round_trip_ascii_password() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    test_round_trip("ascii password", &entry, "test ascii password");
}

#[test]
fn test_round_trip_non_ascii_password() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    test_round_trip("non-ascii password", &entry, "このきれいな花は桜です");
}

#[test]
fn test_round_trip_password_starting_with_a_noncharacter() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    test_round_trip("noncharacter password", &entry, "\u{ffff}secret");
}

#[test]
fn test_entries_with_same_and_different_specifiers() {
    let name1 = generate_random_string();
    let name2 = generate_random_string();
    let entry1 = entry_new(&name1, &name2);
    let entry2 = entry_new(&name1, &name2);
    let entry3 = entry_new(&name2, &name1);
    entry1.set_password("test password").unwrap();
    let pw2 = entry2.get_password().unwrap();
    assert_eq!(pw2, "test password");
    _ = entry3.get_password().unwrap_err();
    entry1.delete_credential().unwrap();
    _ = entry2.get_password().unwrap_err();
    entry3.delete_credential().unwrap_err();
}

#[test]
fn test_round_trip_random_secret() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    let secret = generate_random_bytes();
    test_round_trip_secret("non-ascii password", &entry, secret.as_slice());
}

#[test]
fn test_update() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    test_round_trip_no_delete("initial ascii password", &entry, "test ascii password");
    test_round_trip(
        "updated non-ascii password",
        &entry,
        "このきれいな花は桜です",
    );
}

#[test]
fn test_get_update_attributes() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    entry.set_password("test password").unwrap();
    let before = entry.get_attributes().unwrap();
    assert_eq!(before["username"], name);
    assert_eq!(before["target_alias"], "");
    assert_eq!(before["comment"], "");
    let in_map: HashMap<&str, &str> = HashMap::from([
        ("target_alias", "target alias value"),
        ("comment", "comment value"),
        ("username", "username value"),
    ]);
    entry.update_attributes(&in_map).unwrap();
    let after = entry.get_attributes().unwrap();
    assert_eq!(after["username"], "username value");
    assert_eq!(after["target_alias"], "target alias value");
    assert_eq!(after["comment"], "comment value");
    entry.delete_credential().unwrap();
}

#[test]
fn test_get_credential_and_specifiers() {
    let name1 = generate_random_string();
    let name2 = generate_random_string();
    let entry1 = entry_new(&name1, &name2);
    assert!(matches!(entry1.get_credential(), Err(Error::NoEntry)));
    entry1.set_password("password for entry1").unwrap();
    let cred1 = entry1.as_any().downcast_ref::<Cred>().unwrap();
    let wrapper = entry1.get_credential().unwrap();
    let cred2 = wrapper.as_any().downcast_ref::<Cred>().unwrap();
    assert_eq!(cred1 as *const _, cred2 as *const _);
    let (service, user) = wrapper.get_specifiers().unwrap();
    assert_eq!(service, format!("test-{name1}"));
    assert_eq!(user, name2);
    entry1.delete_credential().unwrap();
    wrapper.delete_credential().unwrap_err();
    let modifiers = HashMap::from([("target", name1.as_str())]);
    let entry2 = Entry::new_with_modifiers(&name1, &name2, &modifiers).unwrap();
    assert!(entry2.get_specifiers().is_none());
    entry2.delete_credential().unwrap_err();
}

#[test]
fn test_create_then_move() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    let test = move || {
        let password = "test ascii password";
        entry.set_password(password).unwrap();
        let stored_password = entry.get_password().unwrap();
        assert_eq!(stored_password, password);
        let password = "このきれいな花は桜です";
        entry.set_password(password).unwrap();
        let stored_password = entry.get_password().unwrap();
        assert_eq!(stored_password, password);
        entry.delete_credential().unwrap();
        assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
    };
    let handle = std::thread::spawn(test);
    assert!(handle.join().is_ok(), "Couldn't execute on thread")
}

#[test]
fn test_simultaneous_create_then_move() {
    let mut handles = vec![];
    let base = generate_random_string();
    for i in 0..10 {
        let name = format!("{base}-{i}");
        let entry = entry_new(&name, &name);
        let test = move || {
            entry.set_password(&name).unwrap();
            let stored_password = entry.get_password().unwrap();
            assert_eq!(stored_password, name);
            entry.delete_credential().unwrap();
            assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
        };
        handles.push(std::thread::spawn(test))
    }
    for handle in handles {
        handle.join().unwrap()
    }
}

#[test]
fn test_create_set_then_move() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    let password = "test ascii password";
    entry.set_password(password).unwrap();
    let test = move || {
        let stored_password = entry.get_password().unwrap();
        assert_eq!(stored_password, password);
        entry.delete_credential().unwrap();
        assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
    };
    let handle = std::thread::spawn(test);
    assert!(handle.join().is_ok(), "Couldn't execute on thread")
}

#[test]
fn test_simultaneous_create_set_then_move() {
    let mut handles = vec![];
    let base = generate_random_string();
    for i in 0..10 {
        let name = format!("{base}-{i}");
        let entry = entry_new(&name, &name);
        entry.set_password(&name).unwrap();
        let test = move || {
            let stored_password = entry.get_password().unwrap();
            assert_eq!(stored_password, name);
            entry.delete_credential().unwrap();
            assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
        };
        handles.push(std::thread::spawn(test))
    }
    for handle in handles {
        handle.join().unwrap()
    }
}

#[test]
fn test_simultaneous_independent_create_set() {
    let mut handles = vec![];
    let base = generate_random_string();
    for i in 0..10 {
        let name = format!("{base}-{i}");
        let test = move || {
            let entry = entry_new(&name, &name);
            entry.set_password(&name).unwrap();
            let stored_password = entry.get_password().unwrap();
            assert_eq!(stored_password, name);
            entry.delete_credential().unwrap();
            assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
        };
        handles.push(std::thread::spawn(test))
    }
    for handle in handles {
        handle.join().unwrap()
    }
}

#[test]
fn test_multiple_create_delete_single_thread() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    let repeats = 10;
    for _i in 0..repeats {
        entry.set_password(&name).unwrap();
        let stored_password = entry.get_password().unwrap();
        assert_eq!(stored_password, name);
        entry.delete_credential().unwrap();
        assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
    }
}

#[test]
fn test_simultaneous_multiple_create_delete_single_thread() {
    let mut handles = vec![];
    let base = generate_random_string();
    for t in 0..10 {
        let name = format!("{base}-{t}");
        let test = move || {
            let entry = entry_new(&name, &name);
            let repeats = 10;
            for _i in 0..repeats {
                entry.set_password(&name).unwrap();
                assert_eq!(entry.get_password().unwrap(), name);
                entry.delete_credential().unwrap();
                assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
            }
        };
        handles.push(std::thread::spawn(test))
    }
    for handle in handles {
        handle.join().unwrap()
    }
}

#[test]
fn test_simultaneous_deletes_leave_no_credentials() {
    let base = &generate_random_string();
    let entries: Vec<(String, TestEntry)> = (0..10)
        .flat_map(|t| (0..40).map(move |r| format!("{base}-{t}-{r}")))
        .map(|name| {
            let entry = entry_new(&name, &name);
            (name, entry)
        })
        .collect();
    let failed_workers = std::thread::scope(|scope| {
        let workers: Vec<_> = entries
            .chunks(40)
            .map(|chunk| {
                // Stopping at the first failed call keeps a broken call from piling up records.
                scope.spawn(move || {
                    chunk.iter().any(|(name, entry)| {
                        entry.set_password(name).is_err()
                            || entry.get_password().ok().as_deref() != Some(name)
                            || entry.delete_credential().is_err()
                            || !matches!(entry.get_password(), Err(Error::NoEntry))
                    })
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|&failed| failed)
            .count()
    });
    let survivors = entries
        .iter()
        .filter(|(_, entry)| entry.get_password().is_ok())
        .count();
    assert_eq!(
        (failed_workers, survivors),
        (0, 0),
        "(failed workers, survivors)"
    );
}

#[test]
fn test_credential_persistence() {
    let name = generate_random_string();
    let persist_local = HashMap::from([("persistence", "local")]);
    let persist_session = HashMap::from([("persistence", "session")]);
    let default = entry_new(&name, "enterprise");
    default.set_password("enterprise").unwrap();
    assert_eq!(
        default.get_attributes().unwrap()["persistence"],
        "Enterprise"
    );
    let session = entry_new_with_modifiers(&name, "session", &persist_session);
    session.set_password("session").unwrap();
    assert_eq!(session.get_attributes().unwrap()["persistence"], "Session");
    let local = entry_new_with_modifiers(&name, "local", &persist_local);
    local.set_password("local").unwrap();
    assert_eq!(local.get_attributes().unwrap()["persistence"], "Local");
    let mock_session = entry_new(&name, "session");
    assert_eq!(mock_session.get_password().unwrap(), "session");
    assert_eq!(
        mock_session.get_attributes().unwrap()["persistence"],
        "Session"
    );
    mock_session.set_password("enterprise").unwrap();
    assert_eq!(
        mock_session.get_attributes().unwrap()["persistence"],
        "Enterprise"
    );
    assert_eq!(session.get_password().unwrap(), "enterprise");
    assert_eq!(
        session.get_attributes().unwrap()["persistence"],
        "Enterprise"
    );
    session.set_password("back to session").unwrap();
    assert_eq!(session.get_attributes().unwrap()["persistence"], "Session");
    assert_eq!(mock_session.get_password().unwrap(), "back to session");
    assert_eq!(
        mock_session.get_attributes().unwrap()["persistence"],
        "Session"
    );
    mock_session.delete_credential().unwrap();
    session.delete_credential().unwrap_err();
    local.delete_credential().unwrap();
    default.delete_credential().unwrap();
}

#[cfg(feature = "search")]
#[test]
fn test_search() {
    use keyring_core::api::CredentialApi;

    let name = generate_random_string();
    let entry = entry_new("search entry", &name);
    entry.set_password("test search entry").unwrap();
    let entries = Entry::search(&HashMap::from([("pattern", "test-")])).unwrap();
    entry.delete_credential().unwrap();
    assert!(!entries.is_empty());
    println!("Found {} test entries:", entries.len());
    let mut found = false;
    for e in entries {
        let cred: &Cred = e.as_any().downcast_ref().unwrap();
        match cred.get_specifiers() {
            None => panic!("All test entries should have specifiers"),
            Some(specs) => {
                if specs.0.ends_with("search entry") && specs.1 == name {
                    found = true;
                    println!("\t{specs:?} (test target)");
                } else {
                    println!("\t{specs:?}");
                }
            }
        }
    }
    assert!(found, "We didn't find the test search entry");
}

#[test]
fn test_store_persistence() {
    let store: Arc<CredentialStore> = Store::new().unwrap();
    assert!(matches!(
        store.persistence(),
        CredentialPersistence::UntilDelete
    ));
}

#[test]
fn ordinary_binary_secret_with_protected_prefix_remains_readable() {
    let entry = entry_new("binary-secret", &generate_random_string());
    let secret = b"\x00\xdc\x01binary";
    entry.set_secret(secret).unwrap();
    assert_eq!(entry.get_secret().unwrap(), secret);
    assert!(matches!(
        entry.get_password(),
        Err(Error::BadStoreFormat(_))
    ));
    entry.delete_credential().unwrap();
}

#[test]
fn wide_string_decoding_accepts_an_odd_address() {
    let units: Vec<u16> = "Windows Hello".encode_utf16().chain([0]).collect();
    let mut bytes = vec![0u8; units.len() * 2 + 1];
    let start = 1 - bytes.as_ptr() as usize % 2;
    for (at, unit) in units.iter().enumerate() {
        bytes[start + 2 * at..start + 2 * at + 2].copy_from_slice(&unit.to_ne_bytes());
    }
    let string = bytes[start..].as_ptr().cast::<u16>();
    assert_eq!(string as usize % 2, 1);
    // SAFETY: `string` points to a NUL-terminated UTF-16 string inside `bytes`.
    assert_eq!(unsafe { crate::utils::from_wstr(string) }, "Windows Hello");
}

#![forbid(unsafe_code)]

use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use std::{
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};
use windows_native_keyring_store::tpm_key::{TpmKeyError, TpmSigningKey};
use windows_sys::Win32::Foundation::{NTE_EXISTS, NTE_NOT_FOUND};

const DIGEST: [u8; 32] = [0x42; 32];

fn verify(key: &TpmSigningKey) {
    let verifier = VerifyingKey::from_sec1_bytes(&key.public_point()).unwrap();
    let signature = Signature::from_slice(&key.sign_digest(&DIGEST).unwrap()).unwrap();
    verifier.verify_prehash(&DIGEST, &signature).unwrap();
    assert!(verifier.verify_prehash(&[0x43; 32], &signature).is_err());
}

#[test]
fn persisted_key_lifecycle() {
    let name = format!(
        "keyring-tpm-test-{}-{:016x}",
        std::process::id(),
        fastrand::u64(..)
    );
    match TpmSigningKey::open(&name) {
        Ok(None) => {}
        Err(TpmKeyError::Unavailable(status)) => {
            eprintln!("TPM unavailable on open ({status:#010x})");
            assert!(matches!(
                TpmSigningKey::create(&name),
                Err(TpmKeyError::Unavailable(_))
            ));
            return;
        }
        other => panic!("unexpected open result {other:?}"),
    }
    let key = match TpmSigningKey::create(&name) {
        Ok(key) => key,
        Err(TpmKeyError::Unavailable(status)) => {
            eprintln!("TPM unavailable on create ({status:#010x})");
            return;
        }
        Err(error) => panic!("create failed {error}"),
    };
    let point = key.public_point();
    verify(&key);
    assert!(matches!(
        TpmSigningKey::create(&name),
        Err(TpmKeyError::Windows(_))
    ));
    drop(key);

    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "reopen_in_child", "--nocapture"])
        .env("KEYRING_TPM_TEST_NAME", &name)
        .env(
            "KEYRING_TPM_TEST_POINT",
            point.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        )
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            TpmSigningKey::open(&name)
                .unwrap()
                .unwrap()
                .delete()
                .unwrap();
            panic!("TPM child exceeded its 60-second deadline");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let key = Arc::new(TpmSigningKey::open(&name).unwrap().unwrap());
    assert_eq!(point, key.public_point());
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| verify(&key));
        }
    });
    Arc::try_unwrap(key).unwrap().delete().unwrap();
    assert!(TpmSigningKey::open(&name).unwrap().is_none());
    assert!(status.success());
    eprintln!("TPM lifecycle verified, including fresh-process reopen and concurrent signing");
}

#[test]
fn concurrent_creation_of_same_name() {
    let name = format!(
        "keyring-tpm-test-concurrent-{}-{:016x}",
        std::process::id(),
        fastrand::u64(..)
    );
    let results: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| TpmSigningKey::create(&name)))
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect()
    });
    if results
        .iter()
        .any(|result| matches!(result, Err(TpmKeyError::Unavailable(_))))
    {
        eprintln!("TPM unavailable for concurrent creation");
        return;
    }
    let winners = results.iter().filter(|result| result.is_ok()).count();
    assert_eq!(winners, 1, "exactly one concurrent create must win");
    let losers = results
        .iter()
        .filter(|result| matches!(result, Err(TpmKeyError::Windows(NTE_EXISTS))))
        .count();
    assert_eq!(losers, 3, "every losing create must report NTE_EXISTS");
    let winner = results.into_iter().find_map(Result::ok).unwrap();
    let reopened = TpmSigningKey::open(&name).unwrap().unwrap();
    assert_eq!(reopened.public_point(), winner.public_point());
    verify(&winner);
    verify(&reopened);
    drop(reopened);
    winner.delete().unwrap();
    assert!(TpmSigningKey::open(&name).unwrap().is_none());
}

#[test]
fn failed_delete_returns_the_key() {
    let name = format!(
        "keyring-tpm-test-delete-{}-{:016x}",
        std::process::id(),
        fastrand::u64(..)
    );
    let owner = match TpmSigningKey::create(&name) {
        Ok(key) => key,
        Err(TpmKeyError::Unavailable(_)) => return,
        Err(error) => panic!("create failed {error}"),
    };
    let alias = TpmSigningKey::open(&name).unwrap().unwrap();
    let point = alias.public_point();
    owner.delete().unwrap();
    let failure = alias.delete().unwrap_err();
    assert_eq!(failure.error, TpmKeyError::Windows(NTE_NOT_FOUND));
    assert_eq!(failure.key.public_point(), point);
    assert!(TpmSigningKey::open(&name).unwrap().is_none());
}

#[test]
fn reopen_in_child() {
    let Ok(name) = std::env::var("KEYRING_TPM_TEST_NAME") else {
        return;
    };
    let key = TpmSigningKey::open(&name).unwrap().unwrap();
    let point = key
        .public_point()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(point, std::env::var("KEYRING_TPM_TEST_POINT").unwrap());
    verify(&key);
}

#[test]
fn invalid_names_cannot_alias_persisted_keys() {
    for name in ["", "valid\0suffix"] {
        assert!(matches!(
            TpmSigningKey::open(name),
            Err(TpmKeyError::InvalidName)
        ));
        assert!(matches!(
            TpmSigningKey::create(name),
            Err(TpmKeyError::InvalidName)
        ));
    }
}

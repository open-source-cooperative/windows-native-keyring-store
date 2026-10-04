//! AES-256-GCM codec binding each sealed secret to its store and target.
#![expect(dead_code, reason = "seal and open are called by Gate")]

use crate::sealed::SealError;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInOut, KeyInit, Nonce};
use zeroize::Zeroizing;

// UTF-16LE of a lone low surrogate, which no valid plain password can start with.
const MAGIC: [u8; 2] = [0x00, 0xDC];
const FORMAT_VERSION: u8 = 1;
const VERSION_AT: usize = 2;
const NONCE_LEN: usize = 12;
const NONCE_AT: usize = MAGIC.len() + 1;
const NONCE_END: usize = NONCE_AT + NONCE_LEN;
const TAG_LEN: usize = 16;
const MIN_BLOB_LEN: usize = NONCE_END + TAG_LEN;
pub(crate) const PROTECTED_OVERHEAD: usize = MIN_BLOB_LEN;

/// Whether `blob` carries the protected-format magic prefix.
pub(crate) fn is_protected(blob: &[u8]) -> bool {
    blob.starts_with(&MAGIC)
}

/// Bind length-prefixed store and target names to the ciphertext.
fn associated_data(store: &str, target: &str) -> Vec<u8> {
    let mut ad = Vec::with_capacity(8 + store.len() + 8 + target.len());
    for name in [store, target] {
        ad.extend_from_slice(&(name.len() as u64).to_be_bytes());
        ad.extend_from_slice(name.as_bytes());
    }
    ad
}

/// Seal with a fresh nonce from the system random source.
pub(crate) fn seal(
    key: &[u8; 32],
    store: &str,
    target: &str,
    plain: &[u8],
) -> Result<Vec<u8>, SealError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|error| SealError::Platform(format!("random nonce unavailable: {error}")))?;

    let cipher = Aes256Gcm::new(key.into());
    let nonce: &Nonce<Aes256Gcm> = (&nonce_bytes).into();
    let ad = associated_data(store, target);

    let mut blob = Zeroizing::new(Vec::with_capacity(MIN_BLOB_LEN + plain.len()));
    blob.extend_from_slice(&MAGIC);
    blob.push(FORMAT_VERSION);
    blob.extend_from_slice(&nonce_bytes);
    let plain_at = blob.len();
    blob.extend_from_slice(plain);

    let tag = cipher
        .encrypt_inout_detached(nonce, &ad, (&mut blob[plain_at..]).into())
        .map_err(|_| SealError::Platform("sealing failed".into()))?;
    blob.extend_from_slice(tag.as_slice());
    Ok(std::mem::take(&mut *blob))
}

/// Open a protected blob into a buffer erased when dropped.
pub(crate) fn open(
    key: &[u8; 32],
    store: &str,
    target: &str,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    if blob.len() < MIN_BLOB_LEN {
        return Err(SealError::Corrupt(format!(
            "protected blob is {len} bytes, needs at least {MIN_BLOB_LEN}",
            len = blob.len()
        )));
    }
    if !blob.starts_with(&MAGIC) {
        return Err(SealError::Corrupt(
            "protected blob lacks the 0x00 0xDC magic prefix".into(),
        ));
    }
    if blob[VERSION_AT] != FORMAT_VERSION {
        return Err(SealError::Corrupt(format!(
            "protected blob format version {version} is not supported",
            version = blob[VERSION_AT]
        )));
    }

    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&blob[NONCE_AT..NONCE_END]);
    let nonce: &Nonce<Aes256Gcm> = (&nonce_bytes).into();
    let cipher = Aes256Gcm::new(key.into());
    let ad = associated_data(store, target);

    let mut buffer = Zeroizing::new(blob[NONCE_END..].to_vec());
    cipher
        .decrypt_in_place(nonce, &ad, &mut *buffer)
        .map_err(|_| {
            SealError::Corrupt(
                "ciphertext failed authentication against the sealing key, store, and target"
                    .into(),
            )
        })?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STORE: &str = "myapp.store";
    const TARGET: &str = "myapp.store/entry";

    fn key() -> [u8; 32] {
        [0x5A; 32]
    }

    fn seal_default(plain: &[u8]) -> Vec<u8> {
        seal(&key(), STORE, TARGET, plain).unwrap()
    }

    fn open_default(blob: &[u8]) -> Zeroizing<Vec<u8>> {
        open(&key(), STORE, TARGET, blob).unwrap()
    }

    fn assert_corrupt(result: Result<Zeroizing<Vec<u8>>, SealError>) {
        match result {
            Err(SealError::Corrupt(_)) => {}
            Err(_) => panic!("expected SealError::Corrupt, got another variant"),
            Ok(_) => panic!("expected SealError::Corrupt, got a plaintext"),
        }
    }

    #[test]
    fn seal_open_roundtrip_recovers_secret() {
        let secret = b"SENTINEL secret credential value 12345";
        let blob = seal_default(secret);
        assert_eq!(blob.len(), NONCE_END + secret.len() + TAG_LEN);
        assert_eq!(&blob[..MAGIC.len()], &MAGIC);
        assert_eq!(blob[VERSION_AT], FORMAT_VERSION);
        assert!(is_protected(&blob));
        assert_eq!(open_default(&blob).as_slice(), secret);
        let empty = seal_default(b"");
        assert_eq!(empty.len(), MIN_BLOB_LEN);
        assert!(open_default(&empty).is_empty());
    }

    #[test]
    fn blob_contains_no_plaintext() {
        let secret = b"SENTINEL-PLAINTEXT-SECRET";
        let blob = seal_default(secret);
        assert!(!blob.windows(secret.len()).any(|window| window == secret));
    }

    #[test]
    fn seal_uses_fresh_random_nonce() {
        let first = seal_default(b"same secret");
        let second = seal_default(b"same secret");
        assert_ne!(&first[NONCE_AT..NONCE_END], &second[NONCE_AT..NONCE_END]);
        assert_ne!(&first[NONCE_END..], &second[NONCE_END..]);
        assert_eq!(open_default(&first).as_slice(), b"same secret");
        assert_eq!(open_default(&second).as_slice(), b"same secret");
    }

    #[test]
    fn open_rejects_tampered_ciphertext_and_tag() {
        for at in [NONCE_END, NONCE_END + 9 + TAG_LEN - 1] {
            let mut blob = seal_default(b"tamper me");
            blob[at] ^= 0x01;
            assert_corrupt(open(&key(), STORE, TARGET, &blob));
        }
    }

    #[test]
    fn open_rejects_wrong_key_store_or_target() {
        let blob = seal_default(b"secret");
        assert_corrupt(open(&[0xA5; 32], STORE, TARGET, &blob));
        assert_corrupt(open(&key(), "other.store", TARGET, &blob));
        assert_corrupt(open(&key(), STORE, "myapp.store/other", &blob));
    }

    #[test]
    fn store_and_target_binding_is_unambiguous() {
        let blob = seal(&key(), "a", "bc", b"split").unwrap();
        assert_corrupt(open(&key(), "ab", "c", &blob));

        let blob = seal(&key(), "ab", "c", b"split").unwrap();
        assert_corrupt(open(&key(), "a", "bc", &blob));
    }

    #[test]
    fn open_rejects_truncated_blob() {
        let blob = seal_default(b"trim");
        for cut in 0..MIN_BLOB_LEN {
            assert_corrupt(open(&key(), STORE, TARGET, &blob[..cut]));
        }
        assert_eq!(open_default(&blob).as_slice(), b"trim");
    }

    #[test]
    fn open_rejects_bad_magic_prefix() {
        let mut blob = seal_default(b"prefix");
        blob[0] = 0xFF;
        assert_corrupt(open(&key(), STORE, TARGET, &blob));

        let mut blob = seal_default(b"prefix");
        blob[1] = 0xFF;
        assert_corrupt(open(&key(), STORE, TARGET, &blob));
    }

    #[test]
    fn open_rejects_unknown_format_version() {
        let mut blob = seal_default(b"version");
        blob[VERSION_AT] = FORMAT_VERSION + 1;
        assert_corrupt(open(&key(), STORE, TARGET, &blob));
    }

    #[test]
    fn is_protected_flags_only_protected_format() {
        let blob = seal_default(b"anything");
        assert!(is_protected(&blob));
        assert!(!is_protected(b"plain legacy secret"));
        assert!(!is_protected(&[0x00]));
        assert!(!is_protected(&[]));
        assert!(!is_protected(&[0x00, 0xD8]));
    }

    #[test]
    fn no_utf16_password_carries_the_protected_prefix() {
        for password in [
            "\u{ffff}secret",
            "\u{ffff}",
            "\u{fffe}x",
            "\u{feff}x",
            "\u{10ffff}",
        ] {
            let bytes: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
            assert!(!is_protected(&bytes), "{password:?}");
        }
    }
}

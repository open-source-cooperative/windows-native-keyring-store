use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use sha2::{Digest, Sha256};

use windows::Security::Credentials::{
    KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::CryptographicBuffer;

use keyring_core::error::{Error, Result};

/// Magic header identifying an encrypted blob: "KRB" + version byte 0x01.
pub(crate) const ENCRYPTED_MAGIC: &[u8; 4] = b"KRB\x01";

/// Size of the AES-GCM nonce in bytes.
const NONCE_LEN: usize = 12;

/// Size of the magic header in bytes.
const MAGIC_LEN: usize = 4;

/// Total overhead added by encryption: magic(4) + nonce(12) + AES-GCM tag(16).
pub(crate) const ENCRYPTION_OVERHEAD: usize = MAGIC_LEN + NONCE_LEN + 16;

#[derive(Debug)]
pub enum CryptoError {
    NotSupported,
    UserCanceled,
    UserPrefersPassword,
    SecurityDeviceLocked,
    InvalidBlobFormat,
    DecryptionFailed,
    WindowsError(windows::core::Error),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSupported => write!(f, "KeyCredentialManager is not supported on this device"),
            Self::UserCanceled => write!(f, "biometric verification canceled by user"),
            Self::UserPrefersPassword => write!(f, "user declined biometric verification"),
            Self::SecurityDeviceLocked => write!(f, "security device (TPM) is locked"),
            Self::InvalidBlobFormat => write!(f, "encrypted blob has invalid format"),
            Self::DecryptionFailed => write!(f, "AES-GCM decryption failed"),
            Self::WindowsError(e) => write!(f, "Windows API error: {e}"),
        }
    }
}

impl std::error::Error for CryptoError {}

pub(crate) fn is_ngc_supported() -> bool {
    match KeyCredentialManager::IsSupportedAsync() {
        Ok(op) => op.get().unwrap_or(false),
        Err(_) => false,
    }
}

fn ngc_key_name(target_name: &str) -> String {
    format!("keyring:{target_name}")
}

/// Opens an existing NGC key, or creates one if it doesn't exist (triggers biometric prompt).
pub(crate) fn ensure_ngc_key(target_name: &str) -> Result<KeyCredential> {
    let key_name = ngc_key_name(target_name);

    let open_result = KeyCredentialManager::OpenAsync(&key_name.clone().into())
        .map_err(|e| Error::PlatformFailure(Box::new(CryptoError::WindowsError(e))))?
        .get()
        .map_err(|e| Error::PlatformFailure(Box::new(CryptoError::WindowsError(e))))?;

    match open_result.Status() {
        Ok(KeyCredentialStatus::Success) => {
            return open_result
                .Credential()
                .map_err(|e| Error::PlatformFailure(Box::new(CryptoError::WindowsError(e))));
        }
        Ok(KeyCredentialStatus::NotFound) => {}
        Ok(status) => return Err(map_credential_status(status)),
        Err(e) => {
            return Err(Error::PlatformFailure(Box::new(CryptoError::WindowsError(
                e,
            ))));
        }
    }

    let create_result = KeyCredentialManager::RequestCreateAsync(
        &key_name.clone().into(),
        KeyCredentialCreationOption::FailIfExists,
    )
    .map_err(|e| Error::PlatformFailure(Box::new(CryptoError::WindowsError(e))))?
    .get()
    .map_err(|e| Error::PlatformFailure(Box::new(CryptoError::WindowsError(e))))?;

    match create_result.Status() {
        Ok(KeyCredentialStatus::Success) => create_result
            .Credential()
            .map_err(|e| Error::PlatformFailure(Box::new(CryptoError::WindowsError(e)))),
        Ok(KeyCredentialStatus::CredentialAlreadyExists) => open_ngc_key(target_name),
        Ok(status) => Err(map_credential_status(status)),
        Err(e) => Err(Error::PlatformFailure(Box::new(CryptoError::WindowsError(
            e,
        )))),
    }
}

pub(crate) fn open_ngc_key(target_name: &str) -> Result<KeyCredential> {
    let key_name = ngc_key_name(target_name);

    let result = KeyCredentialManager::OpenAsync(&key_name.into())
        .map_err(|e| Error::PlatformFailure(Box::new(CryptoError::WindowsError(e))))?
        .get()
        .map_err(|e| Error::PlatformFailure(Box::new(CryptoError::WindowsError(e))))?;

    match result.Status() {
        Ok(KeyCredentialStatus::Success) => result
            .Credential()
            .map_err(|e| Error::PlatformFailure(Box::new(CryptoError::WindowsError(e)))),
        Ok(KeyCredentialStatus::NotFound) => Err(Error::NoEntry),
        Ok(status) => Err(map_credential_status(status)),
        Err(e) => Err(Error::PlatformFailure(Box::new(CryptoError::WindowsError(
            e,
        )))),
    }
}

pub(crate) fn delete_ngc_key(target_name: &str) {
    let key_name = ngc_key_name(target_name);
    let _ = KeyCredentialManager::DeleteAsync(&key_name.into()).and_then(|op| op.get());
}

fn compute_challenge(target_name: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"keyring-credential:");
    hasher.update(target_name.as_bytes());
    hasher.finalize().into()
}

/// Signs a challenge with the NGC key (triggers biometric) and derives a 32-byte AES key.
pub(crate) fn derive_aes_key(key: &KeyCredential, target_name: &str) -> Result<[u8; 32]> {
    let challenge = compute_challenge(target_name);

    let buffer = CryptographicBuffer::CreateFromByteArray(&challenge)
        .map_err(|e| Error::PlatformFailure(Box::new(CryptoError::WindowsError(e))))?;

    let sign_result = key
        .RequestSignAsync(&buffer)
        .map_err(|e| Error::PlatformFailure(Box::new(CryptoError::WindowsError(e))))?
        .get()
        .map_err(|e| Error::PlatformFailure(Box::new(CryptoError::WindowsError(e))))?;

    match sign_result.Status() {
        Ok(KeyCredentialStatus::Success) => {}
        Ok(status) => return Err(map_credential_status(status)),
        Err(e) => {
            return Err(Error::PlatformFailure(Box::new(CryptoError::WindowsError(
                e,
            ))));
        }
    }

    let sig_buffer = sign_result
        .Result()
        .map_err(|e| Error::PlatformFailure(Box::new(CryptoError::WindowsError(e))))?;

    let mut sig_bytes = windows::core::Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(&sig_buffer, &mut sig_bytes)
        .map_err(|e| Error::PlatformFailure(Box::new(CryptoError::WindowsError(e))))?;

    let mut hasher = Sha256::new();
    hasher.update(sig_bytes.as_slice());
    let aes_key: [u8; 32] = hasher.finalize().into();

    Ok(aes_key)
}

pub(crate) fn encrypt(aes_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(aes_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| Error::PlatformFailure(Box::new(CryptoError::DecryptionFailed)))?;

    let mut blob = Vec::with_capacity(MAGIC_LEN + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(ENCRYPTED_MAGIC);
    blob.extend_from_slice(nonce.as_slice());
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

pub(crate) fn decrypt(aes_key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < MAGIC_LEN + NONCE_LEN + 16 {
        return Err(Error::BadDataFormat(
            blob.to_vec(),
            Box::new(CryptoError::InvalidBlobFormat),
        ));
    }

    if &blob[..MAGIC_LEN] != ENCRYPTED_MAGIC {
        return Err(Error::BadDataFormat(
            blob.to_vec(),
            Box::new(CryptoError::InvalidBlobFormat),
        ));
    }

    let nonce = Nonce::from_slice(&blob[MAGIC_LEN..MAGIC_LEN + NONCE_LEN]);
    let ciphertext_and_tag = &blob[MAGIC_LEN + NONCE_LEN..];

    let key = Key::<Aes256Gcm>::from_slice(aes_key);
    let cipher = Aes256Gcm::new(key);

    cipher
        .decrypt(nonce, ciphertext_and_tag)
        .map_err(|_| Error::BadDataFormat(blob.to_vec(), Box::new(CryptoError::DecryptionFailed)))
}

pub(crate) fn is_encrypted(blob: &[u8]) -> bool {
    blob.len() >= MAGIC_LEN && &blob[..MAGIC_LEN] == ENCRYPTED_MAGIC
}

fn map_credential_status(status: KeyCredentialStatus) -> Error {
    match status {
        KeyCredentialStatus::UserCanceled => {
            Error::NoStorageAccess(Box::new(CryptoError::UserCanceled))
        }
        KeyCredentialStatus::UserPrefersPassword => {
            Error::NoStorageAccess(Box::new(CryptoError::UserPrefersPassword))
        }
        KeyCredentialStatus::SecurityDeviceLocked => {
            Error::NoStorageAccess(Box::new(CryptoError::SecurityDeviceLocked))
        }
        KeyCredentialStatus::NotFound => Error::NoEntry,
        _ => Error::PlatformFailure(Box::new(CryptoError::NotSupported)),
    }
}

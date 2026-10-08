//! Non-exportable, user-scoped P-256 keys in the Microsoft Platform Crypto Provider.
//!
//! Do not use from a Windows service. On an IFX TPM 2.0, a create, sign and delete cycle froze the service process for over two minutes.

use parking_lot::Mutex;
use std::{fmt::Write, ptr};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_TIMEOUT, GetLastError, HANDLE, NTE_BAD_ALGID, NTE_BAD_KEYSET,
        NTE_BAD_PROVIDER, NTE_DEVICE_NOT_FOUND, NTE_DEVICE_NOT_READY, NTE_NOT_SUPPORTED,
        NTE_PROV_DLL_NOT_FOUND, NTE_SILENT_CONTEXT, STATUS_NOT_FOUND, TBS_E_SERVICE_DISABLED,
        TBS_E_SERVICE_NOT_RUNNING, TBS_E_TPM_NOT_FOUND, TBSIMP_E_TPM_INCOMPATIBLE,
        TPM_20_E_ASYMMETRIC, TPM_20_E_COMMAND_CODE, TPM_20_E_CURVE, TPM_20_E_DISABLED,
        TPM_20_E_ECC_CURVE, TPM_E_BAD_ORDINAL, TPM_E_DEACTIVATED, TPM_E_DISABLED,
        TPM_E_PCP_DEVICE_NOT_READY, TPM_E_PCP_NOT_SUPPORTED, WAIT_ABANDONED, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    },
    Security::{
        Cryptography::{
            BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
            MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_HANDLE,
            NCRYPT_SILENT_FLAG, NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey,
            NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider,
            NCryptSetProperty, NCryptSignHash,
        },
        GetLengthSid, GetTokenInformation, TOKEN_USER, TokenUser,
    },
    System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject},
};

/// Bounds the wait for another `create` of the same name.
const CREATE_LOCK_TIMEOUT_MS: u32 = 60_000;

/// TPM errors retaining native `SECURITY_STATUS` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TpmKeyError {
    /// Missing, disabled, unsupported, or UI-dependent TPM/provider.
    #[error("TPM signing unavailable ({0:#010x})")]
    Unavailable(i32),
    /// Native failure without software fallback.
    #[error("Windows cryptography failed ({0:#010x})")]
    Windows(i32),
    #[error("key name must be nonempty and contain no NUL characters")]
    InvalidName,
    #[error("persisted key is not ECDSA P-256")]
    WrongKeyType,
    #[error("cryptography provider returned an invalid output length")]
    InvalidOutput,
}

/// Deletion failure retaining the key for retry.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct TpmDeleteError {
    pub key: TpmSigningKey,
    #[source]
    pub error: TpmKeyError,
}

#[derive(Debug)]
struct OwnedHandle(NCRYPT_HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: `self` uniquely owns this live handle.
            unsafe { NCryptFreeObject(self.0) };
        }
    }
}

/// Serializes `create` for one name of the current user.
///
/// Not `Send`, because `ReleaseMutex` must run on the owning thread.
struct CreateLock(HANDLE);

impl CreateLock {
    fn acquire(name: &[u16], timeout_ms: u32) -> Result<Self, TpmKeyError> {
        let lock_name = lock_name(name)?;
        // SAFETY: Default security and a terminated name.
        let handle = unsafe { CreateMutexW(ptr::null(), 0, lock_name.as_ptr()) };
        if handle.is_null() {
            return Err(last_error());
        }
        // SAFETY: `handle` is a live mutex.
        match unsafe { WaitForSingleObject(handle, timeout_ms) } {
            // An abandoned owner left either no key or a complete one.
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self(handle)),
            status => {
                let error = if status == WAIT_TIMEOUT {
                    win32_error(ERROR_TIMEOUT)
                } else {
                    last_error()
                };
                // SAFETY: The unowned handle is live and closed once.
                unsafe { CloseHandle(handle) };
                Err(error)
            }
        }
    }
}

impl Drop for CreateLock {
    fn drop(&mut self) {
        // SAFETY: This thread owns the live mutex, which is released and closed once.
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}

/// A TPM key with serialized signing.
///
/// Microsoft documents no NCrypt threading guarantee. `Send + Sync` rests on an audit of Windows x64 `ncrypt.dll` and `PCPKsp.dll` 10.0.26100.8875.
#[derive(Debug)]
pub struct TpmSigningKey {
    key: Mutex<OwnedHandle>,
    _provider: OwnedHandle,
    point: [u8; 65],
}

impl TpmSigningKey {
    /// Creates a non-exportable key without UI, failing with `NTE_EXISTS` if the name exists.
    ///
    /// Concurrent calls for one name are serialized per user. NCrypt callers outside this crate bypass the lock.
    pub fn create(name: &str) -> Result<Self, TpmKeyError> {
        let name = key_name(name)?;
        let _lock = CreateLock::acquire(&name, CREATE_LOCK_TIMEOUT_MS)?;
        let provider = open_provider()?;
        let mut raw = 0;
        // SAFETY: Live provider, terminated name, writable output handle.
        check(unsafe {
            NCryptCreatePersistedKey(
                provider.0,
                &mut raw,
                BCRYPT_ECDSA_P256_ALGORITHM,
                name.as_ptr(),
                0,
                NCRYPT_SILENT_FLAG,
            )
        })?;
        let mut key = OwnedHandle(raw);
        let policy = 0u32.to_le_bytes();
        // SAFETY: Live key and initialized four-byte policy.
        check(unsafe {
            NCryptSetProperty(key.0, NCRYPT_EXPORT_POLICY_PROPERTY, policy.as_ptr(), 4, 0)
        })?;
        // SAFETY: The owned key is live and unfinalized.
        check(unsafe { NCryptFinalizeKey(key.0, NCRYPT_SILENT_FLAG) })?;
        let point = match public_point(&key) {
            Ok(point) => point,
            Err(error) => {
                // SAFETY: The owned handle is live, and success frees it.
                if unsafe { NCryptDeleteKey(key.0, 0) } == 0 {
                    key.0 = 0;
                }
                return Err(error);
            }
        };
        Ok(Self {
            key: Mutex::new(key),
            _provider: provider,
            point,
        })
    }

    /// Opens without UI, returning `None` for a missing name.
    pub fn open(name: &str) -> Result<Option<Self>, TpmKeyError> {
        let name = key_name(name)?;
        let provider = open_provider()?;
        let mut raw = 0;
        // SAFETY: Live provider, terminated name, writable output handle.
        let status =
            unsafe { NCryptOpenKey(provider.0, &mut raw, name.as_ptr(), 0, NCRYPT_SILENT_FLAG) };
        if status == NTE_BAD_KEYSET {
            return Ok(None);
        }
        check(status)?;
        let key = OwnedHandle(raw);
        let point = public_point(&key)?;
        Ok(Some(Self {
            key: Mutex::new(key),
            _provider: provider,
            point,
        }))
    }

    /// Returns the SEC1 point `0x04 || X || Y`.
    pub fn public_point(&self) -> [u8; 65] {
        self.point
    }

    /// Signs a SHA-256 digest without UI, returning `r || s`.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], TpmKeyError> {
        let key = self.key.lock();
        let mut signature = [0; 64];
        let mut written = 0;
        // SAFETY: Locked live key, valid buffers and result pointer, no ECDSA padding.
        check(unsafe {
            NCryptSignHash(
                key.0,
                ptr::null(),
                digest.as_ptr(),
                32,
                signature.as_mut_ptr(),
                64,
                &mut written,
                NCRYPT_SILENT_FLAG,
            )
        })?;
        if written != 64 {
            return Err(TpmKeyError::InvalidOutput);
        }
        Ok(signature)
    }

    /// Deletes the persisted key, returning it on failure.
    ///
    /// Handles opened separately keep signing after deletion.
    pub fn delete(mut self) -> Result<(), TpmDeleteError> {
        let key = self.key.get_mut();
        // Platform deletion rejects `NCRYPT_SILENT_FLAG` with `NTE_BAD_FLAGS`.
        // SAFETY: Exclusive live handle, freed only on success.
        let status = unsafe { NCryptDeleteKey(key.0, 0) };
        if let Err(error) = check(status) {
            return Err(TpmDeleteError { key: self, error });
        }
        key.0 = 0;
        Ok(())
    }
}

fn key_name(name: &str) -> Result<Vec<u16>, TpmKeyError> {
    if name.is_empty() || name.contains('\0') {
        return Err(TpmKeyError::InvalidName);
    }
    Ok(name.encode_utf16().chain(Some(0)).collect())
}

/// Names the creation lock from the user SID and a hash of the key name, staying under `MAX_PATH`.
fn lock_name(name: &[u16]) -> Result<Vec<u16>, TpmKeyError> {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for unit in name {
        hash = (hash ^ u64::from(*unit)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    let mut text = String::from("Global\\windows-native-keyring-store-tpm-");
    for byte in user_sid()? {
        write!(text, "{byte:02x}").unwrap();
    }
    write!(text, "-{hash:016x}").unwrap();
    Ok(text.encode_utf16().chain(Some(0)).collect())
}

/// Returns the SID of the thread's effective token, matching NCrypt's per-user key store.
fn user_sid() -> Result<Vec<u8>, TpmKeyError> {
    // `GetCurrentThreadEffectiveToken()` pseudo-handle from `processthreadsapi.h`.
    let token = ptr::without_provenance_mut((-6isize).cast_unsigned());
    let mut buffer = [0usize; 16];
    let mut written = 0;
    // SAFETY: Queryable pseudo-token, writable aligned 128-byte buffer and result pointer.
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            128,
            &mut written,
        )
    } == 0
    {
        return Err(last_error());
    }
    // SAFETY: Success wrote a `TOKEN_USER` whose SID lies inside `buffer`.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: `sid` is valid while `buffer` lives.
    let length = unsafe { GetLengthSid(sid) } as usize;
    // SAFETY: `GetLengthSid` bounds the SID bytes inside `buffer`.
    Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) }.to_vec())
}

fn last_error() -> TpmKeyError {
    // SAFETY: Reads this thread's last error.
    win32_error(unsafe { GetLastError() })
}

fn win32_error(code: u32) -> TpmKeyError {
    TpmKeyError::Windows((code & 0xffff | 0x8007_0000).cast_signed())
}

fn open_provider() -> Result<OwnedHandle, TpmKeyError> {
    let mut raw = 0;
    // SAFETY: Static terminated name and writable output handle.
    check_provider(unsafe { NCryptOpenStorageProvider(&mut raw, MS_PLATFORM_CRYPTO_PROVIDER, 0) })?;
    Ok(OwnedHandle(raw))
}

fn check_provider(status: i32) -> Result<(), TpmKeyError> {
    if status == STATUS_NOT_FOUND {
        Err(TpmKeyError::Unavailable(status))
    } else {
        check(status)
    }
}

fn check(status: i32) -> Result<(), TpmKeyError> {
    match status {
        0 => Ok(()),
        NTE_BAD_PROVIDER
        | NTE_PROV_DLL_NOT_FOUND
        | NTE_DEVICE_NOT_FOUND
        | NTE_DEVICE_NOT_READY
        | NTE_BAD_ALGID
        | NTE_NOT_SUPPORTED
        | NTE_SILENT_CONTEXT
        | TBS_E_SERVICE_DISABLED
        | TBS_E_SERVICE_NOT_RUNNING
        | TBS_E_TPM_NOT_FOUND
        | TBSIMP_E_TPM_INCOMPATIBLE
        | TPM_E_PCP_DEVICE_NOT_READY
        | TPM_E_PCP_NOT_SUPPORTED
        | TPM_E_DISABLED
        | TPM_E_DEACTIVATED
        | TPM_E_BAD_ORDINAL
        | TPM_20_E_ASYMMETRIC
        | TPM_20_E_COMMAND_CODE
        | TPM_20_E_CURVE
        | TPM_20_E_DISABLED
        | TPM_20_E_ECC_CURVE => Err(TpmKeyError::Unavailable(status)),
        _ => Err(TpmKeyError::Windows(status)),
    }
}

fn public_point(key: &OwnedHandle) -> Result<[u8; 65], TpmKeyError> {
    let mut blob = [0; 72];
    let mut written = 0;
    // SAFETY: Live key, writable 72-byte buffer and result pointer.
    check(unsafe {
        NCryptExportKey(
            key.0,
            0,
            BCRYPT_ECCPUBLIC_BLOB,
            ptr::null(),
            blob.as_mut_ptr(),
            72,
            &mut written,
            NCRYPT_SILENT_FLAG,
        )
    })?;
    decode_point(&blob, written)
}

fn decode_point(blob: &[u8; 72], written: u32) -> Result<[u8; 65], TpmKeyError> {
    if written != 72 {
        return Err(TpmKeyError::InvalidOutput);
    }
    if blob[..4] != BCRYPT_ECDSA_PUBLIC_P256_MAGIC.to_le_bytes()
        || blob[4..8] != 32u32.to_le_bytes()
    {
        return Err(TpmKeyError::WrongKeyType);
    }
    let mut point = [0; 65];
    point[0] = 4;
    point[1..].copy_from_slice(&blob[8..]);
    Ok(point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::mpsc, time::Duration};

    fn lock_test_name() -> Vec<u16> {
        key_name(&format!("keyring-tpm-lock-test-{:016x}", fastrand::u64(..))).unwrap()
    }

    #[test]
    fn create_lock_times_out_while_held() {
        let name = lock_test_name();
        let (held_tx, held_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let name = &name;
            scope.spawn(move || {
                let _lock = CreateLock::acquire(name, 0).unwrap();
                held_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(30)).unwrap();
            });
            held_rx.recv_timeout(Duration::from_secs(30)).unwrap();
            let error = CreateLock::acquire(name, 100).err();
            release_tx.send(()).unwrap();
            assert_eq!(
                error,
                Some(TpmKeyError::Windows(0x8007_05b4_u32.cast_signed()))
            );
        });
        assert!(CreateLock::acquire(&name, 0).is_ok());
    }

    #[test]
    fn create_lock_recovers_from_abandoned_owner() {
        let name = lock_test_name();
        std::thread::scope(|scope| {
            scope.spawn(|| std::mem::forget(CreateLock::acquire(&name, 0).unwrap()));
        });
        assert!(CreateLock::acquire(&name, 1_000).is_ok());
    }

    #[test]
    fn rejects_wrong_curve_and_malformed_public_blobs() {
        let mut blob = [0; 72];
        blob[..4].copy_from_slice(&BCRYPT_ECDSA_PUBLIC_P256_MAGIC.to_le_bytes());
        blob[4..8].copy_from_slice(&32u32.to_le_bytes());
        assert_eq!(decode_point(&blob, 71), Err(TpmKeyError::InvalidOutput));
        blob[4] = 48;
        assert_eq!(decode_point(&blob, 72), Err(TpmKeyError::WrongKeyType));
        blob[4] = 32;
        blob[0] ^= 1;
        assert_eq!(decode_point(&blob, 72), Err(TpmKeyError::WrongKeyType));
    }

    #[test]
    fn lock_name_is_a_valid_mutex_name() {
        let long = key_name(&"\\".repeat(4096)).unwrap();
        let short = key_name("a").unwrap();
        let name = lock_name(&long).unwrap();
        assert!(name.len() <= 260);
        let text = String::from_utf16(&name[..name.len() - 1]).unwrap();
        assert!(!text["Global\\".len()..].contains('\\'));
        assert_eq!(name, lock_name(&long).unwrap());
        assert_ne!(name, lock_name(&short).unwrap());
    }

    #[test]
    fn absent_provider_is_unavailable() {
        let name = windows_sys::core::w!("keyring-test-provider-that-does-not-exist");
        let mut raw = 0;
        // SAFETY: Static terminated name and writable output handle.
        let status = unsafe { NCryptOpenStorageProvider(&mut raw, name, 0) };
        if status == 0 {
            drop(OwnedHandle(raw));
        }
        let error = check_provider(status).unwrap_err();
        eprintln!("Missing provider result {error:?}");
        assert!(matches!(error, TpmKeyError::Unavailable(_)));
    }

    #[test]
    fn check_separates_success_unavailability_and_other_failures() {
        assert_eq!(check(0), Ok(()));
        assert_eq!(
            check(TPM_E_DISABLED),
            Err(TpmKeyError::Unavailable(TPM_E_DISABLED))
        );
        assert_eq!(
            check(NTE_BAD_KEYSET),
            Err(TpmKeyError::Windows(NTE_BAD_KEYSET))
        );
    }

    #[test]
    fn private_key_cannot_be_exported() {
        use windows_sys::Win32::Security::Cryptography::BCRYPT_ECCPRIVATE_BLOB;
        let name = format!("keyring-tpm-private-test-{:016x}", fastrand::u64(..));
        let key = match TpmSigningKey::create(&name) {
            Ok(key) => key,
            Err(TpmKeyError::Unavailable(_)) => return,
            Err(error) => panic!("create failed {error}"),
        };
        let status = {
            let handle = key.key.lock();
            let mut private_blob = [0; 104];
            let mut written = 0;
            // SAFETY: Locked live key, writable 104-byte buffer and result pointer.
            unsafe {
                NCryptExportKey(
                    handle.0,
                    0,
                    BCRYPT_ECCPRIVATE_BLOB,
                    ptr::null(),
                    private_blob.as_mut_ptr(),
                    104,
                    &mut written,
                    NCRYPT_SILENT_FLAG,
                )
            }
        };
        key.delete().unwrap();
        assert_ne!(status, 0, "private key export must be forbidden");
    }
}

//! Sealed entries shared by the protected stores, encrypted under one key per store.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use keyring_core::attributes::parse_attributes;
use keyring_core::{Entry, Error, Result};
use windows_sys::Win32::Security::Credentials::{
    CRED_MAX_CREDENTIAL_BLOB_SIZE, CredEnumerateW, CredFree,
};
use zeroize::Zeroizing;

use crate::cred::Cred;
use crate::sealed_crypto::{PROTECTED_OVERHEAD, check_layout, is_protected, open, seal};
use crate::sealed_lock::lock_target;
use crate::utils::{
    CredPersist, FoldedName, extract_attributes, extract_from_credential, extract_secret, hex,
    save_credential, save_spelled_credential, validate_attributes, validate_secret,
    validate_spelling, validate_target,
};

/// Why a sealed store refused an operation.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SealError {
    /// The store holds no key, so sealed entries cannot be read or written.
    #[error("sealed store is locked")]
    Locked,
    /// The key does not open this store's keycheck record.
    #[error("key does not open this sealed store")]
    WrongKey,
    /// A sealed record failed authentication or has an unknown layout.
    #[error("sealed store is corrupt ({0})")]
    Corrupt(String),
    /// Credential Manager or another Windows service failed.
    #[error("sealed store operation failed ({0})")]
    Platform(String),
    /// Another process held the store's lock for too long.
    #[error("sealed store lock timed out")]
    TimedOut,
}

impl From<SealError> for Error {
    fn from(error: SealError) -> Self {
        match error {
            SealError::Corrupt(reason) => Error::BadStoreFormat(reason),
            SealError::Platform(_) => Error::PlatformFailure(Box::new(error)),
            _ => Error::NoStorageAccess(Box::new(error)),
        }
    }
}

pub(crate) type SealResult<T> = std::result::Result<T, SealError>;

/// Recovers a poisoned guard, since no store invariant depends on a panicking holder.
pub(crate) fn unpoison<T>(result: std::sync::LockResult<T>) -> T {
    result.unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Whether a sealed store currently holds its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// No key is held.
    Locked,
    /// The key is held until `lock` or drop.
    Unlocked,
}

pub(crate) const MAX_PROTECTED_PLAINTEXT: usize =
    CRED_MAX_CREDENTIAL_BLOB_SIZE as usize - PROTECTED_OVERHEAD;

/// Scoped targets, keycheck and key of one sealed store, shared by its entries.
pub(crate) struct Gate {
    prefix: String,
    key: Mutex<Option<Zeroizing<[u8; 32]>>>,
}

/// The gate of a sealed entry and the `{user}.{service}` spelling its caller used.
#[derive(Clone)]
pub(crate) struct SealedEntry {
    pub(crate) gate: Arc<Gate>,
    pub(crate) spelling: String,
}

impl Gate {
    pub(crate) fn new(application: &str, store: &str) -> Result<Arc<Self>> {
        if application.is_empty() || store.is_empty() {
            return Err(Error::Invalid(
                "application/store".into(),
                "identifiers cannot be empty".into(),
            ));
        }
        let mut prefix = "keyring:sealed:1:".to_owned();
        for identifier in [application, store] {
            prefix += &format!("{:x}:{}:", identifier.len(), hex(identifier.as_bytes()));
        }
        validate_target(&format!("{prefix}keycheck"), "")?;
        Ok(Arc::new(Self {
            prefix,
            key: Mutex::new(None),
        }))
    }

    pub(crate) fn id(&self) -> String {
        self.prefix.clone()
    }

    pub(crate) fn protection(&self) -> Protection {
        if unpoison(self.key.lock()).is_some() {
            Protection::Unlocked
        } else {
            Protection::Locked
        }
    }

    /// Builds an entry whose target is scoped to this store and whose secret is sealed.
    ///
    /// The target encodes the name in the case Credential Manager compares it in, so every
    /// spelling a plain `Store` treats as one credential is one sealed entry.
    pub(crate) fn build(
        self: &Arc<Self>,
        service: &str,
        user: &str,
        modifiers: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        let modifiers = parse_attributes(&["target", "persistence"], modifiers)?;
        if modifiers.contains_key("target") {
            return Err(Error::Invalid(
                "target".into(),
                "sealed targets are derived from service and user".into(),
            ));
        }
        let persistence: CredPersist = modifiers
            .get("persistence")
            .map_or("Local", String::as_str)
            .parse()?;
        if persistence != CredPersist::Local {
            return Err(Error::Invalid(
                "persistence".into(),
                "sealed entries require Local persistence".into(),
            ));
        }
        let delimiters = [String::new(), ".".into(), String::new()];
        let mut cred =
            Cred::build_from_specifiers(None, &delimiters, false, service, user, persistence)?;
        let spelling = std::mem::take(&mut cred.target_name);
        validate_spelling(&spelling)?;
        cred.target_name = self.scoped_target(&spelling)?;
        cred.sealed = Some(SealedEntry {
            gate: Arc::clone(self),
            spelling,
        });
        Ok(Entry::new_with_credential(Arc::new(cred)))
    }

    fn scoped_target(&self, spelling: &str) -> Result<String> {
        let folded = FoldedName::new(spelling)?;
        let target = format!("{}entry:{}", self.prefix, hex(folded.as_str().as_bytes()));
        validate_target(&target, "")?;
        Ok(target)
    }

    fn keycheck_target(&self) -> String {
        format!("{}keycheck", self.prefix)
    }

    /// Erases the key, so entries stay sealed until the next unlock.
    pub(crate) fn lock(&self) {
        *unpoison(self.key.lock()) = None;
    }

    /// Verifies `key` against the keycheck record, writing it for a new store, then holds it.
    pub(crate) fn unlock(&self, key: &[u8; 32]) -> SealResult<()> {
        let keycheck = self.keycheck_target();
        let _keycheck_lock = lock_target(&keycheck)?;
        match read_raw(&keycheck)? {
            Some(blob) if !is_protected(&blob) => {
                return Err(SealError::Corrupt("keycheck record is unsealed".into()));
            }
            Some(blob) => {
                // Only an authentication failure on a well-formed record means another key.
                check_layout(&blob)?;
                open(key, &self.prefix, &keycheck, &blob).map_err(|_| SealError::WrongKey)?;
            }
            None if self.has_scoped_entries()? => {
                return Err(SealError::Corrupt("keycheck record is missing".into()));
            }
            None => {
                let sealed = seal(key, &self.prefix, &keycheck, &[])?;
                save_credential(&keycheck, "", "", "", &sealed, &CredPersist::Local)
                    .map_err(platform)?;
            }
        }
        *unpoison(self.key.lock()) = Some(Zeroizing::new(*key));
        Ok(())
    }

    fn scoped_targets(&self) -> SealResult<Vec<String>> {
        let entry_prefix = format!("{}entry:", self.prefix);
        let filter: Vec<u16> = format!("{entry_prefix}*\0").encode_utf16().collect();
        let mut count = 0;
        let mut entries = std::ptr::null_mut();
        // SAFETY: `filter` is NUL-terminated and both out pointers are writable locals.
        if unsafe { CredEnumerateW(filter.as_ptr(), 0, &mut count, &mut entries) } == 0 {
            return match crate::utils::decode_error() {
                Error::NoEntry => Ok(Vec::new()),
                error => Err(platform(error)),
            };
        }
        // SAFETY: on success `entries` holds `count` credential pointers owned until `CredFree`.
        let native = unsafe {
            std::slice::from_raw_parts(
                entries,
                usize::try_from(count).expect("u32 fits usize on Windows"),
            )
        };
        let listed: Vec<String> = native
            .iter()
            // SAFETY: every enumerated pointer refers to a credential that lives until `CredFree`.
            .map(|credential| crate::utils::target_name(unsafe { &**credential }))
            .collect();
        // SAFETY: `entries` came from the successful enumeration above and is freed exactly once.
        unsafe { CredFree(entries.cast()) };
        // Credential Manager matches the filter by `FoldedName`'s rule and keeps the last writer's
        // spelling, so each listed name is checked in its folded and lowered form.
        listed
            .into_iter()
            .map(|target| {
                let folded = FoldedName::new(&target).map_err(platform)?;
                scoped_canonical(&folded, &entry_prefix)
            })
            .collect()
    }

    fn has_scoped_entries(&self) -> SealResult<bool> {
        Ok(!self.scoped_targets()?.is_empty())
    }

    fn with_key<T>(&self, action: impl FnOnce(&[u8; 32]) -> Result<T>) -> Result<T> {
        let key = unpoison(self.key.lock());
        action(key.as_ref().ok_or(SealError::Locked)?)
    }

    /// Opens the sealed secret of `target`, refusing an unsealed record.
    fn open_scoped(&self, target: &str, key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
        let blob = read_raw(target)?.ok_or(Error::NoEntry)?;
        if !is_protected(&blob) {
            return Err(SealError::Corrupt("scoped secret is unsealed".into()).into());
        }
        Ok(open(key, &self.prefix, target, &blob)?)
    }

    pub(crate) fn get_secret(&self, target: &str) -> Result<Vec<u8>> {
        self.with_key(|key| Ok(std::mem::take(&mut *self.open_scoped(target, key)?)))
    }

    pub(crate) fn set_secret(
        &self,
        target: &str,
        spelling: &str,
        user: &str,
        secret: &[u8],
    ) -> Result<()> {
        validate_protected_plaintext(secret)?;
        self.with_key(|key| {
            // A record that does not open is kept for inspection, never overwritten.
            let attributes = match self.open_scoped(target, key) {
                Ok(_) => Some(extract_from_credential(target, extract_attributes)?),
                Err(Error::NoEntry) => None,
                Err(error) => return Err(error),
            };
            let field = |name: &str, absent| {
                attributes
                    .as_ref()
                    .map_or(absent, |attributes| attributes[name].as_str())
            };
            let sealed = seal(key, &self.prefix, target, secret)?;
            validate_secret(&sealed)?;
            save_spelled_credential(
                target,
                field("username", user),
                field("target_alias", ""),
                field("comment", ""),
                &sealed,
                spelling,
            )
        })
    }

    pub(crate) fn update_attributes(
        &self,
        target: &str,
        spelling: &str,
        user: &str,
        alias: &str,
        comment: &str,
    ) -> Result<()> {
        validate_attributes(user, alias, comment)?;
        self.with_key(|key| {
            let secret = self.open_scoped(target, key)?;
            let sealed = seal(key, &self.prefix, target, &secret)?;
            save_spelled_credential(target, user, alias, comment, &sealed, spelling)
        })
    }

    pub(crate) fn attributes(&self, target: &str) -> Result<HashMap<String, String>> {
        self.with_key(|key| {
            self.open_scoped(target, key)?;
            extract_from_credential(target, extract_attributes)
        })
    }
}

/// A listed name is one of the store's scoped targets exactly when its folded form is ASCII
/// and, lowered again, has the store's entry prefix.
pub(crate) fn scoped_canonical(folded: &FoldedName, entry_prefix: &str) -> SealResult<String> {
    let canonical = folded.as_str().to_ascii_lowercase();
    if folded.as_str().is_ascii() && canonical.starts_with(entry_prefix) {
        Ok(canonical)
    } else {
        Err(SealError::Corrupt(
            "credential enumeration escaped the scoped prefix".into(),
        ))
    }
}

fn read_raw(target: &str) -> SealResult<Option<Zeroizing<Vec<u8>>>> {
    match extract_from_credential(target, extract_secret) {
        Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
        Err(Error::NoEntry) => Ok(None),
        Err(error) => Err(platform(error)),
    }
}

fn platform(error: impl std::fmt::Display) -> SealError {
    SealError::Platform(error.to_string())
}

pub(crate) fn validate_protected_plaintext(secret: &[u8]) -> Result<()> {
    if secret.len() > MAX_PROTECTED_PLAINTEXT {
        return Err(Error::TooLong(
            "secret".into(),
            u32::try_from(MAX_PROTECTED_PLAINTEXT).expect("Credential Manager bound fits u32"),
        ));
    }
    Ok(())
}

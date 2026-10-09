//! Sealed entries shared by the protected stores, encrypted under one key per store.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use keyring_core::attributes::parse_attributes;
use keyring_core::{Entry, Error, Result};
use windows_sys::Win32::Security::Credentials::{
    CRED_MAX_CREDENTIAL_BLOB_SIZE, CREDENTIALW, CredEnumerateW, CredFree,
};
use zeroize::Zeroizing;

use crate::cred::Cred;
use crate::sealed_crypto::{PROTECTED_OVERHEAD, check_layout, is_protected, open, seal};
use crate::sealed_lock::{lock_target, lock_target_with_timeout};
use crate::utils::{
    CredPersist, FoldedName, delete_credential, extract_attributes, extract_from_credential,
    extract_secret, hex, save_credential, save_spelled_credential, validate_attributes,
    validate_secret, validate_spelling, validate_target,
};

/// Why a sealed store refused an operation.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SealError {
    /// The store holds no key, or the Windows Hello authenticator is locked.
    #[error("sealed store or its authenticator is locked")]
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
    /// A discard of this store started and has not finished.
    #[error("sealed store discard is incomplete")]
    Discarding,
    /// This handle predates a finished discard, so the store must be opened again.
    #[error("sealed store was discarded")]
    Discarded,
    /// This machine lacks what the store needs, such as WebAuthn API 9 or Windows Hello.
    #[error("sealed store is unsupported here ({0})")]
    Unsupported(String),
    /// The platform reports an ambiguous state the store refuses to guess about.
    #[error("sealed store found a conflict ({0})")]
    Conflict(String),
    /// The window meant to own the Windows Hello prompt is missing or no longer live.
    #[error("Windows Hello owner window is missing or no longer live")]
    MissingOwner,
    /// The caller cancelled, or `lock` revoked, a Windows Hello request.
    #[error("Windows Hello request was cancelled")]
    Cancelled,
    /// The store's Windows Hello passkey is gone or no longer matches its entries.
    #[error("Windows Hello credential for this store was lost")]
    KeyLost,
    /// The legacy source was deleted but the scoped record was not.
    #[error("legacy source deleted but scoped deletion failed ({0})")]
    IncompleteDeletion(String),
}

impl From<SealError> for Error {
    fn from(error: SealError) -> Self {
        match error {
            SealError::Corrupt(reason) => Error::BadStoreFormat(reason),
            SealError::Unsupported(reason) => Error::NotSupportedByStore(reason),
            SealError::Platform(_) | SealError::Conflict(_) | SealError::IncompleteDeletion(_) => {
                Error::PlatformFailure(Box::new(error))
            }
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
    /// The store's Windows Hello passkey was lost, so only `discard` can proceed.
    Lost,
}

pub(crate) const MAX_PROTECTED_PLAINTEXT: usize =
    CRED_MAX_CREDENTIAL_BLOB_SIZE as usize - PROTECTED_OVERHEAD;
pub(crate) const CONTROL_MAGIC: &[u8; 5] = b"SCTL1";
const MIGRATION_PENDING: &[u8; 5] = b"SMIG1";

/// The store's discard state, which retires every handle that saw another generation.
#[derive(Clone, Copy)]
pub(crate) struct Control {
    discarding: bool,
    generation: [u8; 16],
}

/// Which store owns a gate, fixing its target prefix and whether it keeps a keycheck record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Sealed,
    Hello,
}

/// The key and the facts that decide whether it may be published.
struct KeyState {
    key: Option<Zeroizing<[u8; 32]>>,
    // Bumped by `lock`, so a request that started earlier cannot publish.
    epoch: u64,
    lost: bool,
}

/// Scoped targets, control record and key of one sealed store, shared by its entries.
pub(crate) struct Gate {
    prefix: String,
    generation: Option<[u8; 16]>,
    state: Mutex<KeyState>,
}

/// The gate of a sealed entry and the `{user}.{service}` spelling its caller used.
#[derive(Clone)]
pub(crate) struct SealedEntry {
    pub(crate) gate: Arc<Gate>,
    pub(crate) spelling: String,
}

impl Gate {
    pub(crate) fn new(kind: Kind, application: &str, store: &str) -> Result<Arc<Self>> {
        if application.is_empty() || store.is_empty() {
            return Err(Error::Invalid(
                "application/store".into(),
                "identifiers cannot be empty".into(),
            ));
        }
        let mut prefix = match kind {
            Kind::Sealed => "keyring:sealed:1:",
            Kind::Hello => "keyring:hello-prf:1:",
        }
        .to_owned();
        for identifier in [application, store] {
            prefix += &format!("{:x}:{}:", identifier.len(), hex(identifier.as_bytes()));
        }
        validate_target(&format!("{prefix}keycheck"), "")?;
        validate_target(&format!("{prefix}metadata"), "")?;
        let generation = match read_control(&format!("{prefix}control")) {
            Ok(control) => control.map(|control| control.generation),
            // An unreadable record opens blocked, so only `discard` can proceed.
            Err(SealError::Corrupt(_)) => None,
            Err(error) => return Err(error.into()),
        };
        Ok(Arc::new(Self {
            prefix,
            generation,
            state: Mutex::new(KeyState {
                key: None,
                epoch: 0,
                lost: false,
            }),
        }))
    }

    pub(crate) fn id(&self) -> String {
        self.prefix.clone()
    }

    pub(crate) fn protection(&self) -> Protection {
        let state = unpoison(self.state.lock());
        if state.lost {
            Protection::Lost
        } else if state.key.is_some() {
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
        validate_target(&self.marker_target(&target)?, "")?;
        Ok(target)
    }

    fn keycheck_target(&self) -> String {
        format!("{}keycheck", self.prefix)
    }

    pub(crate) fn control_target(&self) -> String {
        format!("{}control", self.prefix)
    }

    pub(crate) fn metadata_target(&self) -> String {
        format!("{}metadata", self.prefix)
    }

    pub(crate) fn check_control(&self) -> SealResult<()> {
        let control = match read_control(&self.control_target()) {
            Ok(control) => control,
            Err(SealError::Corrupt(_)) => return Err(SealError::Discarding),
            Err(error) => return Err(error),
        };
        match control {
            Some(control) if control.discarding => Err(SealError::Discarding),
            Some(control) if Some(control.generation) == self.generation => Ok(()),
            None if self.generation.is_none() => Ok(()),
            _ => Err(SealError::Discarded),
        }
    }

    // Discard writes its marker under the same lock, so a passed check holds for `action`.
    fn guarded<T, E: From<SealError>>(
        &self,
        action: impl FnOnce() -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        let _store = lock_target(&self.control_target())?;
        self.check_control()?;
        action()
    }

    /// Erases the key and retires every request started before this call.
    pub(crate) fn lock(&self) {
        let mut state = unpoison(self.state.lock());
        state.key = None;
        state.epoch += 1;
    }

    /// The publication epoch a request must present to `settle`.
    pub(crate) fn epoch(&self) -> u64 {
        unpoison(self.state.lock()).epoch
    }

    /// Publishes a request's key unless `lock` ran since `epoch`, marking the store lost on loss.
    pub(crate) fn settle(
        &self,
        epoch: u64,
        result: SealResult<Zeroizing<[u8; 32]>>,
    ) -> SealResult<()> {
        let mut state = unpoison(self.state.lock());
        if state.epoch != epoch {
            return Err(SealError::Cancelled);
        }
        match result {
            Ok(key) => {
                state.key = Some(key);
                Ok(())
            }
            Err(error) => {
                if matches!(error, SealError::KeyLost | SealError::Corrupt(_)) {
                    state.lost = true;
                }
                Err(error)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn install_key(&self, key: [u8; 32]) {
        unpoison(self.state.lock()).key = Some(Zeroizing::new(key));
    }

    /// Verifies `key` against the keycheck record, writing it for a new store, then holds it.
    pub(crate) fn unlock(&self, key: &[u8; 32]) -> SealResult<()> {
        self.guarded(|| {
            let keycheck = self.keycheck_target();
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
            unpoison(self.state.lock()).key = Some(Zeroizing::new(*key));
            Ok(())
        })
    }

    /// Deletes every entry and the keycheck, retiring all existing handles of this store.
    pub(crate) fn discard(&self, timeout: Duration) -> SealResult<()> {
        #[cfg(test)]
        crate::pause::reached(&self.prefix, "discard.entered")?;
        let deadline = deadline(timeout)?;
        // One transaction, so no discarder or writer acts between the marker and the new generation.
        let _store = lock_target_with_timeout(&self.control_target(), remaining(deadline))?;
        self.mark_discarding()?;
        self.lock();
        #[cfg(test)]
        crate::pause::reached(&self.prefix, "discard.deleting")?;
        self.delete_entries()?;
        self.publish_generation()
    }

    /// Deletes every scoped entry and pending-migration marker, then the keycheck record.
    pub(crate) fn delete_entries(&self) -> SealResult<()> {
        for target in self
            .targets_under("entry:")?
            .into_iter()
            .chain(self.targets_under("migration:")?)
        {
            delete_owned(&target)?;
        }
        delete_owned(&self.keycheck_target())
    }

    /// Persists the discard marker, or keeps an interrupted one, under the caller's control lock.
    pub(crate) fn mark_discarding(&self) -> SealResult<Control> {
        let control_target = self.control_target();
        let marker = match read_control(&control_target) {
            Ok(Some(control)) if control.discarding => return Ok(control),
            Ok(Some(control)) if Some(control.generation) == self.generation => Control {
                discarding: true,
                ..control
            },
            Ok(None) if self.generation.is_none() => Control {
                discarding: true,
                generation: random_generation()?,
            },
            // An unreadable record is an interrupted discard that any handle may resume.
            Err(SealError::Corrupt(_)) => Control {
                discarding: true,
                generation: random_generation()?,
            },
            Ok(_) => return Err(SealError::Discarded),
            Err(error) => return Err(error),
        };
        save_control(&control_target, &marker)?;
        Ok(marker)
    }

    /// Whether `marker` is still the recorded discard, under the caller's control lock.
    ///
    /// Another record means another handle finished this discard. A missing or unreadable one is
    /// marked again, since the caller is about to delete everything anyway.
    pub(crate) fn still_discarding(&self, marker: &Control) -> SealResult<bool> {
        match read_control(&self.control_target()) {
            Ok(Some(control)) => Ok(control.discarding && control.generation == marker.generation),
            Ok(None) | Err(SealError::Corrupt(_)) => {
                save_control(&self.control_target(), marker)?;
                Ok(true)
            }
            Err(error) => Err(error),
        }
    }

    /// Ends a discard with a fresh generation, under the caller's control lock.
    pub(crate) fn publish_generation(&self) -> SealResult<()> {
        save_control(
            &self.control_target(),
            &Control {
                discarding: false,
                generation: random_generation()?,
            },
        )
    }

    fn scoped_targets(&self) -> SealResult<Vec<String>> {
        self.targets_under("entry:")
    }

    /// Every target of this store that starts with `kind` after the store prefix.
    fn targets_under(&self, kind: &str) -> SealResult<Vec<String>> {
        Ok(self
            .listed_under(kind, |_| ())?
            .into_iter()
            .map(|(target, ())| target)
            .collect())
    }

    /// Every record of this store under `kind`, by canonical target, with what `read` takes from it.
    fn listed_under<T>(
        &self,
        kind: &str,
        read: impl Fn(&CREDENTIALW) -> T,
    ) -> SealResult<Vec<(String, T)>> {
        let kind_prefix = format!("{}{kind}", self.prefix);
        let filter: Vec<u16> = format!("{kind_prefix}*\0").encode_utf16().collect();
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
        let listed: Vec<(String, T)> = native
            .iter()
            .map(|credential| {
                // SAFETY: every enumerated pointer refers to a credential that lives until `CredFree`.
                let credential = unsafe { &**credential };
                (crate::utils::target_name(credential), read(credential))
            })
            .collect();
        // SAFETY: `entries` came from the successful enumeration above and is freed exactly once.
        unsafe { CredFree(entries.cast()) };
        // Credential Manager matches the filter by `FoldedName`'s rule and keeps the last writer's
        // spelling, so each listed name is checked in its folded and lowered form.
        listed
            .into_iter()
            .map(|(target, value)| {
                let folded = FoldedName::new(&target).map_err(platform)?;
                scoped_canonical(&folded, &kind_prefix).map(|canonical| (canonical, value))
            })
            .collect()
    }

    pub(crate) fn has_scoped_entries(&self) -> SealResult<bool> {
        Ok(!self.scoped_targets()?.is_empty())
    }

    fn with_key<T>(&self, action: impl FnOnce(&[u8; 32]) -> Result<T>) -> Result<T> {
        self.guarded(|| {
            let state = unpoison(self.state.lock());
            let key = state.key.as_ref().ok_or(if state.lost {
                SealError::KeyLost
            } else {
                SealError::Locked
            })?;
            action(key)
        })
    }

    /// Opens the sealed secret of `target`, refusing an unsealed record.
    fn open_scoped(&self, target: &str, key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
        let blob = read_raw(target)?.ok_or(Error::NoEntry)?;
        if !is_protected(&blob) {
            return Err(SealError::Corrupt("scoped secret is unsealed".into()).into());
        }
        Ok(open(key, &self.prefix, target, &blob)?)
    }

    /// The hex-encoded plain target that the scoped `target` was derived from.
    fn encoded_legacy<'a>(&self, target: &'a str) -> Result<&'a str> {
        target
            .strip_prefix(&self.prefix)
            .and_then(|suffix| suffix.strip_prefix("entry:"))
            .ok_or_else(|| Error::BadStoreFormat("entry escaped its scoped prefix".into()))
    }

    /// The plain `Store` target, in the folded case, that the scoped `target` was derived from.
    fn legacy_target(&self, target: &str) -> Result<String> {
        Ok(decode_hex(self.encoded_legacy(target)?)?)
    }

    /// The record whose presence marks the migration into `target` as unfinished.
    fn marker_target(&self, target: &str) -> Result<String> {
        Ok(format!(
            "{}migration:{}",
            self.prefix,
            self.encoded_legacy(target)?
        ))
    }

    /// Opens the scoped secret, first finishing or starting the migration of its plain source.
    fn migrate(&self, target: &str, spelling: &str, key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
        let legacy = &self.legacy_target(target)?;
        let marker = &self.marker_target(target)?;
        // Stores sharing a service and user share this legacy source, and its folded name gives
        // every spelling Credential Manager matches the same lock.
        let _source = lock_target(legacy)?;
        let pending = read_raw(marker)?.is_some();
        let sealed = match self.open_scoped(target, key) {
            Ok(secret) if !pending => return Ok(secret),
            Ok(secret) => Some(secret),
            Err(Error::NoEntry) => None,
            Err(error) => return Err(error),
        };
        let current = match snapshot(legacy) {
            Ok(current) => current,
            // Without a plain source the sealed copy, if any, is the whole entry.
            Err(Error::NoEntry) => {
                delete_owned(marker)?;
                return sealed.ok_or(Error::NoEntry);
            }
            Err(error) => return Err(error),
        };
        if let Some(secret) = sealed {
            let stored = extract_from_credential(target, extract_attributes)?;
            if *secret == *current.source && same_fields(&stored, &current.attributes) {
                self.finish_migration(target, legacy, marker)?;
                return Ok(secret);
            }
        }
        // While `marker` exists the sealed copy holds only migration snapshots, so `current` wins.
        self.migrate_from(target, spelling, key, legacy, marker, current)
    }

    /// Seals `taken` from the plain source into `target`, then deletes the source.
    fn migrate_from(
        &self,
        target: &str,
        spelling: &str,
        key: &[u8; 32],
        legacy: &str,
        marker: &str,
        taken: Snapshot,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let Snapshot { source, attributes } = taken;
        validate_protected_plaintext(&source)?;
        let sealed = seal(key, &self.prefix, target, &source)?;
        validate_secret(&sealed)?;
        save_credential(marker, "", "", "", MIGRATION_PENDING, &CredPersist::Local)?;
        #[cfg(test)]
        crate::pause::reached(&self.prefix, "migrate.marked")?;
        save_spelled_credential(
            target,
            &attributes["username"],
            &attributes["target_alias"],
            &attributes["comment"],
            &sealed,
            spelling,
        )?;
        #[cfg(test)]
        crate::pause::reached(&self.prefix, "migrate.sealed")?;
        // Content decides, since deleting a plain entry rewritten with the same data loses nothing.
        let conflict = match snapshot(legacy) {
            Ok(current) => source_changed(&source, &attributes, &current),
            Err(Error::NoEntry) => true,
            Err(error) => return Err(error),
        };
        if conflict {
            return self.roll_back(target, legacy, marker);
        }
        self.finish_migration(target, legacy, marker)?;
        Ok(source)
    }

    /// Deletes the plain source, then the marker, so the migration counts as complete.
    fn finish_migration(&self, target: &str, legacy: &str, marker: &str) -> Result<()> {
        #[cfg(test)]
        crate::pause::reached(&self.prefix, "migrate.delete-plain")?;
        match delete_credential(legacy) {
            Ok(()) => {}
            // A plain source deleted by someone else takes its sealed copy with it.
            Err(Error::NoEntry) => return self.roll_back(target, legacy, marker),
            Err(error) => return Err(error),
        }
        delete_owned(marker)?;
        Ok(())
    }

    /// Removes the sealed copy this migration wrote, then the marker, and reports the conflict.
    fn roll_back<T>(&self, target: &str, legacy: &str, marker: &str) -> Result<T> {
        #[cfg(test)]
        crate::pause::reached(&self.prefix, "migrate.rollback")?;
        delete_owned(target)?;
        delete_owned(marker)?;
        Err(SealError::Conflict(legacy.into()).into())
    }

    pub(crate) fn get_secret(&self, target: &str, spelling: &str) -> Result<Vec<u8>> {
        self.with_key(|key| Ok(std::mem::take(&mut *self.migrate(target, spelling, key)?)))
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
            let attributes = match self.migrate(target, spelling, key) {
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
            let secret = self.migrate(target, spelling, key)?;
            let sealed = seal(key, &self.prefix, target, &secret)?;
            save_spelled_credential(target, user, alias, comment, &sealed, spelling)
        })
    }

    pub(crate) fn attributes(
        &self,
        target: &str,
        spelling: &str,
    ) -> Result<HashMap<String, String>> {
        self.with_key(|key| {
            self.migrate(target, spelling, key)?;
            extract_from_credential(target, extract_attributes)
        })
    }

    /// Deletes the entry, its exact legacy source and any pending migration, without the key.
    pub(crate) fn delete(&self, target: &str) -> Result<()> {
        let legacy = &self.legacy_target(target)?;
        let marker = &self.marker_target(target)?;
        self.guarded(|| {
            let _source = lock_target(legacy)?;
            let legacy_deleted = match delete_credential(legacy) {
                Ok(()) => true,
                Err(Error::NoEntry) => false,
                Err(error) => return Err(error),
            };
            let removed = merge_scoped_deletion(legacy_deleted, delete_credential(target));
            if matches!(removed, Ok(()) | Err(Error::NoEntry)) {
                delete_owned(marker)?;
            }
            removed
        })
    }

    /// Entries of this store whose last written `{user}.{service}` matches the optional `pattern`.
    #[cfg(feature = "search")]
    pub(crate) fn search(self: &Arc<Self>, spec: &HashMap<&str, &str>) -> Result<Vec<Entry>> {
        let spec = parse_attributes(&["pattern"], Some(spec))?;
        let pattern = spec
            .get("pattern")
            .map(|pattern| {
                regex::Regex::new(pattern).map_err(|_| {
                    Error::Invalid(
                        pattern.to_string(),
                        "is not a valid regular expression".into(),
                    )
                })
            })
            .transpose()?;
        let names = regex::Regex::new(r"^(.*)\.(.*)$").expect("the name pattern is valid");
        self.guarded(|| {
            let mut entries = Vec::new();
            for (target_name, spelling) in self.listed_under("entry:", crate::utils::spelling)? {
                // A record written without its spelling is named by its folded name.
                let spelling = match spelling {
                    Some(spelling) => spelling,
                    None => self.legacy_target(&target_name)?,
                };
                if pattern
                    .as_ref()
                    .is_some_and(|pattern| !pattern.is_match(&spelling))
                {
                    continue;
                }
                let specifiers = names
                    .captures(&spelling)
                    .map(|captures| (captures[2].to_owned(), captures[1].to_owned()));
                entries.push(Entry::new_with_credential(Arc::new(Cred {
                    target_name,
                    specifiers,
                    persistence: CredPersist::Local,
                    sealed: Some(SealedEntry {
                        gate: Arc::clone(self),
                        spelling,
                    }),
                })));
            }
            Ok(entries)
        })
    }
}

#[cfg(test)]
impl Gate {
    /// Panics unless this gate of a fresh store takes its control lock and passes its control
    /// check, so a test built on a broken gate fails at once instead of waiting out its bounds.
    pub(crate) fn assert_usable(&self) {
        let control = self.control_target();
        assert!(
            control.starts_with(&self.prefix),
            "the control record {control:?} escapes the store prefix"
        );
        drop(lock_target_with_timeout(&control, Duration::from_secs(2)).expect("the control lock"));
        assert_eq!(self.check_control(), Ok(()));
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

/// A legacy source's content as read before and after sealing, to detect a concurrent writer.
struct Snapshot {
    source: Zeroizing<Vec<u8>>,
    attributes: HashMap<String, String>,
}

fn snapshot(target: &str) -> Result<Snapshot> {
    extract_from_credential(target, |native: &CREDENTIALW| {
        Ok(Snapshot {
            source: Zeroizing::new(extract_secret(native)?),
            attributes: extract_attributes(native)?,
        })
    })
}

/// Whether two credentials carry the same attributes a migration copies.
fn same_fields(left: &HashMap<String, String>, right: &HashMap<String, String>) -> bool {
    ["username", "target_alias", "comment"]
        .iter()
        .all(|name| left.get(*name) == right.get(*name))
}

/// Whether the plain source rewritten after sealing changed content the migration copied.
fn source_changed(
    source: &Zeroizing<Vec<u8>>,
    attributes: &HashMap<String, String>,
    current: &Snapshot,
) -> bool {
    current.source != *source || current.attributes != *attributes
}

/// Merges a scoped deletion with the plain source outcome, so a scoped record
/// already gone does not undo the source deletion.
fn merge_scoped_deletion(legacy_deleted: bool, scoped: Result<()>) -> Result<()> {
    match scoped {
        Err(Error::NoEntry) if legacy_deleted => Ok(()),
        Err(error) if legacy_deleted => {
            Err(SealError::IncompleteDeletion(error.to_string()).into())
        }
        result => result,
    }
}

fn decode_hex(encoded: &str) -> SealResult<String> {
    fn digit(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            _ => None,
        }
    }
    let invalid = || SealError::Corrupt("invalid scoped target encoding".into());
    let (pairs, remainder) = encoded.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(invalid());
    }
    let decoded = pairs
        .iter()
        .map(|&[high, low]| Some(digit(high)? << 4 | digit(low)?))
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(invalid)?;
    String::from_utf8(decoded).map_err(|_| SealError::Corrupt("invalid scoped target UTF-8".into()))
}

pub(crate) fn read_raw(target: &str) -> SealResult<Option<Zeroizing<Vec<u8>>>> {
    match extract_from_credential(target, extract_secret) {
        Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
        Err(Error::NoEntry) => Ok(None),
        Err(error) => Err(platform(error)),
    }
}

pub(crate) fn platform(error: impl std::fmt::Display) -> SealError {
    SealError::Platform(error.to_string())
}

/// The instant `timeout` from now, refusing a timeout too large to represent.
pub(crate) fn deadline(timeout: Duration) -> SealResult<Instant> {
    Instant::now()
        .checked_add(timeout)
        .ok_or(SealError::TimedOut)
}

pub(crate) fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn read_control(target: &str) -> SealResult<Option<Control>> {
    let Some(blob) = read_raw(target)? else {
        return Ok(None);
    };
    let (Some(magic), Some(&state), Some(generation)) = (blob.get(..5), blob.get(5), blob.get(6..))
    else {
        return Err(SealError::Corrupt("invalid store control record".into()));
    };
    let discarding = match state {
        0 => false,
        1 => true,
        _ => return Err(SealError::Corrupt("invalid store control state".into())),
    };
    match (magic == CONTROL_MAGIC, <[u8; 16]>::try_from(generation)) {
        (true, Ok(generation)) => Ok(Some(Control {
            discarding,
            generation,
        })),
        _ => Err(SealError::Corrupt("invalid store control record".into())),
    }
}

fn save_control(target: &str, control: &Control) -> SealResult<()> {
    let mut bytes = CONTROL_MAGIC.to_vec();
    bytes.push(u8::from(control.discarding));
    bytes.extend_from_slice(&control.generation);
    save_credential(target, "", "", "", &bytes, &CredPersist::Local).map_err(platform)
}

fn random_generation() -> SealResult<[u8; 16]> {
    let mut generation = [0; 16];
    getrandom::fill(&mut generation).map_err(platform)?;
    Ok(generation)
}

pub(crate) fn delete_owned(target: &str) -> SealResult<()> {
    match delete_credential(target) {
        Ok(()) | Err(Error::NoEntry) => Ok(()),
        Err(error) => Err(platform(error)),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The byte string `save_control` writes for one `Control`.
    fn control_blob(discarding: bool, generation: &[u8; 16]) -> Vec<u8> {
        let mut bytes = CONTROL_MAGIC.to_vec();
        bytes.push(u8::from(discarding));
        bytes.extend_from_slice(generation);
        bytes
    }

    /// A gate of a store whose published record carries `generation`.
    fn gate_with_record(generation: [u8; 16]) -> Arc<Gate> {
        let application = format!("sealed-unit-{}", fastrand::u64(..));
        let gate = Gate::new(Kind::Hello, &application, "store").unwrap();
        save_credential(
            &gate.control_target(),
            "",
            "",
            "",
            &control_blob(false, &generation),
            &CredPersist::Local,
        )
        .unwrap();
        Gate::new(Kind::Hello, &application, "store").unwrap()
    }

    #[test]
    fn a_published_record_is_not_still_discarding_for_its_generation() {
        let generation = [7u8; 16];
        let gate = gate_with_record(generation);
        let _control = lock_target(&gate.control_target()).expect("the control lock");
        let marker = Control {
            discarding: false,
            generation,
        };
        assert_eq!(gate.still_discarding(&marker), Ok(false));
        let _ = delete_owned(&gate.control_target());
    }

    #[test]
    fn a_published_record_is_remarked_discarding_by_a_current_handle() {
        let generation = [7u8; 16];
        let gate = gate_with_record(generation);
        let control = gate.control_target();
        let _lock = lock_target(&control).expect("the control lock");
        let marker = gate.mark_discarding().unwrap();
        assert!(marker.discarding);
        let expected = control_blob(true, &generation);
        let stored = read_raw(&control).unwrap().unwrap();
        assert_eq!(*stored, expected);
        let _ = delete_owned(&control);
    }

    #[test]
    fn decode_hex_reads_lowercase_hex_pairs() {
        assert_eq!(decode_hex(""), Ok(String::new()));
        assert_eq!(decode_hex("00"), Ok("\0".into()));
        assert_eq!(decode_hex("10"), Ok("\u{10}".into()));
        assert_eq!(decode_hex("61"), Ok("a".into()));
        assert_eq!(decode_hex("7a"), Ok("z".into()));
        assert_eq!(decode_hex("1f61"), Ok("\u{1f}a".into()));
    }

    #[test]
    fn decode_hex_refuses_odd_lengths_invalid_digits_and_bad_utf8() {
        let corrupt = |message: &str| SealError::Corrupt(message.into());
        assert_eq!(
            decode_hex("6"),
            Err(corrupt("invalid scoped target encoding"))
        );
        assert_eq!(
            decode_hex("611"),
            Err(corrupt("invalid scoped target encoding"))
        );
        assert_eq!(
            decode_hex("6g"),
            Err(corrupt("invalid scoped target encoding"))
        );
        assert_eq!(
            decode_hex("6G"),
            Err(corrupt("invalid scoped target encoding"))
        );
        assert_eq!(
            decode_hex("6A"),
            Err(corrupt("invalid scoped target encoding"))
        );
        assert_eq!(
            decode_hex("ff61"),
            Err(corrupt("invalid scoped target UTF-8"))
        );
    }

    #[test]
    fn source_changed_flags_a_plain_source_rewritten_during_migration() {
        let attributes = HashMap::from([("username".to_owned(), "alice".to_owned())]);
        let source = Zeroizing::new(b"secret".to_vec());
        let unchanged = Snapshot {
            source: Zeroizing::new(b"secret".to_vec()),
            attributes: attributes.clone(),
        };
        assert!(!source_changed(&source, &attributes, &unchanged));
        let rewritten = Snapshot {
            source: Zeroizing::new(b"other".to_vec()),
            attributes: attributes.clone(),
        };
        assert!(source_changed(&source, &attributes, &rewritten));
        let reattributed = Snapshot {
            source: Zeroizing::new(b"secret".to_vec()),
            attributes: HashMap::from([("username".to_owned(), "bob".to_owned())]),
        };
        assert!(source_changed(&source, &attributes, &reattributed));
    }

    #[test]
    fn a_scoped_deletion_merges_with_the_plain_source_outcome() {
        assert!(matches!(merge_scoped_deletion(true, Ok(())), Ok(())));
        assert!(matches!(merge_scoped_deletion(false, Ok(())), Ok(())));
        assert!(matches!(
            merge_scoped_deletion(true, Err(Error::NoEntry)),
            Ok(())
        ));
        assert!(matches!(
            merge_scoped_deletion(false, Err(Error::NoEntry)),
            Err(Error::NoEntry)
        ));
        assert!(matches!(
            merge_scoped_deletion(true, Err(Error::NotSupportedByStore("denied".into()))),
            Err(Error::PlatformFailure(_))
        ));
        assert!(matches!(
            merge_scoped_deletion(false, Err(Error::NotSupportedByStore("denied".into()))),
            Err(Error::NotSupportedByStore(_))
        ));
    }
}

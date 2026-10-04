use std::collections::HashMap;
use std::sync::Arc;

use keyring_core::api::{CredentialPersistence, CredentialStoreApi};
use keyring_core::{Entry, Result};

use crate::sealed::{Gate, Protection, SealError};

/// A named store whose entries are sealed under a key the application supplies.
///
/// Entries are readable only between [`SealedStore::unlock`] and [`SealedStore::lock`].
pub struct SealedStore {
    id: String,
    gate: Arc<Gate>,
}

impl SealedStore {
    /// Create the store named `store` for `application`, starting locked.
    pub fn new(application: &str, store: &str) -> Result<Arc<Self>> {
        let gate = Gate::new(application, store)?;
        Ok(Arc::new(Self {
            id: gate.id(),
            gate,
        }))
    }

    /// Hold `key` for every entry of this store.
    ///
    /// The first unlock of an empty store records `key`, and later unlocks must present it.
    ///
    /// # Errors
    ///
    /// [`SealError::WrongKey`] if `key` is not the store's key, and [`SealError::Corrupt`] if
    /// the store's key record is unreadable or missing while entries exist.
    pub fn unlock(&self, key: &[u8; 32]) -> std::result::Result<(), SealError> {
        self.gate.unlock(key)
    }

    /// Erase the key, so entries stay sealed until the next unlock.
    pub fn lock(&self) {
        self.gate.lock();
    }

    /// Report whether this store holds its key.
    pub fn protection(&self) -> Protection {
        self.gate.protection()
    }
}

impl Drop for SealedStore {
    fn drop(&mut self) {
        self.gate.lock();
    }
}

impl std::fmt::Debug for SealedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedStore").field("id", &self.id).finish()
    }
}

impl CredentialStoreApi for SealedStore {
    fn vendor(&self) -> String {
        "Windows sealed store, https://crates.io/crates/windows-native-keyring-store".into()
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
        self.gate.build(service, user, modifiers)
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

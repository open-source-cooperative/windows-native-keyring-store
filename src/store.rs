use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use keyring_core::api::{CredentialPersistence, CredentialStoreApi};
use keyring_core::attributes::parse_attributes;
use keyring_core::{Entry, Error, Result};

use crate::cred::Cred;
use crate::utils::enumerate_credentials;

/// The store for Windows native credentials
#[derive(Clone)]
pub struct Store {
    pub id: String,
    pub delimiters: [String; 3],
    pub service_no_divider: bool,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("vendor", &self.vendor())
            .field("id", &self.id)
            .field("delimiters", &self.delimiters)
            .field("service_no_divider", &self.service_no_divider)
            .finish()
    }
}

impl Store {
    /// Create the default store: prefix and suffix empty, divider '.'.
    ///
    /// This is the configuration that matches the config for this store
    /// in earlier versions of keyring.
    pub fn new() -> Result<Arc<Self>> {
        Ok(Self::new_internal(
            ["".to_string(), ".".to_string(), "".to_string()],
            false,
        ))
    }

    /// Create a custom-configured store.
    ///
    /// The delimiter config options are `prefix`, `divider`, and `suffix`. They
    /// default to `keyring:`, `@`, and the empty string, respectively.
    ///
    /// If you want to be sure that key descriptions cannot be ambiguous, specify
    /// the config option `service_no_divider` to `true`.
    pub fn new_with_configuration(config: &HashMap<&str, &str>) -> Result<Arc<Self>> {
        let config = parse_attributes(
            &["prefix", "divider", "suffix", "*service_no_divider"],
            Some(config),
        )?;
        let prefix = match config.get("prefix") {
            Some(prefix) => prefix.to_string(),
            None => "".to_string(),
        };
        let divider = match config.get("divider") {
            Some(divider) => divider.to_string(),
            None => ".".to_string(),
        };
        let suffix = match config.get("suffix") {
            Some(suffix) => suffix.to_string(),
            None => "".to_string(),
        };
        let service_no_divider = config
            .get("service_no_divider")
            .is_some_and(|s| s.eq("true"));
        Ok(Self::new_internal(
            [prefix, divider, suffix],
            service_no_divider,
        ))
    }

    fn new_internal(delimiters: [String; 3], service_no_divider: bool) -> Arc<Self> {
        let now = SystemTime::now();
        let elapsed = if now.lt(&UNIX_EPOCH) {
            UNIX_EPOCH.duration_since(now).unwrap()
        } else {
            now.duration_since(UNIX_EPOCH).unwrap()
        };
        Arc::new(Store {
            id: format!(
                "Crate version {}, Instantiated at {}",
                env!("CARGO_PKG_VERSION"),
                elapsed.as_secs_f64()
            ),
            delimiters,
            service_no_divider,
        })
    }
}

impl CredentialStoreApi for Store {
    /// See the keyring-core API docs.
    fn vendor(&self) -> String {
        "Windows Credential Manager, https://crates.io/crates/windows-native-keyring-store"
            .to_string()
    }

    /// See the keyring-core API docs.
    fn id(&self) -> String {
        self.id.clone()
    }

    /// See the keyring-core API docs.
    ///
    /// Building a credential does not create a key in the store.
    /// It's setting a password that does that.
    fn build(
        &self,
        service: &str,
        user: &str,
        modifiers: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        let mods = parse_attributes(&["target", "persistence"], modifiers)?;
        let target = mods.get("target").map(|s| s.as_str());
        let persistence = mods
            .get("persistence")
            .map(|s| s.as_str())
            .unwrap_or("Enterprise");
        let cred = Cred::build_from_specifiers(
            target,
            &self.delimiters,
            self.service_no_divider,
            service,
            user,
            persistence.parse()?,
        )?;
        Ok(Entry::new_with_credential(Arc::new(cred)))
    }

    /// See the keyring-core API docs.
    fn search(&self, spec: &HashMap<&str, &str>) -> Result<Vec<Entry>> {
        let spec = parse_attributes(&["pattern"], Some(spec))?;
        let expr = if let Some(val) = spec.get("pattern") {
            if let Ok(pat) = regex::Regex::new(val) {
                Some(pat)
            } else {
                return Err(Error::Invalid(
                    val.to_string(),
                    "is not a valid regular expression".to_string(),
                ));
            }
        } else {
            None
        };
        let creds = enumerate_credentials(expr, &self.delimiters)?;
        Ok(creds
            .into_iter()
            .map(|c| Entry::new_with_credential(Arc::new(c)))
            .collect())
    }

    /// See the keyring-core API docs.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// See the keyring-core API docs.
    ///
    /// Since this keystore keeps credentials in kernel memory, they vanish on reboot
    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::UntilDelete
    }

    /// See the keychain-core API docs.
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

use std::any::Any;
use std::collections::HashMap;
use std::fmt::Formatter;
use std::sync::Arc;

use zeroize::Zeroize;

use keyring_core::api::CredentialApi;
use keyring_core::attributes::parse_attributes;
use keyring_core::{Credential, Error as ErrorCode, Result};

pub use crate::utils::CredPersist;
use crate::utils::{
    decode_utf16_password, delete_credential, extract_attributes, extract_from_credential,
    extract_secret, save_credential, validate_attributes, validate_password, validate_secret,
    validate_secret_for_encryption, validate_target, BIOMETRIC_MARKER,
};

/// Cred specifies or wraps a generic credential.
/// Whether it's a specifier or wrapper depends on the specifiers field,
/// which is a tuple <service, user> or `None`.
#[derive(Debug, Clone)]
pub(crate) struct Cred {
    pub target_name: String,
    pub specifiers: Option<(String, String)>,
    pub persistence: CredPersist,
    pub require_biometric: bool,
}

impl Cred {
    /// Create a Windows generic credential from the given specifiers.
    ///
    /// An explicit target string is interpreted as the target to use for the entry.
    /// If none is provided, then we concatenate the user and service in the string
    /// `{delimiters[0]}{user}{delimiters[1]}{service}{delimiters[2]}`.
    pub fn build_from_specifiers(
        target: Option<&str>,
        delimiters: &[String; 3],
        service_no_dividers: bool,
        service: &str,
        user: &str,
        persistence: CredPersist,
        require_biometric: bool,
    ) -> Result<Self> {
        let (target_name, specifiers) = match target {
            Some(value) => (value.to_string(), None),
            None => {
                if service_no_dividers && service.contains(delimiters[1].as_str()) {
                    return Err(ErrorCode::Invalid(
                        "service".to_string(),
                        "cannot contain delimiter".to_string(),
                    ));
                }
                (
                    format!(
                        "{}{user}{}{service}{}",
                        delimiters[0], delimiters[1], delimiters[2]
                    ),
                    Some((service.to_string(), user.to_string())),
                )
            }
        };
        validate_target(
            &target_name,
            &specifiers
                .as_ref()
                .map_or_else(String::new, |s| s.1.clone()),
        )?;
        Ok(Self {
            target_name,
            specifiers,
            persistence,
            require_biometric,
        })
    }

    /// Check if the stored credential has the biometric marker in its comment.
    /// Returns false if the credential does not exist yet or cannot be read.
    fn has_stored_biometric_marker(&self) -> bool {
        match extract_from_credential(&self.target_name, extract_attributes) {
            Ok(attrs) => attrs
                .get("comment")
                .is_some_and(|c| c.contains(BIOMETRIC_MARKER)),
            Err(_) => false,
        }
    }

    fn encrypt_secret(&self, secret: &[u8]) -> Result<Vec<u8>> {
        validate_secret_for_encryption(secret)?;
        let ngc_key = crate::crypto::ensure_ngc_key(&self.target_name)?;
        let mut aes_key = crate::crypto::derive_aes_key(&ngc_key, &self.target_name)?;
        let result = crate::crypto::encrypt(&aes_key, secret);
        aes_key.zeroize();
        result
    }

    fn decrypt_or_verify(&self, blob: Vec<u8>) -> Result<Vec<u8>> {
        if crate::crypto::is_encrypted(&blob) {
            let ngc_key = crate::crypto::open_ngc_key(&self.target_name)?;
            let mut aes_key = crate::crypto::derive_aes_key(&ngc_key, &self.target_name)?;
            let result = crate::crypto::decrypt(&aes_key, &blob);
            aes_key.zeroize();
            result
        } else {
            Ok(blob)
        }
    }
}

impl CredentialApi for Cred {
    /// See the keyring-core API docs.
    ///
    // Password strings are converted to UTF-16 because that's the native
    // charset for Windows strings.  This allows interoperability with native
    // Windows credential APIs.  But the storage for the credential is actually
    // a little-endian blob, because Windows credentials can contain anything.
    fn set_password(&self, password: &str) -> Result<()> {
        let mut secret = validate_password(password)?;
        let result = self.set_secret_internal(&secret);
        // make sure that the copy of the secret is erased
        secret.zeroize();
        result
    }

    /// See the keyring-core API docs.
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        self.set_secret_internal(secret)
    }

    /// See the keyring-core API docs.
    fn get_password(&self) -> Result<String> {
        let blob = extract_from_credential(&self.target_name, extract_secret)?;
        let mut decrypted = self.decrypt_or_verify(blob)?;
        let result = decode_utf16_password(&decrypted);
        decrypted.zeroize();
        result
    }

    /// See the keyring-core API docs.
    fn get_secret(&self) -> Result<Vec<u8>> {
        let blob = extract_from_credential(&self.target_name, extract_secret)?;
        self.decrypt_or_verify(blob)
    }

    /// See the keyring-core API docs.
    fn get_attributes(&self) -> Result<HashMap<String, String>> {
        extract_from_credential(&self.target_name, extract_attributes)
    }

    /// See the keyring-core API docs.
    fn update_attributes(&self, attributes: &HashMap<&str, &str>) -> Result<()> {
        let new = parse_attributes(&["username", "target_alias", "comment"], Some(attributes))?;
        let old = self.get_attributes()?;
        let username = new
            .get("username")
            .cloned()
            .unwrap_or_else(|| old["username"].clone());
        let target_alias = new
            .get("target_alias")
            .cloned()
            .unwrap_or_else(|| old["target_alias"].clone());
        let comment = new
            .get("comment")
            .cloned()
            .unwrap_or_else(|| old["comment"].clone());
        validate_attributes(&username, &target_alias, &comment)?;
        let mut raw_blob = extract_from_credential(&self.target_name, extract_secret)?;
        let result = save_credential(
            &self.target_name,
            &username,
            &target_alias,
            &comment,
            &raw_blob,
            &self.persistence,
        );
        // erase the copy of the secret
        raw_blob.zeroize();
        result
    }

    /// See the keyring-core API docs.
    fn delete_credential(&self) -> Result<()> {
        delete_credential(&self.target_name)?;
        crate::crypto::delete_ngc_key(&self.target_name);
        Ok(())
    }

    /// See the keyring-core API docs.
    ///
    /// No ambiguity, so every wrap is its own wrapper
    fn get_credential(&self) -> Result<Option<Arc<Credential>>> {
        let attrs = self.get_attributes()?;
        let persistence: CredPersist = attrs["persistence"].parse()?;
        let stored_biometric = attrs
            .get("comment")
            .is_some_and(|c| c.contains(BIOMETRIC_MARKER));
        if self.persistence == persistence && self.require_biometric == stored_biometric {
            Ok(None)
        } else {
            let mut new = self.clone();
            new.persistence = persistence;
            new.require_biometric = stored_biometric;
            Ok(Some(Arc::new(new)))
        }
    }

    /// See the keyring-core API docs.
    fn get_specifiers(&self) -> Option<(String, String)> {
        self.specifiers.clone()
    }

    /// See the keyring-core API docs.
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// See the keyring-core API docs.
    fn debug_fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Cred {
    fn set_secret_internal(&self, secret: &[u8]) -> Result<()> {
        let effective_biometric = self.require_biometric || self.has_stored_biometric_marker();

        let blob = if effective_biometric {
            self.encrypt_secret(secret)?
        } else {
            validate_secret(secret)?;
            secret.to_vec()
        };

        let mut username = if let Some((_, user)) = &self.specifiers {
            user.to_owned()
        } else {
            String::new()
        };
        let mut target_alias = String::new();
        let mut comment = String::new();
        if let Ok(attributes) = self.get_attributes() {
            username = attributes["username"].clone();
            target_alias = attributes["target_alias"].clone();
            comment = attributes["comment"].clone();
        }
        if effective_biometric && !comment.contains(BIOMETRIC_MARKER) {
            if comment.is_empty() {
                comment = BIOMETRIC_MARKER.to_string();
            } else {
                comment = format!("{BIOMETRIC_MARKER} {comment}");
            }
        }
        let result = save_credential(
            &self.target_name,
            &username,
            &target_alias,
            &comment,
            &blob,
            &self.persistence,
        );
        drop(blob);
        result
    }
}

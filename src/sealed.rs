//! Sealed entries shared by the protected stores, encrypted under one key per store.

use keyring_core::Error;

/// Why a sealed store refused an operation.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SealError {
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

#[cfg(test)]
mod tests {
    use keyring_core::Error;

    use super::SealError;

    #[test]
    fn seal_errors_map_to_keyring_error_kinds() {
        assert!(matches!(
            Error::from(SealError::Corrupt("record".into())),
            Error::BadStoreFormat(reason) if reason == "record"
        ));
        assert!(matches!(
            Error::from(SealError::Platform("service".into())),
            Error::PlatformFailure(_)
        ));
        assert!(matches!(
            Error::from(SealError::TimedOut),
            Error::NoStorageAccess(_)
        ));
    }
}

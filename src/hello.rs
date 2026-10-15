//! Windows Hello support for sealed stores.

use crate::sealed::SealError;

/// Check that Windows Hello can protect a sealed store on this machine, without prompting.
///
/// This needs WebAuthn API 9, a user-verifying platform authenticator, and exactly one
/// Windows Hello entry in the WebAuthn authenticator list. PRF support is only confirmed by
/// the first unlock.
///
/// # Errors
///
/// [`SealError::Unsupported`] when any requirement is missing, [`SealError::Locked`] when
/// Windows Hello is locked, [`SealError::Conflict`] when several Windows Hello authenticators
/// are listed, and [`SealError::Platform`] when WebAuthn fails.
pub fn capability() -> Result<(), SealError> {
    crate::hello_native::available()
}

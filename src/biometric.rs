use windows::Security::Credentials::UI::{
    UserConsentVerifier, UserConsentVerifierAvailability,
};

/// Check if TPM-backed biometric credential protection is available.
///
/// This verifies that the KeyCredentialManager API is supported, which requires
/// Windows 10+ with a TPM or software-emulated NGC. This is a stronger check
/// than [`is_available`] — it means credentials can be cryptographically
/// protected by Windows Hello, not just UI-gated.
pub fn is_ngc_supported() -> bool {
    crate::crypto::is_ngc_supported()
}

/// Check if Windows Hello biometric verification is available on this device.
pub fn is_available() -> bool {
    let op = match UserConsentVerifier::CheckAvailabilityAsync() {
        Ok(op) => op,
        Err(_) => return false,
    };
    match op.get() {
        Ok(availability) => availability == UserConsentVerifierAvailability::Available,
        Err(_) => false,
    }
}

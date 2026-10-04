//! Regenerates `src/webauthn.rs` from the Windows SDK metadata shipped with `windows-bindgen`.

fn main() {
    let out = concat!(env!("CARGO_MANIFEST_DIR"), "/../../src/webauthn.rs");
    windows_bindgen::bindgen([
        "--out",
        out,
        "--sys",
        "--flat",
        "--extern",
        "--filter",
        "WebAuthNAuthenticatorGetAssertion",
        "WebAuthNAuthenticatorMakeCredential",
        "WebAuthNDeletePlatformCredential",
        "WebAuthNFreeAuthenticatorList",
        "WebAuthNFreePlatformCredentialList",
        "WebAuthNGetApiVersionNumber",
        "WebAuthNGetAuthenticatorList",
        "WebAuthNGetErrorName",
        "WebAuthNGetPlatformCredentialList",
        "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable",
        "WEBAUTHN_API_VERSION_9",
        "WEBAUTHN_ASSERTION_VERSION_6",
        "WEBAUTHN_AUTHENTICATOR_DETAILS_OPTIONS_CURRENT_VERSION",
        "WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION",
        "WEBAUTHN_CTAP_ONE_HMAC_SECRET_LENGTH",
        "WEBAUTHN_CTAP_TRANSPORT_INTERNAL",
    ]);
}

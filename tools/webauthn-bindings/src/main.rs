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
        "WebAuthNDeletePlatformCredential",
        "WebAuthNFreeAuthenticatorList",
        "WebAuthNFreePlatformCredentialList",
        "WebAuthNGetApiVersionNumber",
        "WebAuthNGetAuthenticatorList",
        "WebAuthNGetErrorName",
        "WebAuthNGetPlatformCredentialList",
        "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable",
        "WEBAUTHN_API_VERSION_9",
        "WEBAUTHN_AUTHENTICATOR_DETAILS_OPTIONS_CURRENT_VERSION",
    ]);
}

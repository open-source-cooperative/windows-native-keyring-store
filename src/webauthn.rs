pub type WebAuthNFreeAuthenticatorList = unsafe extern "system" fn(
    pauthenticatordetailslist: *const WEBAUTHN_AUTHENTICATOR_DETAILS_LIST,
);
unsafe extern "system" {
    pub fn WebAuthNFreeAuthenticatorList(
        pauthenticatordetailslist: *const WEBAUTHN_AUTHENTICATOR_DETAILS_LIST,
    );
}
pub type WebAuthNGetApiVersionNumber = unsafe extern "system" fn() -> u32;
unsafe extern "system" {
    pub fn WebAuthNGetApiVersionNumber() -> u32;
}
pub type WebAuthNGetAuthenticatorList = unsafe extern "system" fn(
    pwebauthngetauthenticatorlistoptions: *const WEBAUTHN_AUTHENTICATOR_DETAILS_OPTIONS,
    ppauthenticatordetailslist: *mut PWEBAUTHN_AUTHENTICATOR_DETAILS_LIST,
) -> HRESULT;
unsafe extern "system" {
    pub fn WebAuthNGetAuthenticatorList(
        pwebauthngetauthenticatorlistoptions: *const WEBAUTHN_AUTHENTICATOR_DETAILS_OPTIONS,
        ppauthenticatordetailslist: *mut PWEBAUTHN_AUTHENTICATOR_DETAILS_LIST,
    ) -> HRESULT;
}
pub type WebAuthNGetErrorName = unsafe extern "system" fn(hr: HRESULT) -> PCWSTR;
unsafe extern "system" {
    pub fn WebAuthNGetErrorName(hr: HRESULT) -> PCWSTR;
}
pub type WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable =
    unsafe extern "system" fn(
        pbisuserverifyingplatformauthenticatoravailable: *mut BOOL,
    ) -> HRESULT;
unsafe extern "system" {
    pub fn WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(
        pbisuserverifyingplatformauthenticatoravailable: *mut BOOL,
    ) -> HRESULT;
}
pub type BOOL = i32;
pub type HRESULT = i32;
pub type PBYTE = *mut u8;
pub type PCWSTR = *const u16;
pub type PWEBAUTHN_AUTHENTICATOR_DETAILS = *mut WEBAUTHN_AUTHENTICATOR_DETAILS;
pub type PWEBAUTHN_AUTHENTICATOR_DETAILS_LIST = *mut WEBAUTHN_AUTHENTICATOR_DETAILS_LIST;
pub const WEBAUTHN_API_VERSION_9: i32 = 9;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WEBAUTHN_AUTHENTICATOR_DETAILS {
    pub dwVersion: u32,
    pub cbAuthenticatorId: u32,
    pub pbAuthenticatorId: PBYTE,
    pub pwszAuthenticatorName: PCWSTR,
    pub cbAuthenticatorLogo: u32,
    pub pbAuthenticatorLogo: PBYTE,
    pub bLocked: BOOL,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WEBAUTHN_AUTHENTICATOR_DETAILS_LIST {
    pub cAuthenticatorDetails: u32,
    pub ppAuthenticatorDetails: *mut PWEBAUTHN_AUTHENTICATOR_DETAILS,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WEBAUTHN_AUTHENTICATOR_DETAILS_OPTIONS {
    pub dwVersion: u32,
}
pub const WEBAUTHN_AUTHENTICATOR_DETAILS_OPTIONS_CURRENT_VERSION: i32 = 1;

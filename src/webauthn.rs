pub type WebAuthNDeletePlatformCredential =
    unsafe extern "system" fn(cbcredentialid: u32, pbcredentialid: *const u8) -> HRESULT;
unsafe extern "system" {
    pub fn WebAuthNDeletePlatformCredential(
        cbcredentialid: u32,
        pbcredentialid: *const u8,
    ) -> HRESULT;
}
pub type WebAuthNFreeAuthenticatorList = unsafe extern "system" fn(
    pauthenticatordetailslist: *const WEBAUTHN_AUTHENTICATOR_DETAILS_LIST,
);
unsafe extern "system" {
    pub fn WebAuthNFreeAuthenticatorList(
        pauthenticatordetailslist: *const WEBAUTHN_AUTHENTICATOR_DETAILS_LIST,
    );
}
pub type WebAuthNFreePlatformCredentialList =
    unsafe extern "system" fn(pcredentialdetailslist: *const WEBAUTHN_CREDENTIAL_DETAILS_LIST);
unsafe extern "system" {
    pub fn WebAuthNFreePlatformCredentialList(
        pcredentialdetailslist: *const WEBAUTHN_CREDENTIAL_DETAILS_LIST,
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
pub type WebAuthNGetPlatformCredentialList = unsafe extern "system" fn(
    pgetcredentialsoptions: *const WEBAUTHN_GET_CREDENTIALS_OPTIONS,
    ppcredentialdetailslist: *mut PWEBAUTHN_CREDENTIAL_DETAILS_LIST,
) -> HRESULT;
unsafe extern "system" {
    pub fn WebAuthNGetPlatformCredentialList(
        pgetcredentialsoptions: *const WEBAUTHN_GET_CREDENTIALS_OPTIONS,
        ppcredentialdetailslist: *mut PWEBAUTHN_CREDENTIAL_DETAILS_LIST,
    ) -> HRESULT;
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
pub type PWEBAUTHN_CREDENTIAL_DETAILS = *mut WEBAUTHN_CREDENTIAL_DETAILS;
pub type PWEBAUTHN_CREDENTIAL_DETAILS_LIST = *mut WEBAUTHN_CREDENTIAL_DETAILS_LIST;
pub type PWEBAUTHN_RP_ENTITY_INFORMATION = *mut WEBAUTHN_RP_ENTITY_INFORMATION;
pub type PWEBAUTHN_USER_ENTITY_INFORMATION = *mut WEBAUTHN_USER_ENTITY_INFORMATION;
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
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WEBAUTHN_CREDENTIAL_DETAILS {
    pub dwVersion: u32,
    pub cbCredentialID: u32,
    pub pbCredentialID: PBYTE,
    pub pRpInformation: PWEBAUTHN_RP_ENTITY_INFORMATION,
    pub pUserInformation: PWEBAUTHN_USER_ENTITY_INFORMATION,
    pub bRemovable: BOOL,
    pub bBackedUp: BOOL,
    pub pwszAuthenticatorName: PCWSTR,
    pub cbAuthenticatorLogo: u32,
    pub pbAuthenticatorLogo: PBYTE,
    pub bThirdPartyPayment: BOOL,
    pub dwTransports: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WEBAUTHN_CREDENTIAL_DETAILS_LIST {
    pub cCredentialDetails: u32,
    pub ppCredentialDetails: *mut PWEBAUTHN_CREDENTIAL_DETAILS,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WEBAUTHN_GET_CREDENTIALS_OPTIONS {
    pub dwVersion: u32,
    pub pwszRpId: PCWSTR,
    pub bBrowserInPrivateMode: BOOL,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WEBAUTHN_RP_ENTITY_INFORMATION {
    pub dwVersion: u32,
    pub pwszId: PCWSTR,
    pub pwszName: PCWSTR,
    pub pwszIcon: PCWSTR,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WEBAUTHN_USER_ENTITY_INFORMATION {
    pub dwVersion: u32,
    pub cbId: u32,
    pub pbId: PBYTE,
    pub pwszName: PCWSTR,
    pub pwszIcon: PCWSTR,
    pub pwszDisplayName: PCWSTR,
}

pub type WebAuthNAuthenticatorGetAssertion = unsafe extern "system" fn(
    hwnd: HWND,
    pwszrpid: PCWSTR,
    pwebauthnclientdata: *const WEBAUTHN_CLIENT_DATA,
    pwebauthngetassertionoptions: *const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    ppwebauthnassertion: *mut PWEBAUTHN_ASSERTION,
) -> HRESULT;
unsafe extern "system" {
    pub fn WebAuthNAuthenticatorGetAssertion(
        hwnd: HWND,
        pwszrpid: PCWSTR,
        pwebauthnclientdata: *const WEBAUTHN_CLIENT_DATA,
        pwebauthngetassertionoptions: *const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
        ppwebauthnassertion: *mut PWEBAUTHN_ASSERTION,
    ) -> HRESULT;
}
pub type WebAuthNAuthenticatorMakeCredential = unsafe extern "system" fn(
    hwnd: HWND,
    prpinformation: *const WEBAUTHN_RP_ENTITY_INFORMATION,
    puserinformation: *const WEBAUTHN_USER_ENTITY_INFORMATION,
    ppubkeycredparams: *const WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
    pwebauthnclientdata: *const WEBAUTHN_CLIENT_DATA,
    pwebauthnmakecredentialoptions: *const WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
    ppwebauthncredentialattestation: *mut PWEBAUTHN_CREDENTIAL_ATTESTATION,
) -> HRESULT;
unsafe extern "system" {
    pub fn WebAuthNAuthenticatorMakeCredential(
        hwnd: HWND,
        prpinformation: *const WEBAUTHN_RP_ENTITY_INFORMATION,
        puserinformation: *const WEBAUTHN_USER_ENTITY_INFORMATION,
        ppubkeycredparams: *const WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
        pwebauthnclientdata: *const WEBAUTHN_CLIENT_DATA,
        pwebauthnmakecredentialoptions: *const WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
        ppwebauthncredentialattestation: *mut PWEBAUTHN_CREDENTIAL_ATTESTATION,
    ) -> HRESULT;
}
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
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CTAPCBOR_HYBRID_STORAGE_LINKED_DATA {
    pub dwVersion: u32,
    pub cbContactId: u32,
    pub pbContactId: PBYTE,
    pub cbLinkId: u32,
    pub pbLinkId: PBYTE,
    pub cbLinkSecret: u32,
    pub pbLinkSecret: PBYTE,
    pub cbPublicKey: u32,
    pub pbPublicKey: PBYTE,
    pub pwszAuthenticatorName: PCWSTR,
    pub wEncodedTunnelServerDomain: u16,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}
pub type HRESULT = i32;
pub type HWND = *mut core::ffi::c_void;
pub type PBYTE = *mut u8;
pub type PCTAPCBOR_HYBRID_STORAGE_LINKED_DATA = *mut CTAPCBOR_HYBRID_STORAGE_LINKED_DATA;
pub type PCWSTR = *const u16;
pub type PWEBAUTHN_ASSERTION = *mut WEBAUTHN_ASSERTION;
pub type PWEBAUTHN_AUTHENTICATOR_DETAILS = *mut WEBAUTHN_AUTHENTICATOR_DETAILS;
pub type PWEBAUTHN_AUTHENTICATOR_DETAILS_LIST = *mut WEBAUTHN_AUTHENTICATOR_DETAILS_LIST;
pub type PWEBAUTHN_COSE_CREDENTIAL_PARAMETER = *mut WEBAUTHN_COSE_CREDENTIAL_PARAMETER;
pub type PWEBAUTHN_CREDENTIAL = *mut WEBAUTHN_CREDENTIAL;
pub type PWEBAUTHN_CREDENTIAL_ATTESTATION = *mut WEBAUTHN_CREDENTIAL_ATTESTATION;
pub type PWEBAUTHN_CREDENTIAL_DETAILS = *mut WEBAUTHN_CREDENTIAL_DETAILS;
pub type PWEBAUTHN_CREDENTIAL_DETAILS_LIST = *mut WEBAUTHN_CREDENTIAL_DETAILS_LIST;
pub type PWEBAUTHN_CREDENTIAL_EX = *mut WEBAUTHN_CREDENTIAL_EX;
pub type PWEBAUTHN_CREDENTIAL_LIST = *mut WEBAUTHN_CREDENTIAL_LIST;
pub type PWEBAUTHN_CRED_WITH_HMAC_SECRET_SALT = *mut WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT;
pub type PWEBAUTHN_EXTENSION = *mut WEBAUTHN_EXTENSION;
pub type PWEBAUTHN_HMAC_SECRET_SALT = *mut WEBAUTHN_HMAC_SECRET_SALT;
pub type PWEBAUTHN_HMAC_SECRET_SALT_VALUES = *mut WEBAUTHN_HMAC_SECRET_SALT_VALUES;
pub type PWEBAUTHN_RP_ENTITY_INFORMATION = *mut WEBAUTHN_RP_ENTITY_INFORMATION;
pub type PWEBAUTHN_USER_ENTITY_INFORMATION = *mut WEBAUTHN_USER_ENTITY_INFORMATION;
pub const WEBAUTHN_API_VERSION_9: i32 = 9;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WEBAUTHN_ASSERTION {
    pub dwVersion: u32,
    pub cbAuthenticatorData: u32,
    pub pbAuthenticatorData: PBYTE,
    pub cbSignature: u32,
    pub pbSignature: PBYTE,
    pub Credential: WEBAUTHN_CREDENTIAL,
    pub cbUserId: u32,
    pub pbUserId: PBYTE,
    pub Extensions: WEBAUTHN_EXTENSIONS,
    pub cbCredLargeBlob: u32,
    pub pbCredLargeBlob: PBYTE,
    pub dwCredLargeBlobStatus: u32,
    pub pHmacSecret: PWEBAUTHN_HMAC_SECRET_SALT,
    pub dwUsedTransport: u32,
    pub cbUnsignedExtensionOutputs: u32,
    pub pbUnsignedExtensionOutputs: PBYTE,
    pub cbClientDataJSON: u32,
    pub pbClientDataJSON: PBYTE,
    pub cbAuthenticationResponseJSON: u32,
    pub pbAuthenticationResponseJSON: PBYTE,
}
pub const WEBAUTHN_ASSERTION_VERSION_6: i32 = 6;
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
pub struct WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
    pub dwVersion: u32,
    pub dwTimeoutMilliseconds: u32,
    pub CredentialList: WEBAUTHN_CREDENTIALS,
    pub Extensions: WEBAUTHN_EXTENSIONS,
    pub dwAuthenticatorAttachment: u32,
    pub dwUserVerificationRequirement: u32,
    pub dwFlags: u32,
    pub pwszU2fAppId: PCWSTR,
    pub pbU2fAppId: *mut BOOL,
    pub pCancellationId: *mut GUID,
    pub pAllowCredentialList: PWEBAUTHN_CREDENTIAL_LIST,
    pub dwCredLargeBlobOperation: u32,
    pub cbCredLargeBlob: u32,
    pub pbCredLargeBlob: PBYTE,
    pub pHmacSecretSaltValues: PWEBAUTHN_HMAC_SECRET_SALT_VALUES,
    pub bBrowserInPrivateMode: BOOL,
    pub pLinkedDevice: PCTAPCBOR_HYBRID_STORAGE_LINKED_DATA,
    pub bAutoFill: BOOL,
    pub cbJsonExt: u32,
    pub pbJsonExt: PBYTE,
    pub cCredentialHints: u32,
    pub ppwszCredentialHints: *mut PCWSTR,
    pub pwszRemoteWebOrigin: PCWSTR,
    pub cbPublicKeyCredentialRequestOptionsJSON: u32,
    pub pbPublicKeyCredentialRequestOptionsJSON: PBYTE,
    pub cbAuthenticatorId: u32,
    pub pbAuthenticatorId: PBYTE,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
    pub dwVersion: u32,
    pub dwTimeoutMilliseconds: u32,
    pub CredentialList: WEBAUTHN_CREDENTIALS,
    pub Extensions: WEBAUTHN_EXTENSIONS,
    pub dwAuthenticatorAttachment: u32,
    pub bRequireResidentKey: BOOL,
    pub dwUserVerificationRequirement: u32,
    pub dwAttestationConveyancePreference: u32,
    pub dwFlags: u32,
    pub pCancellationId: *mut GUID,
    pub pExcludeCredentialList: PWEBAUTHN_CREDENTIAL_LIST,
    pub dwEnterpriseAttestation: u32,
    pub dwLargeBlobSupport: u32,
    pub bPreferResidentKey: BOOL,
    pub bBrowserInPrivateMode: BOOL,
    pub bEnablePrf: BOOL,
    pub pLinkedDevice: PCTAPCBOR_HYBRID_STORAGE_LINKED_DATA,
    pub cbJsonExt: u32,
    pub pbJsonExt: PBYTE,
    pub pPRFGlobalEval: PWEBAUTHN_HMAC_SECRET_SALT,
    pub cCredentialHints: u32,
    pub ppwszCredentialHints: *mut PCWSTR,
    pub bThirdPartyPayment: BOOL,
    pub pwszRemoteWebOrigin: PCWSTR,
    pub cbPublicKeyCredentialCreationOptionsJSON: u32,
    pub pbPublicKeyCredentialCreationOptionsJSON: PBYTE,
    pub cbAuthenticatorId: u32,
    pub pbAuthenticatorId: PBYTE,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WEBAUTHN_CLIENT_DATA {
    pub dwVersion: u32,
    pub cbClientDataJSON: u32,
    pub pbClientDataJSON: PBYTE,
    pub pwszHashAlgId: PCWSTR,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
    pub dwVersion: u32,
    pub pwszCredentialType: PCWSTR,
    pub lAlg: i32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
    pub cCredentialParameters: u32,
    pub pCredentialParameters: PWEBAUTHN_COSE_CREDENTIAL_PARAMETER,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WEBAUTHN_CREDENTIAL {
    pub dwVersion: u32,
    pub cbId: u32,
    pub pbId: PBYTE,
    pub pwszCredentialType: PCWSTR,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WEBAUTHN_CREDENTIALS {
    pub cCredentials: u32,
    pub pCredentials: PWEBAUTHN_CREDENTIAL,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WEBAUTHN_CREDENTIAL_ATTESTATION {
    pub dwVersion: u32,
    pub pwszFormatType: PCWSTR,
    pub cbAuthenticatorData: u32,
    pub pbAuthenticatorData: PBYTE,
    pub cbAttestation: u32,
    pub pbAttestation: PBYTE,
    pub dwAttestationDecodeType: u32,
    pub pvAttestationDecode: *mut core::ffi::c_void,
    pub cbAttestationObject: u32,
    pub pbAttestationObject: PBYTE,
    pub cbCredentialId: u32,
    pub pbCredentialId: PBYTE,
    pub Extensions: WEBAUTHN_EXTENSIONS,
    pub dwUsedTransport: u32,
    pub bEpAtt: BOOL,
    pub bLargeBlobSupported: BOOL,
    pub bResidentKey: BOOL,
    pub bPrfEnabled: BOOL,
    pub cbUnsignedExtensionOutputs: u32,
    pub pbUnsignedExtensionOutputs: PBYTE,
    pub pHmacSecret: PWEBAUTHN_HMAC_SECRET_SALT,
    pub bThirdPartyPayment: BOOL,
    pub dwTransports: u32,
    pub cbClientDataJSON: u32,
    pub pbClientDataJSON: PBYTE,
    pub cbRegistrationResponseJSON: u32,
    pub pbRegistrationResponseJSON: PBYTE,
}
pub const WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION: i32 = 8;
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
pub struct WEBAUTHN_CREDENTIAL_EX {
    pub dwVersion: u32,
    pub cbId: u32,
    pub pbId: PBYTE,
    pub pwszCredentialType: PCWSTR,
    pub dwTransports: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WEBAUTHN_CREDENTIAL_LIST {
    pub cCredentials: u32,
    pub ppCredentials: *mut PWEBAUTHN_CREDENTIAL_EX,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT {
    pub cbCredID: u32,
    pub pbCredID: PBYTE,
    pub pHmacSecretSalt: PWEBAUTHN_HMAC_SECRET_SALT,
}
pub const WEBAUTHN_CTAP_ONE_HMAC_SECRET_LENGTH: i32 = 32;
pub const WEBAUTHN_CTAP_TRANSPORT_INTERNAL: i32 = 16;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WEBAUTHN_EXTENSION {
    pub pwszExtensionIdentifier: PCWSTR,
    pub cbExtension: u32,
    pub pvExtension: *mut core::ffi::c_void,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WEBAUTHN_EXTENSIONS {
    pub cExtensions: u32,
    pub pExtensions: PWEBAUTHN_EXTENSION,
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
pub struct WEBAUTHN_HMAC_SECRET_SALT {
    pub cbFirst: u32,
    pub pbFirst: PBYTE,
    pub cbSecond: u32,
    pub pbSecond: PBYTE,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct WEBAUTHN_HMAC_SECRET_SALT_VALUES {
    pub pGlobalHmacSalt: PWEBAUTHN_HMAC_SECRET_SALT,
    pub cCredWithHmacSecretSaltList: u32,
    pub pCredWithHmacSecretSaltList: PWEBAUTHN_CRED_WITH_HMAC_SECRET_SALT,
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

//! Dynamic binding to `webauthn.dll` for the Windows Hello platform authenticator.
//!
//! The DLL is loaded at run time from System32 only, so a machine without WebAuthn API 9
//! reports [`SealError::Unsupported`] instead of failing to start.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use getrandom::fill;
use libloading::Library;
use libloading::os::windows::{LOAD_LIBRARY_SEARCH_SYSTEM32, Library as WindowsLibrary};
use zeroize::{Zeroize, Zeroizing};

use windows_sys::Win32::Foundation::{ERROR_CANCELLED, ERROR_TIMEOUT, HWND, NTE_USER_CANCELLED};
use windows_sys::Win32::Security::Credentials::CRED_MAX_CREDENTIAL_BLOB_SIZE;
use windows_sys::Win32::UI::WindowsAndMessaging::IsWindow;

use crate::sealed::{SealError, unpoison};
use crate::utils::from_wstr;
use crate::webauthn::{
    BOOL, GUID, HRESULT, PBYTE, PWEBAUTHN_ASSERTION, PWEBAUTHN_AUTHENTICATOR_DETAILS_LIST,
    PWEBAUTHN_CREDENTIAL_ATTESTATION, PWEBAUTHN_CREDENTIAL_DETAILS_LIST, WEBAUTHN_API_VERSION_9,
    WEBAUTHN_ASSERTION, WEBAUTHN_ASSERTION_VERSION_6,
    WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE, WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
    WEBAUTHN_AUTHENTICATOR_DETAILS_LIST, WEBAUTHN_AUTHENTICATOR_DETAILS_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_DETAILS_OPTIONS_CURRENT_VERSION,
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION,
    WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG, WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION, WEBAUTHN_CLIENT_DATA,
    WEBAUTHN_COSE_CREDENTIAL_PARAMETER, WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
    WEBAUTHN_CREDENTIAL_ATTESTATION, WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION,
    WEBAUTHN_CREDENTIAL_EX, WEBAUTHN_CREDENTIAL_LIST, WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
    WEBAUTHN_CTAP_ONE_HMAC_SECRET_LENGTH, WEBAUTHN_CTAP_TRANSPORT_INTERNAL,
    WEBAUTHN_GET_CREDENTIALS_OPTIONS, WEBAUTHN_HASH_ALGORITHM_SHA_256, WEBAUTHN_HMAC_SECRET_SALT,
    WEBAUTHN_HMAC_SECRET_SALT_VALUES, WEBAUTHN_RP_ENTITY_INFORMATION,
    WEBAUTHN_USER_ENTITY_INFORMATION, WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
    WebAuthNAuthenticatorGetAssertion, WebAuthNAuthenticatorMakeCredential,
    WebAuthNCancelCurrentOperation, WebAuthNDeletePlatformCredential, WebAuthNFreeAssertion,
    WebAuthNFreeAuthenticatorList, WebAuthNFreeCredentialAttestation,
    WebAuthNFreePlatformCredentialList, WebAuthNGetApiVersionNumber, WebAuthNGetAuthenticatorList,
    WebAuthNGetCancellationId, WebAuthNGetErrorName, WebAuthNGetPlatformCredentialList,
    WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable,
};

const S_OK: HRESULT = 0;
const NTE_NOT_FOUND: HRESULT = 0x8009_0011u32.cast_signed();
const ERROR_CANCELLED_HRESULT: HRESULT = hresult_from_win32(ERROR_CANCELLED);
const ERROR_TIMEOUT_HRESULT: HRESULT = hresult_from_win32(ERROR_TIMEOUT);
const HELLO_NAME: &str = "Windows Hello";

/// `HRESULT_FROM_WIN32` for a Win32 error code.
const fn hresult_from_win32(code: u32) -> HRESULT {
    (0x8007_0000 | (code & 0xFFFF)).cast_signed()
}
// The mirrored attestation and assertion layouts are versions 8 and 6, which API 9 returns.
const ATTESTATION_VERSION_MIN: u32 =
    WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION.cast_unsigned();
const ASSERTION_VERSION_MIN: u32 = WEBAUTHN_ASSERTION_VERSION_6.cast_unsigned();
const HMAC_SECRET_LENGTH: u32 = WEBAUTHN_CTAP_ONE_HMAC_SECRET_LENGTH.cast_unsigned();
const RAW_SALT_FLAG: u32 = WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG.cast_unsigned();
const TRANSPORT_INTERNAL: u32 = WEBAUTHN_CTAP_TRANSPORT_INTERNAL.cast_unsigned();
const ATTACHMENT_PLATFORM: u32 = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM.cast_unsigned();
const UV_REQUIREMENT_REQUIRED: u32 =
    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED.cast_unsigned();
const ATTESTATION_CONVEYANCE_NONE: u32 =
    WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE.cast_unsigned();
const ALG_ES256: i32 = -7;
// authenticator data is 32-byte rpIdHash plus a flags byte plus a counter.
const AUTHENTICATOR_DATA_HEADER_LEN: u32 = 37;
const AUTHENTICATOR_DATA_FLAGS_OFFSET: usize = 32;
const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
pub(crate) const MAX_CREDENTIAL_ID: usize = CRED_MAX_CREDENTIAL_BLOB_SIZE as usize - 72;

/// A live window that may anchor a Windows Hello prompt.
///
/// Implementors must be kept owned in the caller's `Arc` and must keep the
/// actual OS window alive for the whole operation. `hwnd` is that window's
/// handle, not a copy of a window the caller is not keeping alive.
pub trait HelloWindow: Send + Sync {
    fn hwnd(&self) -> HWND;
}

/// How often a cancelled token re-sends its abort to a native call that has not returned.
pub const DEFAULT_ABORT_INTERVAL: Duration = Duration::from_millis(50);

/// Shared cancellation state for one or more in-flight Hello operations.
///
/// Clones share one flag and the registration of every native operation started with
/// them. [`HelloCancellation::cancel`] is safe to call from another thread while the
/// blocking native calls are running, and it aborts each of them. Windows forgets an
/// abort sent before its call starts, so each cancelled call is aborted again every
/// abort interval until it returns.
///
/// Windows 11 25H2 honours the abort of an assertion prompt but almost never the abort
/// of an enrollment prompt, which creates the passkey. A cancelled enrollment can
/// therefore keep its prompt on screen, and its native call running, until the user
/// dismisses it.
#[derive(Clone)]
pub struct HelloCancellation {
    inner: Arc<CancellationState>,
}

struct CancellationState {
    cancelled: AtomicBool,
    registry: Mutex<Registry>,
    abort_interval: Duration,
}

/// Native operations running under one token, each under the ticket its ceremony keeps.
#[derive(Default)]
struct Registry {
    next: u64,
    active: Vec<(u64, GUID)>,
}

impl Default for HelloCancellation {
    fn default() -> Self {
        Self::new()
    }
}

impl HelloCancellation {
    /// A token that re-sends its abort every [`DEFAULT_ABORT_INTERVAL`].
    pub fn new() -> Self {
        Self::with_abort_interval(DEFAULT_ABORT_INTERVAL)
    }

    /// A token that re-sends its abort every `interval` until each cancelled call returns.
    ///
    /// A shorter interval shortens how long a prompt that started just after the cancel
    /// stays visible. An `interval` below 1 ms is raised to 1 ms.
    pub fn with_abort_interval(interval: Duration) -> Self {
        Self {
            inner: Arc::new(CancellationState {
                cancelled: AtomicBool::new(false),
                registry: Mutex::default(),
                abort_interval: interval.max(Duration::from_millis(1)),
            }),
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    pub fn cancel(&self) {
        self.mark_cancelled();
        self.abort_native();
    }

    /// Sets the flag that every operation and waiter checks.
    pub(crate) fn mark_cancelled(&self) {
        self.inner.cancelled.store(true, Ordering::Release);
    }

    /// Asks webauthn.dll to abort every registered native operation.
    pub(crate) fn abort_native(&self) {
        if self.registry().active.is_empty() {
            return;
        }
        let Ok(lib) = load_system_webauthn() else {
            return;
        };
        // SAFETY: the declared type matches the `WebAuthNCancelCurrentOperation` signature.
        let Ok(abort) = (unsafe {
            resolve::<WebAuthNCancelCurrentOperation>(&lib, "WebAuthNCancelCurrentOperation")
        }) else {
            return;
        };
        // SAFETY: `lib` stays loaded for every call, and each GUID came from `WebAuthNGetCancellationId`.
        self.abort_registered(|guid| unsafe { abort(guid) });
    }

    /// Calls `abort` for every registered native operation, outside the registry lock.
    fn abort_registered(&self, mut abort: impl FnMut(&GUID) -> HRESULT) {
        let guids: Vec<GUID> = self
            .registry()
            .active
            .iter()
            .map(|&(_, guid)| guid)
            .collect();
        for guid in &guids {
            // A finished operation rejects its stale id, which needs no handling.
            let _ = abort(guid);
        }
    }

    /// Registers a native operation, returning the ticket that unregisters exactly it.
    fn register(&self, guid: GUID) -> u64 {
        let mut registry = self.registry();
        let ticket = registry.next;
        registry.next += 1;
        registry.active.push((ticket, guid));
        ticket
    }

    fn unregister(&self, ticket: u64) {
        self.registry().active.retain(|&(held, _)| held != ticket);
    }

    fn registry(&self) -> MutexGuard<'_, Registry> {
        unpoison(self.inner.registry.lock())
    }
}

/// Result of one successful Hello PRF enrollment.
pub(crate) struct Enrollment {
    pub credential_id: Vec<u8>,
    pub key: Zeroizing<[u8; 32]>,
}

/// Function pointers copied out of `webauthn.dll`, valid while `_lib` keeps it loaded.
struct WebAuthn {
    _lib: Library,
    uv_available: WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable,
    make_credential: WebAuthNAuthenticatorMakeCredential,
    get_assertion: WebAuthNAuthenticatorGetAssertion,
    free_attestation: WebAuthNFreeCredentialAttestation,
    free_assertion: WebAuthNFreeAssertion,
    get_cancellation_id: WebAuthNGetCancellationId,
    cancel_operation: WebAuthNCancelCurrentOperation,
    get_platform_credential_list: WebAuthNGetPlatformCredentialList,
    free_platform_credential_list: WebAuthNFreePlatformCredentialList,
    get_authenticator_list: WebAuthNGetAuthenticatorList,
    free_authenticator_list: WebAuthNFreeAuthenticatorList,
    delete_platform_credential: WebAuthNDeletePlatformCredential,
    // Optional because it only decorates error messages.
    get_error_name: Option<WebAuthNGetErrorName>,
}

/// Copies the `name` export out of `lib` as a function pointer.
///
/// # Safety
/// `T` must be the export's exact function-pointer type, and `lib` must outlive every use.
unsafe fn resolve<T: Copy>(lib: &Library, name: &str) -> Result<T, SealError> {
    // SAFETY: the caller guarantees `T` matches the export's signature.
    let symbol = unsafe { lib.get::<T>(name) }.map_err(|_| {
        SealError::Unsupported(format!("webauthn.dll is missing the {name} export"))
    })?;
    Ok(*symbol)
}

fn load_system_webauthn() -> Result<Library, libloading::Error> {
    // SAFETY: webauthn.dll is a system library whose initialisation has no preconditions, and
    // the System32-only search prevents loading a substitute from the application path.
    unsafe { WindowsLibrary::load_with_flags("webauthn.dll", LOAD_LIBRARY_SEARCH_SYSTEM32) }
        .map(Into::into)
}

fn load() -> Result<WebAuthn, SealError> {
    let lib = load_system_webauthn().map_err(|error| {
        SealError::Unsupported(format!("webauthn.dll could not be loaded. {error}"))
    })?;
    let required = WEBAUTHN_API_VERSION_9.cast_unsigned();
    // SAFETY: each type is the webauthn.h signature of the export it is resolved from, and
    // `WebAuthn` keeps `lib` loaded for as long as the copied pointers are used.
    unsafe {
        let version =
            resolve::<WebAuthNGetApiVersionNumber>(&lib, "WebAuthNGetApiVersionNumber")?();
        if let Some(error) = api_version_error(version, required) {
            return Err(error);
        }
        Ok(WebAuthn {
            uv_available: resolve(
                &lib,
                "WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable",
            )?,
            make_credential: resolve(&lib, "WebAuthNAuthenticatorMakeCredential")?,
            get_assertion: resolve(&lib, "WebAuthNAuthenticatorGetAssertion")?,
            free_attestation: resolve(&lib, "WebAuthNFreeCredentialAttestation")?,
            free_assertion: resolve(&lib, "WebAuthNFreeAssertion")?,
            get_cancellation_id: resolve(&lib, "WebAuthNGetCancellationId")?,
            cancel_operation: resolve(&lib, "WebAuthNCancelCurrentOperation")?,
            get_platform_credential_list: resolve(&lib, "WebAuthNGetPlatformCredentialList")?,
            free_platform_credential_list: resolve(&lib, "WebAuthNFreePlatformCredentialList")?,
            get_authenticator_list: resolve(&lib, "WebAuthNGetAuthenticatorList")?,
            free_authenticator_list: resolve(&lib, "WebAuthNFreeAuthenticatorList")?,
            delete_platform_credential: resolve(&lib, "WebAuthNDeletePlatformCredential")?,
            get_error_name: resolve(&lib, "WebAuthNGetErrorName").ok(),
            _lib: lib,
        })
    }
}

/// Owns native scratch buffers not borrowed from the operation frame.
struct NativeBuffers {
    bytes: Vec<Vec<u8>>,
    wide: Vec<Vec<u16>>,
}

impl NativeBuffers {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            wide: Vec::new(),
        }
    }

    fn add_bytes_owned(&mut self, block: Vec<u8>) -> *const u8 {
        let ptr = block.as_ptr();
        self.bytes.push(block);
        ptr
    }

    fn add_wide(&mut self, text: &str) -> *const u16 {
        let mut block: Vec<u16> = text.encode_utf16().collect();
        block.push(0);
        let ptr = block.as_ptr();
        self.wide.push(block);
        ptr
    }
}

/// The error for a WebAuthn API below the required version.
fn api_version_error(version: u32, required: u32) -> Option<SealError> {
    if version < required {
        Some(SealError::Unsupported(format!(
            "webauthn API version {version} is below the required {required}"
        )))
    } else {
        None
    }
}

/// Reports whether Windows Hello can back a sealed store on this machine.
pub(crate) fn available() -> Result<(), SealError> {
    let api = load()?;
    platform_authenticator_available(&api)?;
    select_hello_authenticator(&api)?;
    Ok(())
}

/// Checked prerequisites shared by enrollment and assertion, prepared before any record changes.
pub(crate) struct Ceremony {
    api: WebAuthn,
    // Keeps the caller's window alive until the native call returns.
    _owner: Arc<dyn HelloWindow>,
    hwnd: HWND,
    guid: GUID,
    authenticator_id: Vec<u8>,
}

impl Ceremony {
    /// Checks the owner window, the cancel flag and the Windows Hello authenticator, without a
    /// prompt.
    pub(crate) fn begin(
        owner: Arc<dyn HelloWindow>,
        cancel: &HelloCancellation,
    ) -> Result<Self, SealError> {
        let hwnd = live_owner_window(&owner)?;
        if cancel.is_cancelled() {
            return Err(SealError::Cancelled);
        }
        let api = load()?;
        platform_authenticator_available(&api)?;
        let authenticator_id = select_hello_authenticator(&api)?;
        let guid = get_cancellation_id(&api)?;
        Ok(Self {
            api,
            _owner: owner,
            hwnd,
            guid,
            authenticator_id,
        })
    }

    /// Runs the blocking native call while `cancel` can abort it through this ceremony's id.
    fn run(
        &self,
        cancel: &HelloCancellation,
        call: impl FnOnce() -> HRESULT,
    ) -> Result<HRESULT, SealError> {
        let abort = self.api.cancel_operation;
        run_registered(
            cancel,
            self.guid,
            // SAFETY: `self.api` keeps webauthn.dll loaded for the whole call, and `guid` is
            // this ceremony's id from `WebAuthNGetCancellationId`.
            |guid| unsafe { abort(guid) },
            call,
        )
    }
}

/// Runs `call` registered under `guid`, aborting it through `abort` once `cancel` is set.
///
/// A cancel before the flag check stops the call from starting. Windows forgets an abort
/// sent before its call starts, so a watcher aborts the call again every abort interval
/// from the cancel until the call returns.
fn run_registered(
    cancel: &HelloCancellation,
    guid: GUID,
    abort: impl Fn(&GUID) -> HRESULT + Send,
    call: impl FnOnce() -> HRESULT,
) -> Result<HRESULT, SealError> {
    let ticket = cancel.register(guid);
    if cancel.is_cancelled() {
        cancel.unregister(ticket);
        return Err(SealError::Cancelled);
    }
    let (returned, stop) = mpsc::channel::<()>();
    let hr = std::thread::scope(|scope| {
        scope.spawn(move || {
            let interval = cancel.inner.abort_interval;
            while let Err(RecvTimeoutError::Timeout) = stop.recv_timeout(interval) {
                if cancel.is_cancelled() {
                    // A rejected abort is retried on the next tick until the call returns.
                    let _ = abort(&guid);
                }
            }
        });
        let hr = call();
        drop(returned);
        hr
    });
    cancel.unregister(ticket);
    Ok(hr)
}

/// The byte length the native authenticator-id fields need.
fn authenticator_id_len(id: &[u8]) -> u32 {
    u32::try_from(id.len()).expect("authenticator id length came from a u32")
}

/// The COSE parameter that binds the credential to the P-256 algorithm.
fn es256_credential_parameter() -> WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
    WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
        dwVersion: 1,
        pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        lAlg: ALG_ES256,
    }
}

/// The make-credential options that bind the enrollment to this platform authenticator.
fn make_credential_options(
    timeout: Duration,
    cancellation_id: &mut GUID,
    prf: &mut WEBAUTHN_HMAC_SECRET_SALT,
    authenticator_id: &[u8],
) -> WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
        dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION.cast_unsigned(),
        dwTimeoutMilliseconds: timeout_ms(timeout),
        dwAuthenticatorAttachment: ATTACHMENT_PLATFORM,
        dwUserVerificationRequirement: UV_REQUIREMENT_REQUIRED,
        dwAttestationConveyancePreference: ATTESTATION_CONVEYANCE_NONE,
        dwFlags: RAW_SALT_FLAG,
        pCancellationId: std::ptr::addr_of_mut!(*cancellation_id),
        bEnablePrf: 1,
        pPRFGlobalEval: prf,
        cbAuthenticatorId: authenticator_id_len(authenticator_id),
        pbAuthenticatorId: authenticator_id.as_ptr().cast_mut(),
        ..Default::default()
    }
}

/// The get-assertion options that bind the assertion to this platform authenticator.
fn get_assertion_options(
    timeout: Duration,
    cancellation_id: &mut GUID,
    allow: &mut WEBAUTHN_CREDENTIAL_LIST,
    salt_values: &mut WEBAUTHN_HMAC_SECRET_SALT_VALUES,
    authenticator_id: &[u8],
) -> WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
        dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION.cast_unsigned(),
        dwTimeoutMilliseconds: timeout_ms(timeout),
        dwAuthenticatorAttachment: ATTACHMENT_PLATFORM,
        dwUserVerificationRequirement: UV_REQUIREMENT_REQUIRED,
        dwFlags: RAW_SALT_FLAG,
        pCancellationId: std::ptr::addr_of_mut!(*cancellation_id),
        pAllowCredentialList: allow,
        pHmacSecretSaltValues: salt_values,
        cbAuthenticatorId: authenticator_id_len(authenticator_id),
        pbAuthenticatorId: authenticator_id.as_ptr().cast_mut(),
        ..Default::default()
    }
}

/// The result of a make-credential call once the native attestation is free to read.
fn attestation_outcome(
    hr: HRESULT,
    attestation: PWEBAUTHN_CREDENTIAL_ATTESTATION,
    free: WebAuthNFreeCredentialAttestation,
    failure: impl Fn(HRESULT) -> SealError,
) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), SealError> {
    if hr != S_OK {
        return Err(failure(hr));
    }
    if attestation.is_null() {
        return Err(SealError::Corrupt(
            "make credential returned a null attestation".into(),
        ));
    }
    // SAFETY: a successful make returns a non-null attestation that starts with its version.
    let outcome = unsafe { read_attestation(attestation) };
    // SAFETY: webauthn.dll allocated this attestation and owns its free function.
    unsafe { free(attestation) };
    outcome
}

/// The result of a get-assertion call once the native assertion is free to read.
fn assertion_outcome(
    hr: HRESULT,
    assertion: PWEBAUTHN_ASSERTION,
    credential_id: &[u8],
    free: WebAuthNFreeAssertion,
    failure: impl Fn(HRESULT) -> SealError,
) -> Result<Zeroizing<[u8; 32]>, SealError> {
    if hr != S_OK {
        return Err(failure(hr));
    }
    if assertion.is_null() {
        return Err(SealError::Corrupt(
            "get assertion returned a null assertion".into(),
        ));
    }
    // SAFETY: a successful get returns a non-null assertion that starts with its version.
    let outcome = unsafe { read_assertion(assertion, credential_id) };
    // SAFETY: `assertion` was allocated by webauthn.dll and is freed here.
    unsafe { free(assertion) };
    outcome
}

/// Enrolls the Hello PRF credential for `rp_id` under the caller-provided `user_id` and raw
/// `salt`, giving Windows the time left before `deadline`.
pub(crate) fn enroll(
    mut ceremony: Ceremony,
    rp_id: &str,
    user_id: &[u8; 32],
    salt: &[u8; 32],
    cancel: &HelloCancellation,
    deadline: Instant,
) -> Result<Enrollment, SealError> {
    let timeout = dispatch_timeout(deadline)?;
    let api = &ceremony.api;
    let mut bufs = NativeBuffers::new();
    let rp = build_rp_entity(&mut bufs, rp_id);
    let user = WEBAUTHN_USER_ENTITY_INFORMATION {
        dwVersion: 1,
        cbId: 32,
        pbId: user_id.as_ptr().cast_mut(),
        pwszName: bufs.add_wide("hello-prf-store"),
        pwszIcon: std::ptr::null(),
        pwszDisplayName: bufs.add_wide("Windows Hello PRF Store"),
    };
    let mut param = es256_credential_parameter();
    let params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
        cCredentialParameters: 1,
        pCredentialParameters: &mut param,
    };
    let client = build_client_data(&mut bufs, "create", rp_id)?;
    let mut salt_value = prf_salt(salt);
    let options = make_credential_options(
        timeout,
        &mut ceremony.guid,
        &mut salt_value,
        &ceremony.authenticator_id,
    );
    let mut attestation: PWEBAUTHN_CREDENTIAL_ATTESTATION = std::ptr::null_mut();
    let hr = ceremony.run(cancel, || {
        // SAFETY: every pointer is owned by `bufs` or this frame and outlives the call; the
        // owner `Arc` keeps the window alive.
        unsafe {
            (api.make_credential)(
                ceremony.hwnd,
                &rp,
                &user,
                &params,
                &client,
                &options,
                &mut attestation,
            )
        }
    })?;
    let outcome = attestation_outcome(hr, attestation, api.free_attestation, |hr| {
        operation_error(api, hr, "make credential", cancel)
    });
    match outcome {
        Ok((credential_id, key)) => Ok(Enrollment { credential_id, key }),
        Err(error) => {
            delete_created_credential(api, rp_id, user_id)?;
            Err(error)
        }
    }
}

/// Asserts the enrolled credential and returns the PRF-derived 32-byte key, giving Windows the
/// time left before `deadline`.
pub(crate) fn assert_prf(
    mut ceremony: Ceremony,
    rp_id: &str,
    credential_id: &[u8],
    salt: &[u8; 32],
    cancel: &HelloCancellation,
    deadline: Instant,
) -> Result<Zeroizing<[u8; 32]>, SealError> {
    let timeout = dispatch_timeout(deadline)?;
    let api = &ceremony.api;
    let credential_len = u32::try_from(credential_id.len())
        .map_err(|_| SealError::Corrupt("credential ID is too long".into()))?;
    let mut bufs = NativeBuffers::new();
    let client = build_client_data(&mut bufs, "get", rp_id)?;
    let mut credential_ex = WEBAUTHN_CREDENTIAL_EX {
        dwVersion: 1,
        cbId: credential_len,
        pbId: credential_id.as_ptr().cast_mut(),
        pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        // 0 means no transport restriction, since the authenticator id binding routes the call.
        dwTransports: 0,
    };
    let mut allow_array = [std::ptr::from_mut(&mut credential_ex)];
    let mut allow_list = WEBAUTHN_CREDENTIAL_LIST {
        cCredentials: 1,
        ppCredentials: allow_array.as_mut_ptr(),
    };
    let mut first = prf_salt(salt);
    let mut salt_values = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
        pGlobalHmacSalt: &mut first,
        cCredWithHmacSecretSaltList: 0,
        pCredWithHmacSecretSaltList: std::ptr::null_mut(),
    };
    let options = get_assertion_options(
        timeout,
        &mut ceremony.guid,
        &mut allow_list,
        &mut salt_values,
        &ceremony.authenticator_id,
    );
    let rp_wide = bufs.add_wide(rp_id);
    let mut assertion: PWEBAUTHN_ASSERTION = std::ptr::null_mut();
    let hr = ceremony.run(cancel, || {
        // SAFETY: every pointer is owned by `bufs` or this frame and outlives the call; the
        // owner `Arc` keeps the window alive.
        unsafe { (api.get_assertion)(ceremony.hwnd, rp_wide, &client, &options, &mut assertion) }
    })?;
    assertion_outcome(hr, assertion, credential_id, api.free_assertion, |hr| {
        operation_error(api, hr, "get assertion", cancel)
    })
}

/// Finds the platform credential created for exactly `rp_id` and `user_id`.
///
/// Recovers a credential left behind by a crashed enrollment, and refuses ambiguity.
pub(crate) fn recover_created(
    rp_id: &str,
    user_id: &[u8; 32],
) -> Result<Option<Vec<u8>>, SealError> {
    let mut ids = owned_credentials(&load()?, rp_id, Some(user_id))?;
    match ids.len() {
        0 | 1 => Ok(ids.pop()),
        count => Err(SealError::Conflict(format!(
            "{count} platform credentials match the exact RP and user id"
        ))),
    }
}

/// Deletes the platform credential with the exact `credential_id`, verifying its absence.
pub(crate) fn remove_exact(rp_id: &str, credential_id: &[u8]) -> Result<(), SealError> {
    delete_verified(&load()?, rp_id, &[credential_id.to_vec()])
}

/// Deletes every platform credential listed under exactly `rp_id`, verifying their absence.
///
/// The RP identifier is derived from one store's identity, so it cannot match another store.
pub(crate) fn remove_all_for_rp(rp_id: &str) -> Result<(), SealError> {
    let api = match load() {
        Ok(api) => api,
        // Enrollment requires this API, so no credential for the store can exist without it.
        Err(SealError::Unsupported(_)) => return Ok(()),
        Err(error) => return Err(error),
    };
    let ids = owned_credentials(&api, rp_id, None)?;
    delete_verified(&api, rp_id, &ids)
}

/// Credential IDs listed under exactly `rp_id`, narrowed to `user_id` when given.
fn owned_credentials(
    api: &WebAuthn,
    rp_id: &str,
    user_id: Option<&[u8; 32]>,
) -> Result<Vec<Vec<u8>>, SealError> {
    let entries = list_platform_credentials(api, rp_id)?;
    Ok(owned_ids(entries, rp_id, user_id))
}

/// Credential ids of the entries listed under exactly `rp_id`, narrowed to `user_id` when
/// given, dropping entries without a credential id.
fn owned_ids(
    entries: Vec<ListedCredential>,
    rp_id: &str,
    user_id: Option<&[u8; 32]>,
) -> Vec<Vec<u8>> {
    entries
        .into_iter()
        .filter(|entry| {
            entry.rp_id == rp_id
                && !entry.credential_id.is_empty()
                && user_id.is_none_or(|user| entry.user_id.as_deref() == Some(user.as_slice()))
        })
        .map(|entry| entry.credential_id)
        .collect()
}

fn delete_verified(api: &WebAuthn, rp_id: &str, ids: &[Vec<u8>]) -> Result<(), SealError> {
    for id in ids {
        delete_credential(api, id)?;
    }
    if list_platform_credentials(api, rp_id)?
        .iter()
        .any(|entry| ids.contains(&entry.credential_id))
    {
        return Err(SealError::Corrupt(
            "platform credential still listed after deletion".into(),
        ));
    }
    Ok(())
}

fn build_rp_entity(bufs: &mut NativeBuffers, rp_id: &str) -> WEBAUTHN_RP_ENTITY_INFORMATION {
    WEBAUTHN_RP_ENTITY_INFORMATION {
        dwVersion: 1,
        pwszId: bufs.add_wide(rp_id),
        pwszName: bufs.add_wide("Windows Hello PRF Store"),
        pwszIcon: std::ptr::null(),
    }
}

fn prf_salt(salt: &[u8; 32]) -> WEBAUTHN_HMAC_SECRET_SALT {
    WEBAUTHN_HMAC_SECRET_SALT {
        cbFirst: HMAC_SECRET_LENGTH,
        pbFirst: salt.as_ptr().cast_mut(),
        ..Default::default()
    }
}

fn live_owner_window(owner: &Arc<dyn HelloWindow>) -> Result<HWND, SealError> {
    let hwnd = owner.hwnd();
    // SAFETY: `IsWindow` accepts any handle value; a dead or null owner fails before any prompt.
    if unsafe { IsWindow(hwnd) } == 0 {
        return Err(SealError::MissingOwner);
    }
    Ok(hwnd)
}

/// The outcome of the platform-authenticator availability probe.
#[derive(Debug, PartialEq)]
enum PlatformProbe {
    /// WebAuthn reported an error hr for the probe.
    Failed(HRESULT),
    /// WebAuthn succeeded but no user-verifying platform authenticator is present.
    Missing,
    /// A user-verifying platform authenticator is present.
    Present,
}

/// Decides the [`PlatformProbe`] outcome from the probe hr and out flag.
fn platform_probe(hr: HRESULT, available: BOOL) -> PlatformProbe {
    if hr != S_OK {
        return PlatformProbe::Failed(hr);
    }
    if available == 0 {
        return PlatformProbe::Missing;
    }
    PlatformProbe::Present
}

fn platform_authenticator_available(api: &WebAuthn) -> Result<(), SealError> {
    let mut available: BOOL = 0;
    // SAFETY: the out pointer is a valid, writable BOOL.
    let hr = unsafe { (api.uv_available)(&mut available) };
    match platform_probe(hr, available) {
        PlatformProbe::Failed(hr) => Err(hr_error(
            api,
            hr,
            "query platform authenticator availability",
        )),
        PlatformProbe::Missing => Err(SealError::Unsupported(
            "no user-verifying platform authenticator available".into(),
        )),
        PlatformProbe::Present => Ok(()),
    }
}

/// The follow-up to a `WebAuthNGetAuthenticatorList` result.
#[derive(Debug, PartialEq)]
enum EnumerationStep {
    /// The enumeration hr is unacceptable, so no list was allocated.
    Failed(HRESULT),
    /// The list can be read, and `free` marks whether to release it afterwards.
    Proceed { free: bool },
}

/// Decides the [`EnumerationStep`] from the enumeration hr and list pointer.
fn enumeration_step(hr: HRESULT, list: PWEBAUTHN_AUTHENTICATOR_DETAILS_LIST) -> EnumerationStep {
    if hr != S_OK && hr != NTE_NOT_FOUND {
        return EnumerationStep::Failed(hr);
    }
    EnumerationStep::Proceed {
        free: !list.is_null(),
    }
}

/// The identifier of the one Windows Hello authenticator WebAuthn lists.
fn select_hello_authenticator(api: &WebAuthn) -> Result<Vec<u8>, SealError> {
    let options = WEBAUTHN_AUTHENTICATOR_DETAILS_OPTIONS {
        dwVersion: WEBAUTHN_AUTHENTICATOR_DETAILS_OPTIONS_CURRENT_VERSION.cast_unsigned(),
    };
    let mut list: PWEBAUTHN_AUTHENTICATOR_DETAILS_LIST = std::ptr::null_mut();
    // SAFETY: `options` and the out pointer are live locals.
    let hr = unsafe { (api.get_authenticator_list)(&options, &mut list) };
    match enumeration_step(hr, list) {
        EnumerationStep::Failed(hr) => Err(hr_error(api, hr, "enumerate authenticators")),
        EnumerationStep::Proceed { free } => {
            let empty = WEBAUTHN_AUTHENTICATOR_DETAILS_LIST::default();
            // SAFETY: a non-null list from WebAuthNGetAuthenticatorList stays valid until the
            // free call below, and the empty list holds no entries.
            let selected = unsafe { hello_authenticator_id(list.as_ref().unwrap_or(&empty)) };
            if free {
                // SAFETY: `list` was allocated by webauthn.dll and is freed exactly once.
                unsafe { (api.free_authenticator_list)(list) };
            }
            selected
        }
    }
}

/// Picks the single Windows Hello entry of an authenticator list, by name.
///
/// # Safety
/// `list` must hold `cAuthenticatorDetails` entry pointers, each null or a valid entry whose
/// identifier bytes and NUL-terminated name, at any alignment, live as long as `list`.
unsafe fn hello_authenticator_id(
    list: &WEBAUTHN_AUTHENTICATOR_DETAILS_LIST,
) -> Result<Vec<u8>, SealError> {
    let mut ids: Vec<Vec<u8>> = Vec::new();
    let mut locked = false;
    // SAFETY: the caller guarantees the entry pointers.
    for entry in unsafe { native_entries(list.cAuthenticatorDetails, list.ppAuthenticatorDetails) }
    {
        // SAFETY: the caller guarantees a NUL-terminated name, read without alignment.
        if !unsafe { from_wstr(entry.pwszAuthenticatorName) }.eq_ignore_ascii_case(HELLO_NAME) {
            continue;
        }
        if entry.cbAuthenticatorId == 0 || entry.pbAuthenticatorId.is_null() {
            continue;
        }
        // SAFETY: the caller guarantees `cbAuthenticatorId` readable bytes.
        let id = unsafe {
            std::slice::from_raw_parts(entry.pbAuthenticatorId, entry.cbAuthenticatorId as usize)
        };
        locked |= entry.bLocked != 0;
        if !ids.iter().any(|existing| existing == id) {
            ids.push(id.to_vec());
        }
    }
    match ids.len() {
        0 => Err(SealError::Unsupported(
            "Windows Hello authenticator not found in the WebAuthn authenticator enumeration"
                .into(),
        )),
        1 if locked => Err(SealError::Locked),
        1 => Ok(ids.remove(0)),
        count => Err(SealError::Conflict(format!(
            "{count} Windows Hello authenticators enumerated, expected one"
        ))),
    }
}

fn get_cancellation_id(api: &WebAuthn) -> Result<GUID, SealError> {
    let mut guid = GUID::default();
    // SAFETY: the out pointer is a valid, writable GUID-sized struct.
    let hr = unsafe { (api.get_cancellation_id)(&mut guid) };
    cancellation_id_outcome(hr, &guid, |hr| hr_error(api, hr, "get cancellation id"))
}

/// The cancellation id a successful `WebAuthNGetCancellationId` wrote.
fn cancellation_id_outcome(
    hr: HRESULT,
    guid: &GUID,
    failure: impl Fn(HRESULT) -> SealError,
) -> Result<GUID, SealError> {
    if hr == S_OK {
        Ok(*guid)
    } else {
        Err(failure(hr))
    }
}

#[derive(Debug, PartialEq)]
struct ListedCredential {
    credential_id: Vec<u8>,
    rp_id: String,
    user_id: Option<Vec<u8>>,
}

fn list_platform_credentials(
    api: &WebAuthn,
    rp_id: &str,
) -> Result<Vec<ListedCredential>, SealError> {
    let mut bufs = NativeBuffers::new();
    let options = WEBAUTHN_GET_CREDENTIALS_OPTIONS {
        dwVersion: 1,
        pwszRpId: bufs.add_wide(rp_id),
        bBrowserInPrivateMode: 0,
    };
    let mut list: PWEBAUTHN_CREDENTIAL_DETAILS_LIST = std::ptr::null_mut();
    // SAFETY: `options` and the out pointer are live locals.
    let hr = unsafe { (api.get_platform_credential_list)(&options, &mut list) };
    check_list_hr(hr).map_err(|hr| hr_error(api, hr, "enumerate platform credentials"))?;
    if list.is_null() {
        return Ok(Vec::new());
    }
    // SAFETY: the non-null list stays valid, with `cCredentialDetails` entry pointers, until
    // the free call below.
    let entries = unsafe { platform_credential_entries(list) };
    // SAFETY: `list` was allocated by webauthn.dll and is freed exactly once.
    unsafe { (api.free_platform_credential_list)(list) };
    Ok(entries)
}

/// Accepts the success and not-found result codes of a credential enumeration.
fn check_list_hr(hr: HRESULT) -> Result<(), HRESULT> {
    if hr == S_OK || hr == NTE_NOT_FOUND {
        Ok(())
    } else {
        Err(hr)
    }
}

/// Parses the entries of a non-null platform credential list into owned records.
///
/// # Safety
/// `list` must be non-null and hold `cCredentialDetails` entry pointers, each null or a valid
/// entry whose identifier bytes, user id bytes and NUL-terminated `pwszId` live as long as the
/// list.
unsafe fn platform_credential_entries(
    list: PWEBAUTHN_CREDENTIAL_DETAILS_LIST,
) -> Vec<ListedCredential> {
    // SAFETY: the caller guarantees a non-null list with `cCredentialDetails` readable entries.
    let details = unsafe { list.as_ref().unwrap() };
    let mut entries = Vec::new();
    for index in 0..details.cCredentialDetails as usize {
        // SAFETY: the entry pointer table holds `cCredentialDetails` readable pointers.
        let entry = unsafe { *details.ppCredentialDetails.add(index) };
        if entry.is_null() {
            continue;
        }
        // SAFETY: every credential details version carries its version-1 prefix, read
        // without alignment.
        let cb_credential_id = unsafe { (&raw const (*entry).cbCredentialID).read_unaligned() };
        let pb_credential_id = unsafe { (&raw const (*entry).pbCredentialID).read_unaligned() };
        // SAFETY: the count and pointer come from the native entry.
        let credential_id = unsafe { native_id_bytes(cb_credential_id, pb_credential_id) };
        let rp_information = unsafe { (&raw const (*entry).pRpInformation).read_unaligned() };
        let entry_rp_id = if rp_information.is_null() {
            String::new()
        } else {
            // SAFETY: the nested RP entity and its NUL-terminated id live as long as the list.
            let rp_id_ptr = unsafe { (&raw const (*rp_information).pwszId).read_unaligned() };
            unsafe { from_wstr(rp_id_ptr) }
        };
        let user_information = unsafe { (&raw const (*entry).pUserInformation).read_unaligned() };
        let entry_user_id = if user_information.is_null() {
            None
        } else {
            // SAFETY: the nested user entity and its id bytes live as long as the list.
            let cb_id = unsafe { (&raw const (*user_information).cbId).read_unaligned() };
            let pb_id = unsafe { (&raw const (*user_information).pbId).read_unaligned() };
            // SAFETY: the count and pointer come from the native entry.
            Some(unsafe { native_id_bytes(cb_id, pb_id) }).filter(|id| !id.is_empty())
        };
        entries.push(ListedCredential {
            credential_id,
            rp_id: entry_rp_id,
            user_id: entry_user_id,
        });
    }
    entries
}

/// Copies `cb` bytes from `pb` into a vector, empty when the entry carries no id.
///
/// # Safety
/// `pb` must be valid for `cb` bytes when `cb` is greater than zero and `pb` is not null.
unsafe fn native_id_bytes(cb: u32, pb: PBYTE) -> Vec<u8> {
    if cb > 0 && !pb.is_null() {
        // SAFETY: the caller guarantees `pb` is valid for `cb` bytes.
        // `cb` is a native u32 count, lossless in `usize` on the supported targets.
        unsafe { std::slice::from_raw_parts(pb, cb as usize) }.to_vec()
    } else {
        Vec::new()
    }
}

fn delete_credential(api: &WebAuthn, credential_id: &[u8]) -> Result<(), SealError> {
    let cb = u32::try_from(credential_id.len())
        .map_err(|_| SealError::Corrupt("credential ID is too long".into()))?;
    // SAFETY: the id slice is valid for cb bytes for the call duration.
    let hr = unsafe { (api.delete_platform_credential)(cb, credential_id.as_ptr().cast_mut()) };
    match hr {
        S_OK | NTE_NOT_FOUND => Ok(()),
        other => Err(hr_error(api, other, "delete platform credential")),
    }
}

fn delete_created_credential(
    api: &WebAuthn,
    rp_id: &str,
    user_id: &[u8; 32],
) -> Result<(), SealError> {
    let ids = owned_credentials(api, rp_id, Some(user_id))?;
    delete_verified(api, rp_id, &ids)
}

/// # Safety
/// `attestation` must point to a native attestation whose `dwVersion` is readable.
unsafe fn read_attestation(
    attestation: *const WEBAUTHN_CREDENTIAL_ATTESTATION,
) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), SealError> {
    // SAFETY: every attestation version begins with `dwVersion`, read without a whole-struct
    // reference.
    let version = unsafe { (&raw const (*attestation).dwVersion).read_unaligned() };
    if version < ATTESTATION_VERSION_MIN {
        return Err(SealError::Corrupt(format!(
            "attestation version {version} is below the mirrored version {ATTESTATION_VERSION_MIN}"
        )));
    }
    // SAFETY: an attestation of at least the mirrored version carries every field of the
    // mirrored layout, read field by field.
    let used_transport = unsafe { (&raw const (*attestation).dwUsedTransport).read_unaligned() };
    if used_transport & TRANSPORT_INTERNAL == 0 {
        return Err(SealError::Unsupported(
            "make credential did not use the internal Windows Hello transport".into(),
        ));
    }
    let transports = unsafe { (&raw const (*attestation).dwTransports).read_unaligned() };
    if transports & TRANSPORT_INTERNAL == 0 {
        return Err(SealError::Unsupported(
            "attestation reports no internal Windows Hello transport".into(),
        ));
    }
    let prf_enabled = unsafe { (&raw const (*attestation).bPrfEnabled).read_unaligned() };
    if prf_enabled == 0 {
        return Err(SealError::Unsupported(
            "Windows Hello credential lacks PRF support".into(),
        ));
    }
    let pb_credential_id = unsafe { (&raw const (*attestation).pbCredentialId).read_unaligned() };
    let cb_credential_id = unsafe { (&raw const (*attestation).cbCredentialId).read_unaligned() };
    let credential_id = read_credential_id(pb_credential_id.cast(), cb_credential_id)?;
    let pb_authenticator_data =
        unsafe { (&raw const (*attestation).pbAuthenticatorData).read_unaligned() };
    let cb_authenticator_data =
        unsafe { (&raw const (*attestation).cbAuthenticatorData).read_unaligned() };
    check_authenticator_data(pb_authenticator_data.cast(), cb_authenticator_data)?;
    let hmac_secret = unsafe { (&raw const (*attestation).pHmacSecret).read_unaligned() };
    let key = read_prf_key(hmac_secret, "make credential")?;
    Ok((credential_id, key))
}

/// # Safety
/// `assertion` must point to a native assertion whose `dwVersion` is readable.
unsafe fn read_assertion(
    assertion: *const WEBAUTHN_ASSERTION,
    requested_id: &[u8],
) -> Result<Zeroizing<[u8; 32]>, SealError> {
    // SAFETY: every assertion version begins with `dwVersion`, read without a whole-struct
    // reference.
    let version = unsafe { (&raw const (*assertion).dwVersion).read_unaligned() };
    if version < ASSERTION_VERSION_MIN {
        return Err(SealError::Corrupt(format!(
            "assertion version {version} is below the mirrored version {ASSERTION_VERSION_MIN}"
        )));
    }
    // SAFETY: an assertion of at least the mirrored version carries every version-6 field,
    // read field by field.
    let used_transport = unsafe { (&raw const (*assertion).dwUsedTransport).read_unaligned() };
    if used_transport & TRANSPORT_INTERNAL == 0 {
        return Err(SealError::Unsupported(
            "get assertion did not use the internal Windows Hello transport".into(),
        ));
    }
    let used_len = unsafe { (&raw const (*assertion).Credential.cbId).read_unaligned() };
    let used_ptr = unsafe { (&raw const (*assertion).Credential.pbId).read_unaligned() };
    if used_len as usize != requested_id.len() || used_ptr.is_null() {
        return Err(SealError::Corrupt(
            "assertion used a different credential id".into(),
        ));
    }
    // SAFETY: `used_len` equals `requested_id.len()` at this point.
    let used: &[u8] = unsafe { std::slice::from_raw_parts(used_ptr.cast(), requested_id.len()) };
    if used != requested_id {
        return Err(SealError::Corrupt(
            "assertion used a different credential id".into(),
        ));
    }
    let pb_authenticator_data =
        unsafe { (&raw const (*assertion).pbAuthenticatorData).read_unaligned() };
    let cb_authenticator_data =
        unsafe { (&raw const (*assertion).cbAuthenticatorData).read_unaligned() };
    check_authenticator_data(pb_authenticator_data.cast(), cb_authenticator_data)?;
    let hmac_secret = unsafe { (&raw const (*assertion).pHmacSecret).read_unaligned() };
    read_prf_key(hmac_secret, "get assertion")
}

fn read_credential_id(ptr: *const u8, len: u32) -> Result<Vec<u8>, SealError> {
    let length = usize::try_from(len)
        .map_err(|_| SealError::Corrupt("invalid credential ID length".into()))?;
    if length == 0 || length > MAX_CREDENTIAL_ID || ptr.is_null() {
        return Err(SealError::Corrupt(format!(
            "credential ID length {len} cannot fit enrollment metadata"
        )));
    }
    // SAFETY: length is bounded by the local credential metadata capacity.
    Ok(unsafe { std::slice::from_raw_parts(ptr, length) }.to_vec())
}

fn check_authenticator_data(data: *const u8, len: u32) -> Result<(), SealError> {
    if data.is_null() {
        return Err(SealError::Corrupt(
            "authenticator data pointer is null".into(),
        ));
    }
    if len < AUTHENTICATOR_DATA_HEADER_LEN {
        return Err(SealError::Corrupt(format!(
            "authenticator data length {len} is below the {AUTHENTICATOR_DATA_HEADER_LEN}-byte header"
        )));
    }
    // SAFETY: the native buffer has at least the fixed header length.
    let header =
        unsafe { std::slice::from_raw_parts(data, AUTHENTICATOR_DATA_HEADER_LEN as usize) };
    let flags = header[AUTHENTICATOR_DATA_FLAGS_OFFSET];
    if flags & FLAG_USER_PRESENT == 0 {
        return Err(SealError::Corrupt(
            "authenticator data lacks the user presence bit".into(),
        ));
    }
    if flags & FLAG_USER_VERIFIED == 0 {
        return Err(SealError::Corrupt(
            "authenticator data lacks the user verification bit".into(),
        ));
    }
    Ok(())
}

fn read_prf_key(
    hmac_secret: *const WEBAUTHN_HMAC_SECRET_SALT,
    operation: &str,
) -> Result<Zeroizing<[u8; 32]>, SealError> {
    if hmac_secret.is_null() {
        return Err(SealError::Unsupported(format!(
            "{operation} enabled PRF but returned no hmac secret"
        )));
    }
    // SAFETY: a non-null `pHmacSecret` points at the fixed-layout salt value webauthn.dll owns.
    let salt = unsafe { &*hmac_secret };
    if salt.pbFirst.is_null() {
        return Err(SealError::Unsupported(format!(
            "{operation} returned an empty hmac secret"
        )));
    }
    // SAFETY: webauthn.dll reports `cbFirst` writable bytes at `pbFirst`, owned by the response
    // the caller frees after this returns.
    let native = unsafe { std::slice::from_raw_parts_mut(salt.pbFirst, salt.cbFirst as usize) };
    let key = if salt.cbFirst == HMAC_SECRET_LENGTH {
        let mut key = Zeroizing::from([0u8; 32]);
        key.copy_from_slice(native);
        Ok(key)
    } else {
        Err(SealError::Unsupported(format!(
            "{operation} returned an hmac secret of {} bytes instead of {HMAC_SECRET_LENGTH}",
            salt.cbFirst
        )))
    };
    native.zeroize();
    key
}

fn build_client_data(
    bufs: &mut NativeBuffers,
    operation: &str,
    rp_id: &str,
) -> Result<WEBAUTHN_CLIENT_DATA, SealError> {
    let mut challenge = [0u8; 32];
    fill(&mut challenge)
        .map_err(|error| SealError::Platform(format!("challenge randomness failed. {error}")))?;
    // `rp_id` is lowercase hex plus `.invalid`, so it needs no JSON escaping.
    let json = format!(
        "{{\"type\":\"webauthn.{operation}\",\"challenge\":\"{}\",\"origin\":\"https://{rp_id}\",\"crossOrigin\":false}}",
        base64url(&challenge),
    );
    let len = json.len();
    debug_assert!(len <= u32::MAX as usize, "client data json fits in a DWORD");
    Ok(WEBAUTHN_CLIENT_DATA {
        dwVersion: 1,
        cbClientDataJSON: len as u32,
        pbClientDataJSON: bufs.add_bytes_owned(json.into_bytes()).cast_mut(),
        pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
    })
}

fn operation_error(
    api: &WebAuthn,
    hr: HRESULT,
    operation: &str,
    cancel: &HelloCancellation,
) -> SealError {
    // The correlated flag wins because our own `cancel` or the caller's bounded watchdog may
    // have driven the failure.
    if cancel.is_cancelled() {
        return SealError::Cancelled;
    }
    native_outcome(hr).unwrap_or_else(|| hr_error(api, hr, operation))
}

/// The store error a native cancellation, timeout or missing credential stands for.
fn native_outcome(hr: HRESULT) -> Option<SealError> {
    match hr {
        NTE_USER_CANCELLED | ERROR_CANCELLED_HRESULT => Some(SealError::Cancelled),
        ERROR_TIMEOUT_HRESULT => Some(SealError::TimedOut),
        NTE_NOT_FOUND => Some(SealError::KeyLost),
        _ => None,
    }
}

/// The name WebAuthn assigns to an error hr, or `unknown` when it assigns none.
fn hr_error_name(raw: &str) -> &str {
    if raw.is_empty() { "unknown" } else { raw }
}

fn hr_error(api: &WebAuthn, hr: HRESULT, operation: &str) -> SealError {
    let raw = api
        .get_error_name
        // SAFETY: the export returns null or a static NUL-terminated string.
        .map(|get_error_name| unsafe { from_wstr(get_error_name(hr)) })
        .unwrap_or_default();
    SealError::Platform(format!(
        "{operation} failed with {} (0x{hr:08X})",
        hr_error_name(&raw)
    ))
}

/// The time left before `deadline` as the native timeout, or `TimedOut` when none is left.
fn dispatch_timeout(deadline: Instant) -> Result<Duration, SealError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err(SealError::TimedOut)
    } else {
        Ok(left)
    }
}

fn timeout_ms(timeout: Duration) -> u32 {
    // The native field is a DWORD of milliseconds, so durations beyond about
    // 49 days clamp to the field maximum.
    timeout
        .as_millis()
        .min(u32::MAX as u128)
        .try_into()
        .unwrap_or(u32::MAX)
}

// URL-safe base64 without padding, per the WebAuthn challenge encoding.
const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url(input: &[u8]) -> String {
    // Every index is masked to 6 bits, so it is always in range.
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let n = (chunk[0] as u32) << 16
            | (chunk.get(1).copied().unwrap_or(0) as u32) << 8
            | chunk.get(2).copied().unwrap_or(0) as u32;
        out.push(BASE64URL[((n >> 18) & 63) as usize] as char);
        out.push(BASE64URL[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(BASE64URL[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(BASE64URL[(n & 63) as usize] as char);
        }
    }
    out
}

/// Non-null entries of a native array of `count` entry pointers.
///
/// # Safety
/// `entries` must hold `count` pointers, each null or valid for `'a`.
unsafe fn native_entries<'a, T: 'a>(
    count: u32,
    entries: *const *mut T,
) -> impl Iterator<Item = &'a T> {
    // SAFETY: the caller guarantees `count` readable pointers, each null or valid for `'a`.
    (0..count as usize).filter_map(move |index| unsafe { (*entries.add(index)).as_ref() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webauthn::{
        PWEBAUTHN_CREDENTIAL_DETAILS, WEBAUTHN_AUTHENTICATOR_DETAILS, WEBAUTHN_CREDENTIAL,
        WEBAUTHN_CREDENTIAL_DETAILS, WEBAUTHN_CREDENTIAL_DETAILS_LIST,
    };
    use std::time::Duration;

    /// The time a test gives a companion thread to signal before failing.
    const SIGNAL_BOUND: Duration = Duration::from_secs(3);

    /// An authenticator list whose entries and strings live in Rust buffers.
    struct FakeList {
        _names: Vec<Vec<u8>>,
        _ids: Vec<Vec<u8>>,
        entries: Vec<WEBAUTHN_AUTHENTICATOR_DETAILS>,
        pointers: Vec<*mut WEBAUTHN_AUTHENTICATOR_DETAILS>,
    }

    impl FakeList {
        /// Builds entries of `(name, id, locked)`, each name stored at an odd address.
        fn new(authenticators: &[(&str, &[u8], bool)]) -> Self {
            let mut names = Vec::new();
            let mut ids = Vec::new();
            let mut entries = Vec::new();
            for &(name, id, locked) in authenticators {
                let units: Vec<u16> = name.encode_utf16().chain([0]).collect();
                let mut bytes = vec![0u8; units.len() * 2 + 1];
                let start = 1 - bytes.as_ptr() as usize % 2;
                for (at, unit) in units.iter().enumerate() {
                    bytes[start + 2 * at..start + 2 * at + 2].copy_from_slice(&unit.to_ne_bytes());
                }
                let mut id = id.to_vec();
                entries.push(WEBAUTHN_AUTHENTICATOR_DETAILS {
                    dwVersion: 1,
                    cbAuthenticatorId: u32::try_from(id.len()).unwrap(),
                    pbAuthenticatorId: id.as_mut_ptr(),
                    pwszAuthenticatorName: bytes[start..].as_ptr().cast(),
                    bLocked: BOOL::from(locked),
                    ..Default::default()
                });
                names.push(bytes);
                ids.push(id);
            }
            let pointers = entries.iter_mut().map(std::ptr::from_mut).collect();
            Self {
                _names: names,
                _ids: ids,
                entries,
                pointers,
            }
        }

        fn select(&mut self) -> Result<Vec<u8>, SealError> {
            let list = WEBAUTHN_AUTHENTICATOR_DETAILS_LIST {
                cAuthenticatorDetails: u32::try_from(self.entries.len()).unwrap(),
                ppAuthenticatorDetails: self.pointers.as_mut_ptr(),
            };
            // SAFETY: every entry, identifier and name is owned by `self` for the call.
            unsafe { hello_authenticator_id(&list) }
        }
    }

    #[test]
    fn windows_hello_is_selected_by_name_at_any_alignment() {
        let mut list = FakeList::new(&[
            ("Security Key", &[1], false),
            ("windows hello", &[2, 3], false),
        ]);
        assert_eq!(list.select(), Ok(vec![2, 3]));
    }

    #[test]
    fn missing_or_identifierless_hello_is_unsupported() {
        for authenticators in [
            &[][..],
            &[("Security Key", &[1][..], false)][..],
            &[("Windows Hello", &[][..], false)][..],
        ] {
            assert!(matches!(
                FakeList::new(authenticators).select(),
                Err(SealError::Unsupported(_))
            ));
        }
    }

    #[test]
    fn a_locked_hello_authenticator_is_reported_locked() {
        let mut list = FakeList::new(&[("Windows Hello", &[4], true)]);
        assert_eq!(list.select(), Err(SealError::Locked));
    }

    #[test]
    fn several_distinct_hello_authenticators_conflict() {
        let mut duplicate = FakeList::new(&[
            ("Windows Hello", &[5], false),
            ("Windows Hello", &[5], false),
        ]);
        assert_eq!(duplicate.select(), Ok(vec![5]));
        let mut distinct = FakeList::new(&[
            ("Windows Hello", &[5], false),
            ("Windows Hello", &[6], false),
        ]);
        assert!(matches!(distinct.select(), Err(SealError::Conflict(_))));
    }

    #[test]
    fn cancellation_starts_uncancelled_and_clones_share_state() {
        let cancel = HelloCancellation::new();
        let clone = cancel.clone();
        assert!(!cancel.is_cancelled());
        assert!(!clone.is_cancelled());
        cancel.cancel();
        assert!(cancel.is_cancelled());
        assert!(clone.is_cancelled());
        clone.cancel();
        assert!(cancel.is_cancelled());
    }

    #[test]
    fn base64url_matches_rfc4648_url_alphabet_vectors() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(b"foob"), "Zm9vYg");
        assert_eq!(base64url(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64url(b"\xfb\xff\xbf"), "-_-_");
    }

    #[test]
    fn attestation_without_prf_is_unsupported() {
        let mut data = [0u8; 164];
        data[AUTHENTICATOR_DATA_FLAGS_OFFSET] = FLAG_USER_PRESENT | FLAG_USER_VERIFIED;
        assert!(matches!(
            test_attestation_with(ATTESTATION_VERSION_MIN, &data, 0),
            Err(SealError::Unsupported(_))
        ));
    }

    const CREDENTIAL_ID: [u8; 32] = [9; 32];
    const PRF: [u8; 32] = [13; 32];

    fn test_attestation_version(
        version: u32,
        data: &[u8],
    ) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), SealError> {
        test_attestation_with(version, data, 1)
    }

    /// Reads a valid local attestation that differs only in its version, data and PRF flag.
    fn test_attestation_with(
        version: u32,
        data: &[u8],
        prf_enabled: BOOL,
    ) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), SealError> {
        let mut prf = PRF;
        let mut salt = salt_over(&mut prf);
        let attestation = WEBAUTHN_CREDENTIAL_ATTESTATION {
            dwVersion: version,
            dwUsedTransport: TRANSPORT_INTERNAL,
            dwTransports: TRANSPORT_INTERNAL,
            bPrfEnabled: prf_enabled,
            cbCredentialId: u32::try_from(CREDENTIAL_ID.len()).unwrap(),
            pbCredentialId: CREDENTIAL_ID.as_ptr().cast_mut(),
            cbAuthenticatorData: u32::try_from(data.len()).unwrap(),
            pbAuthenticatorData: data.as_ptr().cast_mut(),
            pHmacSecret: &mut salt,
            ..Default::default()
        };
        // SAFETY: the fixture is a complete local attestation.
        unsafe { read_attestation(&attestation) }
    }

    fn test_attestation(data: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), SealError> {
        test_attestation_version(8, data)
    }

    fn test_assertion_version(version: u32, data: &[u8]) -> Result<Zeroizing<[u8; 32]>, SealError> {
        let mut prf = PRF;
        let mut salt = salt_over(&mut prf);
        let assertion = WEBAUTHN_ASSERTION {
            dwVersion: version,
            dwUsedTransport: TRANSPORT_INTERNAL,
            Credential: WEBAUTHN_CREDENTIAL {
                dwVersion: 1,
                cbId: u32::try_from(CREDENTIAL_ID.len()).unwrap(),
                pbId: CREDENTIAL_ID.as_ptr().cast_mut(),
                pwszCredentialType: std::ptr::null(),
            },
            cbAuthenticatorData: u32::try_from(data.len()).unwrap(),
            pbAuthenticatorData: data.as_ptr().cast_mut(),
            pHmacSecret: &mut salt,
            ..Default::default()
        };
        // SAFETY: the fixture is a complete local assertion.
        unsafe { read_assertion(&assertion, &CREDENTIAL_ID) }
    }

    fn test_assertion(data: &[u8]) -> Result<Zeroizing<[u8; 32]>, SealError> {
        test_assertion_version(6, data)
    }

    #[test]
    fn ceremonies_reject_versions_below_the_mirrored_layouts() {
        let mut data = [0u8; 164];
        data[AUTHENTICATOR_DATA_FLAGS_OFFSET] = FLAG_USER_PRESENT | FLAG_USER_VERIFIED;
        assert!(matches!(
            test_attestation_version(7, &data),
            Err(SealError::Corrupt(_))
        ));
        assert!(matches!(
            test_assertion_version(5, &data),
            Err(SealError::Corrupt(_))
        ));
    }

    #[test]
    fn ceremonies_accept_extended_authenticator_data() {
        let mut data = [0u8; 164];
        data[AUTHENTICATOR_DATA_FLAGS_OFFSET] = FLAG_USER_PRESENT | FLAG_USER_VERIFIED;
        let (credential_id, key) = test_attestation(&data).unwrap();
        assert_eq!(
            (credential_id.as_slice(), *key),
            (CREDENTIAL_ID.as_slice(), PRF)
        );
        assert_eq!(*test_assertion(&data[..75]).unwrap(), PRF);
    }

    #[test]
    fn authenticator_data_rejects_null_and_short_headers() {
        let mut short = [0u8; 36];
        short[AUTHENTICATOR_DATA_FLAGS_OFFSET] = FLAG_USER_PRESENT | FLAG_USER_VERIFIED;
        for len in [0, short.len() as u32] {
            assert!(matches!(
                check_authenticator_data(short.as_ptr(), len),
                Err(SealError::Corrupt(_))
            ));
        }
        for len in [AUTHENTICATOR_DATA_HEADER_LEN, 164] {
            assert!(matches!(
                check_authenticator_data(std::ptr::null(), len),
                Err(SealError::Corrupt(_))
            ));
        }
        let mut minimum = [0u8; AUTHENTICATOR_DATA_HEADER_LEN as usize];
        minimum[AUTHENTICATOR_DATA_FLAGS_OFFSET] = FLAG_USER_PRESENT | FLAG_USER_VERIFIED;
        assert!(check_authenticator_data(minimum.as_ptr(), AUTHENTICATOR_DATA_HEADER_LEN).is_ok());
    }

    #[test]
    fn attestation_and_assertion_require_both_user_flags() {
        let mut data = [0u8; 164];
        for (flags, missing) in [
            (FLAG_USER_PRESENT, "verification"),
            (FLAG_USER_VERIFIED, "presence"),
            (0, "presence"),
        ] {
            data[AUTHENTICATOR_DATA_FLAGS_OFFSET] = flags;
            for result in [
                test_attestation(&data).map(|_| ()),
                test_assertion(&data).map(|_| ()),
            ] {
                assert!(matches!(
                    result,
                    Err(SealError::Corrupt(reason)) if reason.contains(missing)
                ));
            }
        }
    }

    #[test]
    fn platform_credential_identifiers_can_exceed_64_bytes() {
        let identifier = [42u8; 128];
        assert_eq!(
            read_credential_id(
                identifier.as_ptr(),
                u32::try_from(identifier.len()).unwrap()
            )
            .unwrap(),
            identifier
        );
    }

    #[test]
    fn timeout_ms_clamps_to_the_dword_maximum() {
        assert_eq!(timeout_ms(Duration::from_millis(180_000)), 180_000);
        assert_eq!(
            timeout_ms(Duration::from_secs(u64::from(u32::MAX) + 1)),
            u32::MAX
        );
    }

    #[test]
    fn a_ceremony_gets_the_time_left_and_none_after_its_deadline() {
        let later = Instant::now() + Duration::from_secs(60);
        let left = dispatch_timeout(later).unwrap();
        assert!(left > Duration::from_secs(59) && left <= Duration::from_secs(60));
        assert_eq!(dispatch_timeout(Instant::now()), Err(SealError::TimedOut));
    }

    #[test]
    fn the_credential_parameter_binds_public_key_es256() {
        let param = es256_credential_parameter();
        assert_eq!(param.dwVersion, 1);
        // SAFETY: `es256_credential_parameter` stores the static NUL-terminated
        // `WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY`, valid for the whole program.
        let credential_type = unsafe { from_wstr(param.pwszCredentialType) };
        assert_eq!(credential_type, "public-key");
        assert_eq!(param.lAlg, -7);
    }

    #[test]
    fn the_authenticator_id_length_is_its_byte_count() {
        assert_eq!(authenticator_id_len(&[]), 0);
        assert_eq!(authenticator_id_len(&[1, 2, 3, 4, 5]), 5);
    }

    #[test]
    fn the_make_credential_options_bind_every_native_field() {
        let mut guid = guid(41);
        let mut native = [0u8; 32];
        let mut salt = salt_over(&mut native);
        let authenticator_id = [7u8; 5];
        let options = make_credential_options(
            Duration::from_millis(2500),
            &mut guid,
            &mut salt,
            &authenticator_id,
        );
        assert_eq!(
            options.dwVersion,
            WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION.cast_unsigned()
        );
        assert_eq!(options.dwTimeoutMilliseconds, 2500);
        assert_eq!(options.dwAuthenticatorAttachment, ATTACHMENT_PLATFORM);
        assert_eq!(
            options.dwUserVerificationRequirement,
            UV_REQUIREMENT_REQUIRED
        );
        assert_eq!(
            options.dwAttestationConveyancePreference,
            ATTESTATION_CONVEYANCE_NONE
        );
        assert_eq!(options.dwFlags, RAW_SALT_FLAG);
        assert_eq!(options.pCancellationId, &mut guid as *mut _);
        assert_eq!(options.bEnablePrf, 1);
        assert_eq!(options.pPRFGlobalEval, &mut salt as *mut _);
        assert_eq!(options.cbAuthenticatorId, 5);
        assert_eq!(
            options.pbAuthenticatorId,
            authenticator_id.as_ptr().cast_mut()
        );
    }

    #[test]
    fn the_get_assertion_options_bind_every_native_field() {
        let mut guid = guid(42);
        let mut credential_ex = WEBAUTHN_CREDENTIAL_EX {
            dwVersion: 1,
            cbId: u32::try_from(CREDENTIAL_ID.len()).unwrap(),
            pbId: CREDENTIAL_ID.as_ptr().cast_mut(),
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            dwTransports: 0,
        };
        let mut allow_array = [std::ptr::from_mut(&mut credential_ex)];
        let mut allow_list = WEBAUTHN_CREDENTIAL_LIST {
            cCredentials: 1,
            ppCredentials: allow_array.as_mut_ptr(),
        };
        let mut native = [0u8; 32];
        let mut first = salt_over(&mut native);
        let mut salt_values = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
            pGlobalHmacSalt: &mut first,
            cCredWithHmacSecretSaltList: 0,
            pCredWithHmacSecretSaltList: std::ptr::null_mut(),
        };
        let authenticator_id = [7u8; 5];
        let options = get_assertion_options(
            Duration::from_millis(1500),
            &mut guid,
            &mut allow_list,
            &mut salt_values,
            &authenticator_id,
        );
        assert_eq!(
            options.dwVersion,
            WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION.cast_unsigned()
        );
        assert_eq!(options.dwTimeoutMilliseconds, 1500);
        assert_eq!(options.dwAuthenticatorAttachment, ATTACHMENT_PLATFORM);
        assert_eq!(
            options.dwUserVerificationRequirement,
            UV_REQUIREMENT_REQUIRED
        );
        assert_eq!(options.dwFlags, RAW_SALT_FLAG);
        assert_eq!(options.pCancellationId, &mut guid as *mut _);
        assert_eq!(options.pAllowCredentialList, &mut allow_list as *mut _);
        assert_eq!(options.pHmacSecretSaltValues, &mut salt_values as *mut _);
        assert_eq!(options.cbAuthenticatorId, 5);
        assert_eq!(
            options.pbAuthenticatorId,
            authenticator_id.as_ptr().cast_mut()
        );
    }

    unsafe extern "system" fn free_attestation_fixture(_: *const WEBAUTHN_CREDENTIAL_ATTESTATION) {}

    unsafe extern "system" fn free_assertion_fixture(_: *const WEBAUTHN_ASSERTION) {}

    /// A valid local attestation whose data and salt buffers the test keeps alive.
    fn attestation_fixture(
        data: &mut [u8; 164],
        salt: &mut WEBAUTHN_HMAC_SECRET_SALT,
    ) -> WEBAUTHN_CREDENTIAL_ATTESTATION {
        data[AUTHENTICATOR_DATA_FLAGS_OFFSET] = FLAG_USER_PRESENT | FLAG_USER_VERIFIED;
        WEBAUTHN_CREDENTIAL_ATTESTATION {
            dwVersion: ATTESTATION_VERSION_MIN,
            dwUsedTransport: TRANSPORT_INTERNAL,
            dwTransports: TRANSPORT_INTERNAL,
            bPrfEnabled: 1,
            cbCredentialId: u32::try_from(CREDENTIAL_ID.len()).unwrap(),
            pbCredentialId: CREDENTIAL_ID.as_ptr().cast_mut(),
            cbAuthenticatorData: u32::try_from(data.len()).unwrap(),
            pbAuthenticatorData: data.as_ptr().cast_mut(),
            pHmacSecret: salt,
            ..Default::default()
        }
    }

    /// A valid local assertion whose data and salt buffers the test keeps alive.
    fn assertion_fixture(
        data: &mut [u8; 164],
        salt: &mut WEBAUTHN_HMAC_SECRET_SALT,
    ) -> WEBAUTHN_ASSERTION {
        data[AUTHENTICATOR_DATA_FLAGS_OFFSET] = FLAG_USER_PRESENT | FLAG_USER_VERIFIED;
        WEBAUTHN_ASSERTION {
            dwVersion: ASSERTION_VERSION_MIN,
            dwUsedTransport: TRANSPORT_INTERNAL,
            Credential: WEBAUTHN_CREDENTIAL {
                dwVersion: 1,
                cbId: u32::try_from(CREDENTIAL_ID.len()).unwrap(),
                pbId: CREDENTIAL_ID.as_ptr().cast_mut(),
                pwszCredentialType: std::ptr::null(),
            },
            cbAuthenticatorData: u32::try_from(data.len()).unwrap(),
            pbAuthenticatorData: data.as_ptr().cast_mut(),
            pHmacSecret: salt,
            ..Default::default()
        }
    }

    #[test]
    fn a_success_attestation_is_read_and_a_failure_is_reported() {
        let mut native = PRF;
        let mut salt = salt_over(&mut native);
        let mut data = [0u8; 164];
        let mut attestation = attestation_fixture(&mut data, &mut salt);
        let (credential_id, key) = attestation_outcome(
            S_OK,
            &mut attestation as *mut _,
            free_attestation_fixture,
            |_hr| panic!("a successful attestation was reported as a failure"),
        )
        .unwrap();
        assert_eq!(credential_id, CREDENTIAL_ID);
        assert_eq!(*key, PRF);
        assert!(matches!(
            attestation_outcome(
                ERROR_CANCELLED_HRESULT,
                std::ptr::null_mut(),
                free_attestation_fixture,
                |_hr| SealError::Cancelled
            ),
            Err(SealError::Cancelled)
        ));
        assert!(matches!(
            attestation_outcome(
                S_OK,
                std::ptr::null_mut(),
                free_attestation_fixture,
                |_hr| SealError::Cancelled
            ),
            Err(SealError::Corrupt(_))
        ));
    }

    #[test]
    fn a_success_assertion_is_read_and_a_failure_is_reported() {
        let mut native = PRF;
        let mut salt = salt_over(&mut native);
        let mut data = [0u8; 164];
        let mut assertion = assertion_fixture(&mut data, &mut salt);
        let key = assertion_outcome(
            S_OK,
            &mut assertion as *mut _,
            &CREDENTIAL_ID,
            free_assertion_fixture,
            |_hr| panic!("a successful assertion was reported as a failure"),
        )
        .unwrap();
        assert_eq!(*key, PRF);
        assert!(matches!(
            assertion_outcome(
                ERROR_CANCELLED_HRESULT,
                std::ptr::null_mut(),
                &CREDENTIAL_ID,
                free_assertion_fixture,
                |_hr| SealError::Cancelled
            ),
            Err(SealError::Cancelled)
        ));
        assert!(matches!(
            assertion_outcome(
                S_OK,
                std::ptr::null_mut(),
                &CREDENTIAL_ID,
                free_assertion_fixture,
                |_hr| SealError::Cancelled
            ),
            Err(SealError::Corrupt(_))
        ));
    }

    #[test]
    fn the_cancellation_id_is_returned_only_on_success() {
        let id = guid(99);
        assert_eq!(
            cancellation_id_outcome(S_OK, &id, |_hr| SealError::Cancelled)
                .unwrap()
                .data1,
            99
        );
        assert!(matches!(
            cancellation_id_outcome(ERROR_TIMEOUT_HRESULT, &id, |_hr| SealError::TimedOut),
            Err(SealError::TimedOut)
        ));
    }

    #[cfg(windows)]
    struct TestWindow {
        hwnd: usize,
    }

    #[cfg(windows)]
    impl HelloWindow for TestWindow {
        fn hwnd(&self) -> HWND {
            self.hwnd as HWND
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_ceremony_with_a_dead_owner_fails_before_any_prompt() {
        let owner = Arc::new(TestWindow { hwnd: 0 });
        let cancel = HelloCancellation::new();
        let error = match Ceremony::begin(owner, &cancel) {
            Ok(_) => panic!("a dead owner prepared a ceremony"),
            Err(error) => error,
        };
        assert!(matches!(error, SealError::MissingOwner));
        assert!(!cancel.is_cancelled());
    }

    #[cfg(windows)]
    #[test]
    fn a_pre_cancelled_ceremony_fails_before_any_prompt() {
        let hwnd = create_hidden_window();
        let owner = Arc::new(TestWindow {
            hwnd: hwnd as usize,
        });
        let cancel = HelloCancellation::new();
        cancel.cancel();
        let error = match Ceremony::begin(owner, &cancel) {
            Ok(_) => panic!("a pre-cancelled request prepared a ceremony"),
            Err(error) => error,
        };
        assert!(matches!(error, SealError::Cancelled));
        destroy_window(hwnd);
    }

    /// A ceremony that skips the live checks and goes straight to the native calls.
    #[cfg(windows)]
    fn test_ceremony() -> Result<Ceremony, SealError> {
        Ok(Ceremony {
            api: load()?,
            _owner: Arc::new(TestWindow { hwnd: 0 }),
            hwnd: std::ptr::null_mut(),
            guid: guid(3),
            authenticator_id: vec![1],
        })
    }

    /// A cancelled request must refuse both native calls before the DLL sees them, so no
    /// prompt can start and no hardware is needed for the refusal.
    #[cfg(windows)]
    #[test]
    fn a_pre_cancelled_enrollment_and_assertion_fail_before_any_prompt() {
        let cancel = HelloCancellation::new();
        cancel.cancel();
        let deadline = Instant::now() + Duration::from_millis(500);
        let salt = [0u8; 32];
        let user_id = [0u8; 32];
        let enrolled = match test_ceremony() {
            Err(error) => {
                eprintln!("skipped on this host. {error}");
                return;
            }
            Ok(ceremony) => enroll(ceremony, TEST_RP_ID, &user_id, &salt, &cancel, deadline),
        };
        assert!(matches!(enrolled, Err(SealError::Cancelled)));
        let asserted = match test_ceremony() {
            Err(error) => {
                eprintln!("skipped on this host. {error}");
                return;
            }
            Ok(ceremony) => assert_prf(
                ceremony,
                TEST_RP_ID,
                &CREDENTIAL_ID,
                &salt,
                &cancel,
                deadline,
            ),
        };
        assert!(matches!(asserted, Err(SealError::Cancelled)));
    }

    #[cfg(windows)]
    fn create_hidden_window() -> HWND {
        use windows_sys::Win32::UI::WindowsAndMessaging::CreateWindowExW;
        let class: Vec<u16> = "STATIC\0".encode_utf16().collect();
        // SAFETY: the class name is a terminated built-in Win32 window class.
        let hwnd = unsafe {
            CreateWindowExW(
                0,
                class.as_ptr(),
                std::ptr::null(),
                0,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        assert!(
            !hwnd.is_null(),
            "static window creation failed on the test machine"
        );
        hwnd
    }

    #[cfg(windows)]
    fn destroy_window(hwnd: HWND) {
        use windows_sys::Win32::UI::WindowsAndMessaging::DestroyWindow;
        // SAFETY: `hwnd` is a live window created by the test.
        unsafe { DestroyWindow(hwnd) };
    }

    #[test]
    fn a_prf_secret_of_the_wrong_length_is_refused() {
        let mut native = [0u8; 32];
        let salt = WEBAUTHN_HMAC_SECRET_SALT {
            cbFirst: 16,
            pbFirst: native.as_mut_ptr(),
            cbSecond: 0,
            pbSecond: std::ptr::null_mut(),
        };
        assert!(matches!(
            read_prf_key(&salt, "test"),
            Err(SealError::Unsupported(_))
        ));
    }

    /// One platform credential entry spec.
    ///
    /// A `None` `credential_id` gives a zero-length id pointer, and a `None` `user_id` gives a
    /// null user information pointer.
    #[derive(Clone, Copy)]
    struct FakeEntry<'a> {
        credential_id: Option<&'a [u8]>,
        rp_id: &'a str,
        user_id: Option<&'a [u8]>,
    }

    /// A platform credential list whose entries and strings live in Rust buffers.
    struct FakeCredentials {
        _ids: Vec<Vec<u8>>,
        _user_ids: Vec<Vec<u8>>,
        _names: Vec<Vec<u8>>,
        _rp_infos: Vec<WEBAUTHN_RP_ENTITY_INFORMATION>,
        _user_infos: Vec<WEBAUTHN_USER_ENTITY_INFORMATION>,
        entries: Vec<WEBAUTHN_CREDENTIAL_DETAILS>,
        pointers: Vec<PWEBAUTHN_CREDENTIAL_DETAILS>,
    }

    impl FakeCredentials {
        /// Builds one entry per spec, each rp id stored at an odd address.
        fn new(credentials: &[FakeEntry]) -> Self {
            let mut ids = Vec::new();
            let mut user_ids = Vec::new();
            let mut names = Vec::new();
            let mut rp_infos = Vec::new();
            let mut user_infos = Vec::new();
            for entry in credentials {
                let id = entry.credential_id.unwrap_or_default().to_vec();
                let mut user = entry.user_id.unwrap_or_default().to_vec();
                let units: Vec<u16> = entry.rp_id.encode_utf16().chain([0]).collect();
                let mut bytes = vec![0u8; units.len() * 2 + 1];
                let start = 1 - bytes.as_ptr() as usize % 2;
                for (at, unit) in units.iter().enumerate() {
                    bytes[start + 2 * at..start + 2 * at + 2].copy_from_slice(&unit.to_ne_bytes());
                }
                rp_infos.push(WEBAUTHN_RP_ENTITY_INFORMATION {
                    dwVersion: 1,
                    pwszId: bytes[start..].as_ptr().cast(),
                    ..Default::default()
                });
                user_infos.push(WEBAUTHN_USER_ENTITY_INFORMATION {
                    dwVersion: 1,
                    cbId: u32::try_from(user.len()).unwrap(),
                    pbId: user.as_mut_ptr(),
                    ..Default::default()
                });
                ids.push(id);
                user_ids.push(user);
                names.push(bytes);
            }
            let mut entries: Vec<WEBAUTHN_CREDENTIAL_DETAILS> = (0..credentials.len())
                .map(|at| {
                    let user_pointer = if credentials[at].user_id.is_some() {
                        std::ptr::from_ref(&user_infos[at]) as *mut _
                    } else {
                        std::ptr::null_mut()
                    };
                    WEBAUTHN_CREDENTIAL_DETAILS {
                        dwVersion: 1,
                        cbCredentialID: u32::try_from(ids[at].len()).unwrap(),
                        pbCredentialID: ids[at].as_ptr().cast_mut(),
                        pRpInformation: std::ptr::from_ref(&rp_infos[at]) as *mut _,
                        pUserInformation: user_pointer,
                        ..Default::default()
                    }
                })
                .collect();
            let pointers = entries.iter_mut().map(std::ptr::from_mut).collect();
            Self {
                _ids: ids,
                _user_ids: user_ids,
                _names: names,
                _rp_infos: rp_infos,
                _user_infos: user_infos,
                entries,
                pointers,
            }
        }

        fn entries(&mut self) -> Vec<ListedCredential> {
            let mut list = WEBAUTHN_CREDENTIAL_DETAILS_LIST {
                cCredentialDetails: u32::try_from(self.entries.len()).unwrap(),
                ppCredentialDetails: self.pointers.as_mut_ptr(),
            };
            // SAFETY: every entry, identifier and string is owned by `self` for the call.
            unsafe { platform_credential_entries(&mut list as *mut _) }
        }
    }

    #[test]
    fn a_platform_list_is_parsed_into_owned_records() {
        let user = [7u8; 32];
        let mut list = FakeCredentials::new(&[
            FakeEntry {
                credential_id: Some(&[1, 2]),
                rp_id: "rp.example",
                user_id: Some(&user),
            },
            FakeEntry {
                credential_id: None,
                rp_id: "rp.example",
                user_id: None,
            },
            FakeEntry {
                credential_id: Some(&[3]),
                rp_id: "other.example",
                user_id: Some(&[]),
            },
            FakeEntry {
                credential_id: Some(&[4, 5]),
                rp_id: "rp.example",
                user_id: Some(&[9, 9]),
            },
        ]);
        assert_eq!(
            list.entries(),
            vec![
                ListedCredential {
                    credential_id: vec![1, 2],
                    rp_id: "rp.example".into(),
                    user_id: Some(user.to_vec()),
                },
                ListedCredential {
                    credential_id: Vec::new(),
                    rp_id: "rp.example".into(),
                    user_id: None,
                },
                ListedCredential {
                    credential_id: vec![3],
                    rp_id: "other.example".into(),
                    user_id: None,
                },
                ListedCredential {
                    credential_id: vec![4, 5],
                    rp_id: "rp.example".into(),
                    user_id: Some(vec![9, 9]),
                },
            ]
        );
    }

    #[test]
    fn a_null_entry_pointer_is_skipped_when_parsing_a_list() {
        let mut id = vec![4u8];
        let mut entry = WEBAUTHN_CREDENTIAL_DETAILS {
            dwVersion: 1,
            cbCredentialID: 1,
            pbCredentialID: id.as_mut_ptr(),
            ..Default::default()
        };
        let mut pointers: [*mut WEBAUTHN_CREDENTIAL_DETAILS; 2] =
            [std::ptr::null_mut(), std::ptr::from_mut(&mut entry)];
        let mut list = WEBAUTHN_CREDENTIAL_DETAILS_LIST {
            cCredentialDetails: 2,
            ppCredentialDetails: pointers.as_mut_ptr(),
        };
        // SAFETY: the table holds two readable pointers, one null and one owned by this stack.
        let entries = unsafe { platform_credential_entries(&mut list as *mut _) };
        assert_eq!(
            entries,
            vec![ListedCredential {
                credential_id: vec![4],
                rp_id: String::new(),
                user_id: None,
            }]
        );
    }

    #[test]
    fn owned_ids_keep_only_exact_rp_and_user_entries() {
        let user = [7u8; 32];
        let entries = vec![
            ListedCredential {
                credential_id: vec![1],
                rp_id: "exact.example".into(),
                user_id: Some(user.to_vec()),
            },
            ListedCredential {
                credential_id: vec![2],
                rp_id: "other.example".into(),
                user_id: Some(user.to_vec()),
            },
            ListedCredential {
                credential_id: Vec::new(),
                rp_id: "exact.example".into(),
                user_id: Some(user.to_vec()),
            },
            ListedCredential {
                credential_id: vec![3],
                rp_id: "exact.example".into(),
                user_id: None,
            },
            ListedCredential {
                credential_id: vec![4],
                rp_id: "other.example".into(),
                user_id: None,
            },
        ];
        assert_eq!(
            owned_ids(entries, "exact.example", Some(&user)),
            vec![vec![1]]
        );
    }

    #[test]
    fn owned_ids_without_a_user_keep_every_exact_rp_entry() {
        let entries = vec![
            ListedCredential {
                credential_id: vec![8],
                rp_id: "exact.example".into(),
                user_id: None,
            },
            ListedCredential {
                credential_id: Vec::new(),
                rp_id: "exact.example".into(),
                user_id: None,
            },
            ListedCredential {
                credential_id: vec![9],
                rp_id: "other.example".into(),
                user_id: None,
            },
        ];
        assert_eq!(owned_ids(entries, "exact.example", None), vec![vec![8]]);
    }

    const E_INVALIDARG: HRESULT = 0x8007_0057u32.cast_signed();

    #[test]
    fn enumeration_accepts_success_and_not_found_only() {
        assert_eq!(check_list_hr(S_OK), Ok(()));
        assert_eq!(check_list_hr(NTE_NOT_FOUND), Ok(()));
        assert_eq!(check_list_hr(E_INVALIDARG), Err(E_INVALIDARG));
    }

    #[test]
    fn native_id_bytes_copies_present_ids_and_skips_absent_ones() {
        let bytes = vec![10u8, 20, 30];
        // SAFETY: `bytes` stays valid for its full length through every call below.
        let copy = unsafe { native_id_bytes(3, bytes.as_ptr().cast_mut()) };
        assert_eq!(copy, bytes);
        // SAFETY: a zero-length copy never dereferences the pointer.
        let zero = unsafe { native_id_bytes(0, bytes.as_ptr().cast_mut()) };
        assert_eq!(zero, Vec::<u8>::new());
        // SAFETY: the null check rejects the pointer before any read happens.
        let missing = unsafe { native_id_bytes(3, std::ptr::null_mut()) };
        assert_eq!(missing, Vec::<u8>::new());
    }

    #[test]
    fn empty_credential_id_is_rejected() {
        let buffer = [0u8; 1];
        assert!(matches!(
            read_credential_id(buffer.as_ptr(), 0),
            Err(SealError::Corrupt(_))
        ));
    }

    #[test]
    fn null_credential_id_pointer_is_rejected() {
        assert!(matches!(
            read_credential_id(std::ptr::null::<u8>(), 1),
            Err(SealError::Corrupt(_))
        ));
    }

    #[test]
    fn credential_id_at_the_metadata_boundary_is_accepted() {
        let buffer = [7u8; MAX_CREDENTIAL_ID];
        assert_eq!(
            read_credential_id(buffer.as_ptr(), u32::try_from(MAX_CREDENTIAL_ID).unwrap()).unwrap(),
            buffer
        );
    }

    #[test]
    fn credential_id_beyond_the_metadata_boundary_is_rejected() {
        let buffer = [0u8; MAX_CREDENTIAL_ID + 1];
        assert!(matches!(
            read_credential_id(
                buffer.as_ptr(),
                u32::try_from(MAX_CREDENTIAL_ID + 1).unwrap()
            ),
            Err(SealError::Corrupt(_))
        ));
    }

    #[test]
    fn max_credential_id_keeps_seventy_two_bytes_for_metadata() {
        assert_eq!(
            MAX_CREDENTIAL_ID + 72,
            CRED_MAX_CREDENTIAL_BLOB_SIZE as usize
        );
    }

    #[test]
    fn prf_salt_carries_the_ctap_one_secret_length() {
        let salt = prf_salt(&PRF);
        assert_eq!(salt.cbFirst, HMAC_SECRET_LENGTH);
        // SAFETY: `pbFirst` points into the 32-byte `PRF` array and `cbFirst` was
        // verified above as its length, so the read is in bounds and non-null.
        let bytes = unsafe { std::slice::from_raw_parts(salt.pbFirst, salt.cbFirst as usize) };
        assert_eq!(bytes, PRF.as_slice());
    }

    #[cfg(windows)]
    const TEST_RP_ID: &str = "windows-native-keyring-store-test.invalid";

    #[cfg(windows)]
    #[test]
    fn recover_created_for_unknown_rp_and_user_is_none() {
        let mut user = [0u8; 32];
        fill(&mut user).expect("test randomness available");
        let found = match recover_created(TEST_RP_ID, &user) {
            Err(SealError::Unsupported(reason)) => {
                eprintln!("skipped on this host. {reason}");
                return;
            }
            result => result.unwrap(),
        };
        assert!(found.is_none());
    }

    fn guid(tag: u32) -> GUID {
        GUID {
            data1: tag,
            ..GUID::default()
        }
    }

    /// The tags of every native operation `cancel` would abort, in ascending order.
    fn aborted(cancel: &HelloCancellation) -> Vec<u32> {
        let mut tags = Vec::new();
        cancel.abort_registered(|guid| {
            tags.push(guid.data1);
            S_OK
        });
        tags.sort_unstable();
        tags
    }

    #[test]
    fn a_completing_ceremony_unregisters_only_itself() {
        let cancel = HelloCancellation::new();
        let (inside, entered) = std::sync::mpsc::channel();
        let (finish, finishing) = std::sync::mpsc::channel::<()>();
        let first = {
            let cancel = cancel.clone();
            std::thread::spawn(move || {
                run_registered(
                    &cancel,
                    guid(1),
                    |_| S_OK,
                    || {
                        inside.send(()).unwrap();
                        finishing.recv_timeout(SIGNAL_BOUND).unwrap();
                        S_OK
                    },
                )
            })
        };
        entered.recv_timeout(SIGNAL_BOUND).unwrap();
        assert_eq!(
            run_registered(&cancel, guid(2), |_| S_OK, || S_OK),
            Ok(S_OK)
        );
        assert_eq!(aborted(&cancel), [1]);
        finish.send(()).unwrap();
        assert_eq!(first.join().unwrap(), Ok(S_OK));
        assert!(aborted(&cancel).is_empty());
    }

    #[test]
    fn cancel_reaches_every_registered_ceremony() {
        let cancel = HelloCancellation::new();
        let first = cancel.register(guid(1));
        let second = cancel.register(guid(2));
        assert_eq!(aborted(&cancel), [1, 2]);
        cancel.unregister(second);
        assert_eq!(aborted(&cancel), [1]);
        cancel.unregister(first);
        assert!(aborted(&cancel).is_empty());
    }

    #[test]
    fn a_ceremony_starting_after_cancel_refuses_and_stays_unregistered() {
        let cancel = HelloCancellation::new();
        cancel.mark_cancelled();
        let result = run_registered(
            &cancel,
            guid(3),
            |_| S_OK,
            || panic!("a cancelled ceremony ran"),
        );
        assert_eq!(result, Err(SealError::Cancelled));
        assert!(aborted(&cancel).is_empty());
    }

    #[test]
    fn a_cancel_lost_before_the_native_call_starts_is_resent_until_it_lands() {
        let cancel = HelloCancellation::with_abort_interval(Duration::from_millis(5));
        let started = AtomicBool::new(false);
        let (landed, landing) = mpsc::channel();
        // Like Windows, the fake call ignores aborts sent before it started.
        let abort = |guid: &GUID| {
            if started.load(Ordering::Acquire) {
                let _ = landed.send(guid.data1);
            }
            S_OK
        };
        let hr = run_registered(&cancel, guid(7), abort, || {
            cancel.mark_cancelled();
            cancel.abort_registered(|_| S_OK);
            started.store(true, Ordering::Release);
            match landing.recv_timeout(SIGNAL_BOUND) {
                Ok(7) => NTE_USER_CANCELLED,
                _ => ERROR_TIMEOUT_HRESULT,
            }
        });
        assert_eq!(hr, Ok(NTE_USER_CANCELLED));
        assert!(aborted(&cancel).is_empty());
    }

    #[test]
    fn a_running_call_is_never_aborted_without_a_cancel() {
        let cancel = HelloCancellation::with_abort_interval(Duration::from_millis(1));
        let (aborts, aborting) = mpsc::channel();
        let hr = run_registered(
            &cancel,
            guid(8),
            |guid| {
                let _ = aborts.send(guid.data1);
                S_OK
            },
            || {
                // Fifty ticks pass while the call runs.
                let aborted = aborting.recv_timeout(Duration::from_millis(50)).is_ok();
                if aborted { NTE_USER_CANCELLED } else { S_OK }
            },
        );
        assert_eq!(hr, Ok(S_OK));
    }

    #[test]
    fn an_abort_interval_below_one_millisecond_is_raised_to_one() {
        let cancel = HelloCancellation::with_abort_interval(Duration::ZERO);
        assert_eq!(cancel.inner.abort_interval, Duration::from_millis(1));
    }

    #[test]
    fn native_cancel_and_timeout_results_map_to_their_seal_errors() {
        // 0x80090036 is what Windows returned for an aborted prompt on the laptop.
        let cases = [
            (0x8009_0036u32, SealError::Cancelled),
            (0x8007_04C7, SealError::Cancelled),
            (0x8007_05B4, SealError::TimedOut),
            (0x8009_0011, SealError::KeyLost),
        ];
        for (hr, expected) in cases {
            assert_eq!(
                native_outcome(hr.cast_signed()),
                Some(expected),
                "{hr:#010X}"
            );
        }
    }

    fn salt_over(native: &mut [u8]) -> WEBAUTHN_HMAC_SECRET_SALT {
        WEBAUTHN_HMAC_SECRET_SALT {
            cbFirst: u32::try_from(native.len()).unwrap(),
            pbFirst: native.as_mut_ptr(),
            cbSecond: 0,
            pbSecond: std::ptr::null_mut(),
        }
    }

    #[test]
    fn the_native_prf_output_is_wiped_once_read() {
        let mut native = [7u8; 32];
        let salt = salt_over(&mut native);
        let key = read_prf_key(&salt, "test").unwrap();
        assert_eq!(*key, [7; 32]);
        assert_eq!(native, [0; 32]);
    }

    #[test]
    fn a_native_prf_output_of_the_wrong_length_is_wiped_and_refused() {
        let mut native = [7u8; 16];
        let salt = salt_over(&mut native);
        assert!(matches!(
            read_prf_key(&salt, "test"),
            Err(SealError::Unsupported(_))
        ));
        assert_eq!(native, [0; 16]);
    }

    #[test]
    fn api_below_version_nine_is_unsupported() {
        let required = WEBAUTHN_API_VERSION_9.cast_unsigned();
        let old = required - 1;
        assert_eq!(
            api_version_error(old, required),
            Some(SealError::Unsupported(format!(
                "webauthn API version {old} is below the required {required}"
            )))
        );
        assert_eq!(api_version_error(required, required), None);
        assert_eq!(api_version_error(required + 1, required), None);
    }

    #[test]
    fn platform_probe_maps_the_native_result() {
        assert_eq!(platform_probe(S_OK, 0), PlatformProbe::Missing);
        assert_eq!(platform_probe(S_OK, 1), PlatformProbe::Present);
        assert_eq!(
            platform_probe(NTE_NOT_FOUND, 0),
            PlatformProbe::Failed(NTE_NOT_FOUND)
        );
    }

    #[test]
    fn enumeration_step_maps_the_native_result() {
        let null: PWEBAUTHN_AUTHENTICATOR_DETAILS_LIST = std::ptr::null_mut();
        assert_eq!(
            enumeration_step(S_OK, null),
            EnumerationStep::Proceed { free: false }
        );
        assert_eq!(
            enumeration_step(NTE_NOT_FOUND, null),
            EnumerationStep::Proceed { free: false }
        );
        let error = 0x8004_0020u32.cast_signed();
        assert_eq!(
            enumeration_step(error, null),
            EnumerationStep::Failed(error)
        );
        let allocated =
            std::ptr::NonNull::<WEBAUTHN_AUTHENTICATOR_DETAILS_LIST>::dangling().as_ptr();
        assert_eq!(
            enumeration_step(S_OK, allocated),
            EnumerationStep::Proceed { free: true }
        );
    }

    #[test]
    fn an_empty_error_name_falls_back_to_unknown() {
        assert_eq!(hr_error_name(""), "unknown");
        assert_eq!(hr_error_name("NTE_NO_KEYSET_STORE"), "NTE_NO_KEYSET_STORE");
    }
}

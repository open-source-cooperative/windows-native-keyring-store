use byteorder::{ByteOrder, LittleEndian};
use std::collections::HashMap;
use std::iter::once;

use windows_sys::Win32::Foundation::{
    ERROR_BAD_USERNAME, ERROR_INVALID_FLAGS, ERROR_INVALID_PARAMETER, ERROR_NO_SUCH_LOGON_SESSION,
    ERROR_NOT_FOUND, FILETIME, GetLastError,
};
use windows_sys::Win32::Security::Credentials::{
    CRED_FLAGS, CRED_MAX_CREDENTIAL_BLOB_SIZE, CRED_MAX_GENERIC_TARGET_NAME_LENGTH,
    CRED_MAX_STRING_LENGTH, CRED_MAX_USERNAME_LENGTH, CRED_PERSIST, CRED_PERSIST_ENTERPRISE,
    CRED_PERSIST_LOCAL_MACHINE, CRED_PERSIST_SESSION, CRED_TYPE_GENERIC, CREDENTIAL_ATTRIBUTEW,
    CREDENTIALW, CredDeleteW, CredEnumerateW, CredFree, CredReadW, CredWriteW,
};
use zeroize::Zeroize;

use crate::cred::Cred;
use keyring_core::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum CredPersist {
    Session = CRED_PERSIST_SESSION,
    Local = CRED_PERSIST_LOCAL_MACHINE,
    Enterprise = CRED_PERSIST_ENTERPRISE,
}

impl std::fmt::Display for CredPersist {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CredPersist::Session => "Session",
            CredPersist::Local => "Local",
            CredPersist::Enterprise => "Enterprise",
        })
    }
}

impl std::str::FromStr for CredPersist {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "session" => Ok(CredPersist::Session),
            "local" => Ok(CredPersist::Local),
            "enterprise" => Ok(CredPersist::Enterprise),
            _ => Err(Error::Invalid(
                s.to_string(),
                "must be Session, Local, or Enterprise".to_string(),
            )),
        }
    }
}

pub fn validate_target(target: &str, user: &str) -> Result<()> {
    if user.len() > CRED_MAX_USERNAME_LENGTH as usize {
        return Err(Error::TooLong(
            String::from("user"),
            CRED_MAX_USERNAME_LENGTH,
        ));
    }
    if target.is_empty() {
        return Err(Error::Invalid(
            "target".to_string(),
            "cannot be empty".to_string(),
        ));
    }
    if target.len() > CRED_MAX_GENERIC_TARGET_NAME_LENGTH as usize {
        return Err(Error::TooLong(
            String::from("target"),
            CRED_MAX_GENERIC_TARGET_NAME_LENGTH,
        ));
    }
    Ok(())
}

pub fn validate_password(password: &str) -> Result<Vec<u8>> {
    let mut blob_u16 = to_wstr_no_null(password);
    let mut blob = vec![0; blob_u16.len() * 2];
    LittleEndian::write_u16_into(&blob_u16, &mut blob);
    blob_u16.zeroize();
    if blob.len() > CRED_MAX_CREDENTIAL_BLOB_SIZE as usize {
        blob.zeroize();
        Err(Error::TooLong(
            String::from("password encoded as UTF-16"),
            CRED_MAX_CREDENTIAL_BLOB_SIZE,
        ))
    } else {
        // caller will zeroize the blob
        Ok(blob)
    }
}

pub fn validate_secret(secret: &[u8]) -> Result<()> {
    if secret.len() > CRED_MAX_CREDENTIAL_BLOB_SIZE as usize {
        return Err(Error::TooLong(
            String::from("secret"),
            CRED_MAX_CREDENTIAL_BLOB_SIZE,
        ));
    }
    Ok(())
}

pub fn validate_attributes(username: &str, target_alias: &str, comment: &str) -> Result<()> {
    if username.len() > CRED_MAX_USERNAME_LENGTH as usize {
        return Err(Error::TooLong(
            String::from("user"),
            CRED_MAX_USERNAME_LENGTH,
        ));
    }
    if target_alias.len() > CRED_MAX_STRING_LENGTH as usize {
        return Err(Error::TooLong(
            String::from("target_alias"),
            CRED_MAX_STRING_LENGTH,
        ));
    }
    if comment.len() > CRED_MAX_STRING_LENGTH as usize {
        return Err(Error::TooLong(
            String::from("comment"),
            CRED_MAX_STRING_LENGTH,
        ));
    }
    Ok(())
}

/// Save or create a generic credential with pre-validated data
pub fn save_credential(
    target_name: &str,
    user: &str,
    target_alias: &str,
    comment: &str,
    secret: &[u8],
    persistence: &CredPersist,
) -> Result<()> {
    let mut username = to_wstr(user);
    let mut target_name = to_wstr(target_name);
    let mut target_alias = to_wstr(target_alias);
    let mut comment = to_wstr(comment);
    let mut blob = secret.to_vec();
    let blob_len = blob.len() as u32;
    let flags = CRED_FLAGS::default();
    let cred_type = CRED_TYPE_GENERIC;
    let persist = persistence.clone() as CRED_PERSIST;
    // Ignored by CredWriteW
    let last_written = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let attribute_count = 0;
    let attributes: *mut CREDENTIAL_ATTRIBUTEW = std::ptr::null_mut();
    let credential = CREDENTIALW {
        Flags: flags,
        Type: cred_type,
        TargetName: target_name.as_mut_ptr(),
        Comment: comment.as_mut_ptr(),
        LastWritten: last_written,
        CredentialBlobSize: blob_len,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: persist,
        AttributeCount: attribute_count,
        Attributes: attributes,
        TargetAlias: target_alias.as_mut_ptr(),
        UserName: username.as_mut_ptr(),
    };
    // Call windows API
    let result = match unsafe { CredWriteW(&credential, 0) } {
        0 => Err(decode_error()),
        _ => Ok(()),
    };
    // erase the copy of the secret
    blob.zeroize();
    result
}

/// Delete a generic credential
pub fn delete_credential(target_name: &str) -> Result<()> {
    let target_name = to_wstr(target_name);
    let cred_type = CRED_TYPE_GENERIC;
    match unsafe { CredDeleteW(target_name.as_ptr(), cred_type, 0) } {
        0 => Err(decode_error()),
        _ => Ok(()),
    }
}

/// Enumerate generic credentials
pub fn enumerate_credentials(
    pattern: Option<regex::Regex>,
    delimiters: &[String; 3],
) -> Result<Vec<Cred>> {
    let spec = format!(
        "^{}(.*){}(.*){}$",
        regex::escape(&delimiters[0]),
        regex::escape(&delimiters[1]),
        regex::escape(&delimiters[2])
    );
    let spec_pat = regex::Regex::new(&spec).unwrap();
    let mut count: u32 = 0;
    let mut creds = std::ptr::null_mut();
    if unsafe { CredEnumerateW(std::ptr::null(), 0, &mut count, &mut creds) } == 0 {
        return match decode_error() {
            Error::NoEntry => Ok(Vec::new()),
            err => Err(err),
        };
    }
    let slice = unsafe { std::slice::from_raw_parts(creds, count as usize) };
    let mut result = Vec::new();
    for cred in slice {
        let mut candidate = cred_from_credential(&mut unsafe { **cred });
        if let Some(pat) = &pattern {
            if !pat.is_match(&candidate.target_name) {
                continue;
            }
        }
        if let Some(captures) = spec_pat.captures(&candidate.target_name) {
            // user comes first, service second in the target name. Specifiers are the other way.
            candidate.specifiers = Some((captures[2].to_string(), captures[1].to_string()))
        }
        result.push(candidate)
    }
    unsafe { CredFree(creds as *mut std::ffi::c_void) };
    Ok(result)
}

/// Run a function over a generic credential to extract data from it.
pub fn extract_from_credential<F, T>(target_name: &str, f: F) -> Result<T>
where
    F: FnOnce(&CREDENTIALW) -> Result<T>,
{
    let mut p_credential = std::ptr::null_mut();
    // at this point, p_credential is just a pointer to nowhere.
    // The allocation happens in the `CredReadW` call below.
    let result = {
        let cred_type = CRED_TYPE_GENERIC;
        let target_name = to_wstr(target_name);
        unsafe { CredReadW(target_name.as_ptr(), cred_type, 0, &mut p_credential) }
    };
    match result {
        0 => {
            // `CredReadW` failed, so no allocation has been done, so no free needs to be done
            Err(decode_error())
        }
        _ => {
            // `CredReadW` succeeded, so p_credential points at an allocated credential. Apply
            // the passed extractor function to it.
            let result = f(unsafe { &*p_credential });
            // Finally, we erase the secret and free the allocated credential.
            erase_secret(unsafe { &mut *p_credential });
            unsafe { CredFree(p_credential as *mut _) };
            result
        }
    }
}

/// get a Cred from a native credential
pub fn cred_from_credential(credential: &mut CREDENTIALW) -> Cred {
    erase_secret(credential); // erase the secret, so it won't be leaked into the heap
    let persistence = match credential.Persist {
        CRED_PERSIST_SESSION => CredPersist::Session,
        CRED_PERSIST_LOCAL_MACHINE => CredPersist::Local,
        _ => CredPersist::Enterprise,
    };
    let target_name = unsafe { from_wstr(credential.TargetName) };
    Cred {
        target_name,
        specifiers: None,
        persistence,
    }
}

/// A password extractor for use with [extract_from_credential].
pub fn extract_password(credential: &CREDENTIALW) -> Result<String> {
    let mut blob = extract_secret(credential)?;
    // 3rd parties may write credential data with an odd number of bytes,
    // so we make sure that we don't try to decode those as utf16
    if blob.len() % 2 != 0 {
        return Err(Error::BadEncoding(blob));
    }
    // This should be a UTF-16 string, so convert it to
    // a UTF-16 vector and then try to decode it.
    let mut blob_u16 = vec![0; blob.len() / 2];
    LittleEndian::read_u16_into(&blob, &mut blob_u16);
    let result = match String::from_utf16(&blob_u16) {
        Err(_) => Err(Error::BadEncoding(blob)),
        Ok(s) => {
            // we aren't returning the blob, so clear it
            blob.zeroize();
            Ok(s)
        }
    };
    // we aren't returning the utf16 blob, so clear it
    blob_u16.zeroize();
    result
}

/// A secret extractor for use with [extract_from_credential].
pub fn extract_secret(credential: &CREDENTIALW) -> Result<Vec<u8>> {
    let blob_pointer: *const u8 = credential.CredentialBlob;
    let blob_len: usize = credential.CredentialBlobSize as usize;
    if blob_len == 0 {
        return Ok(Vec::new());
    }
    let blob = unsafe { std::slice::from_raw_parts(blob_pointer, blob_len) };
    Ok(blob.to_vec())
}

/// A metadata extractor for use with [extract_from_credential].
pub fn extract_attributes(credential: &CREDENTIALW) -> Result<HashMap<String, String>> {
    let result = HashMap::from([
        ("target_name".to_string(), unsafe {
            from_wstr(credential.TargetName)
        }),
        ("username".to_string(), unsafe {
            from_wstr(credential.UserName)
        }),
        ("target_alias".to_string(), unsafe {
            from_wstr(credential.TargetAlias)
        }),
        ("comment".to_string(), unsafe {
            from_wstr(credential.Comment)
        }),
        (
            "persistence".to_string(),
            match credential.Persist {
                CRED_PERSIST_SESSION => CredPersist::Session.to_string(),
                CRED_PERSIST_LOCAL_MACHINE => CredPersist::Local.to_string(),
                _ => CredPersist::Enterprise.to_string(),
            },
        ),
    ]);
    Ok(result)
}

/// helper for extract_from_platform
fn erase_secret(credential: &mut CREDENTIALW) {
    let blob_pointer: *mut u8 = credential.CredentialBlob;
    let blob_len: usize = credential.CredentialBlobSize as usize;
    if blob_len == 0 {
        return;
    }
    let blob = unsafe { std::slice::from_raw_parts_mut(blob_pointer, blob_len) };
    blob.zeroize();
}

fn to_wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(once(0)).collect()
}

fn to_wstr_no_null(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

unsafe fn from_wstr(ws: *const u16) -> String {
    // null pointer case, return empty string
    if ws.is_null() {
        return String::new();
    }
    // this code from https://stackoverflow.com/a/48587463/558006
    let len = (0..).take_while(|&i| unsafe { *ws.offset(i) != 0 }).count();
    if len == 0 {
        return String::new();
    }
    let slice = unsafe { std::slice::from_raw_parts(ws, len) };
    String::from_utf16_lossy(slice)
}

/// Windows error codes are `DWORDS` which are 32-bit unsigned ints.
#[derive(Debug)]
pub struct PlatformError(pub u32);

impl std::fmt::Display for PlatformError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.0 {
            ERROR_NO_SUCH_LOGON_SESSION => write!(f, "Windows ERROR_NO_SUCH_LOGON_SESSION"),
            ERROR_NOT_FOUND => write!(f, "Windows ERROR_NOT_FOUND"),
            ERROR_BAD_USERNAME => write!(f, "Windows ERROR_BAD_USERNAME"),
            ERROR_INVALID_FLAGS => write!(f, "Windows ERROR_INVALID_FLAGS"),
            ERROR_INVALID_PARAMETER => write!(f, "Windows ERROR_INVALID_PARAMETER"),
            err => write!(f, "Windows error code {err}"),
        }
    }
}

impl std::error::Error for PlatformError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// Map the last encountered Windows API error to a crate error with appropriate annotation.
pub fn decode_error() -> Error {
    match unsafe { GetLastError() } {
        ERROR_NOT_FOUND => Error::NoEntry,
        ERROR_NO_SUCH_LOGON_SESSION => Error::NoStorageAccess(wrap(ERROR_NO_SUCH_LOGON_SESSION)),
        err => Error::PlatformFailure(wrap(err)),
    }
}

fn wrap(code: u32) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(PlatformError(code))
}

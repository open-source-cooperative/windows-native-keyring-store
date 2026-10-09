use byteorder::{ByteOrder, LittleEndian};
use std::collections::HashMap;
use std::iter::once;

use windows_sys::Win32::Foundation::{
    ERROR_BAD_USERNAME, ERROR_INVALID_FLAGS, ERROR_INVALID_PARAMETER, ERROR_NO_SUCH_LOGON_SESSION,
    ERROR_NOT_FOUND, FILETIME, GetLastError,
};
use windows_sys::Win32::Globalization::{LCMAP_UPPERCASE, LCMapStringEx, LOCALE_NAME_INVARIANT};
#[cfg(feature = "search")]
use windows_sys::Win32::Security::Credentials::CredEnumerateW;
use windows_sys::Win32::Security::Credentials::{
    CRED_FLAGS, CRED_MAX_ATTRIBUTES, CRED_MAX_CREDENTIAL_BLOB_SIZE,
    CRED_MAX_GENERIC_TARGET_NAME_LENGTH, CRED_MAX_STRING_LENGTH, CRED_MAX_USERNAME_LENGTH,
    CRED_MAX_VALUE_SIZE, CRED_PERSIST, CRED_PERSIST_ENTERPRISE, CRED_PERSIST_LOCAL_MACHINE,
    CRED_PERSIST_SESSION, CRED_TYPE_GENERIC, CREDENTIAL_ATTRIBUTEW, CREDENTIALW, CredDeleteW,
    CredFree, CredReadW, CredWriteW,
};
use zeroize::Zeroize;

#[cfg(feature = "search")]
use crate::cred::Cred;
use crate::sealed_crypto::is_protected;
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
    write_credential(
        target_name,
        user,
        target_alias,
        comment,
        secret,
        persistence,
        &mut [],
    )
}

const SPELLING_KEYWORD: &str = "keyring:spelling:";

/// The longest `{user}.{service}` spelling, in UTF-8 bytes, that the attributes of one record hold.
pub(crate) const MAX_SPELLING_LEN: usize = (CRED_MAX_ATTRIBUTES * CRED_MAX_VALUE_SIZE) as usize;

/// Refuse a `{user}.{service}` spelling too long for the attributes of one record to hold.
pub(crate) fn validate_spelling(spelling: &str) -> Result<()> {
    if spelling.len() > MAX_SPELLING_LEN {
        return Err(Error::TooLong(
            "service and user".into(),
            u32::try_from(MAX_SPELLING_LEN).expect("the spelling bound fits u32"),
        ));
    }
    Ok(())
}

/// Save a sealed entry's record, keeping the caller's `spelling` of its name in its attributes.
pub(crate) fn save_spelled_credential(
    target_name: &str,
    user: &str,
    target_alias: &str,
    comment: &str,
    secret: &[u8],
    spelling: &str,
) -> Result<()> {
    let mut keywords: Vec<Vec<u16>> = Vec::new();
    let mut values: Vec<Vec<u8>> = Vec::new();
    for (index, chunk) in spelling
        .as_bytes()
        .chunks(CRED_MAX_VALUE_SIZE as usize)
        .enumerate()
    {
        keywords.push(to_wstr(&format!("{SPELLING_KEYWORD}{index}")));
        values.push(chunk.to_vec());
    }
    let mut attributes: Vec<CREDENTIAL_ATTRIBUTEW> = keywords
        .iter_mut()
        .zip(&mut values)
        .map(|(keyword, value)| CREDENTIAL_ATTRIBUTEW {
            Keyword: keyword.as_mut_ptr(),
            Flags: 0,
            ValueSize: u32::try_from(value.len()).expect("a chunk holds at most 256 bytes"),
            Value: value.as_mut_ptr(),
        })
        .collect();
    write_credential(
        target_name,
        user,
        target_alias,
        comment,
        secret,
        &CredPersist::Local,
        &mut attributes,
    )
}

/// The `{user}.{service}` spelling a sealed record keeps in its attributes, if it has a whole one.
#[cfg(feature = "search")]
pub(crate) fn spelling(credential: &CREDENTIALW) -> Option<String> {
    let mut chunks: Vec<(usize, &[u8])> = Vec::new();
    for index in 0..credential.AttributeCount as usize {
        // SAFETY: Credential Manager returns `AttributeCount` attributes valid while `credential` lives.
        let attribute = unsafe { &*credential.Attributes.add(index) };
        // SAFETY: every returned attribute has a NUL-terminated keyword.
        let keyword = unsafe { from_wstr(attribute.Keyword) };
        let Some(position) = keyword.strip_prefix(SPELLING_KEYWORD) else {
            continue;
        };
        let value = if attribute.ValueSize == 0 {
            &[][..]
        } else {
            // SAFETY: the attribute's value holds `ValueSize` bytes while `credential` lives.
            unsafe { std::slice::from_raw_parts(attribute.Value, attribute.ValueSize as usize) }
        };
        chunks.push((position.parse().ok()?, value));
    }
    chunks.sort_unstable_by_key(|&(position, _)| position);
    if chunks.is_empty()
        || chunks
            .iter()
            .enumerate()
            .any(|(expected, &(position, _))| expected != position)
    {
        return None;
    }
    String::from_utf8(
        chunks
            .into_iter()
            .flat_map(|(_, value)| value.iter().copied())
            .collect(),
    )
    .ok()
}

fn write_credential(
    target_name: &str,
    user: &str,
    target_alias: &str,
    comment: &str,
    secret: &[u8],
    persistence: &CredPersist,
    attributes: &mut [CREDENTIAL_ATTRIBUTEW],
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
    let credential = CREDENTIALW {
        Flags: flags,
        Type: cred_type,
        TargetName: target_name.as_mut_ptr(),
        Comment: comment.as_mut_ptr(),
        LastWritten: last_written,
        CredentialBlobSize: blob_len,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: persist,
        AttributeCount: u32::try_from(attributes.len()).expect("at most 64 attributes"),
        Attributes: if attributes.is_empty() {
            std::ptr::null_mut()
        } else {
            attributes.as_mut_ptr()
        },
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

/// A name in the case Credential Manager compares target names in.
///
/// Credential Manager matches targets by the Windows invariant upper case of each UTF-16 unit,
/// which differs from Rust's `to_uppercase` on hundreds of characters such as `ſ`, so two names
/// it treats as one target have equal folded forms and no others do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FoldedName(String);

impl FoldedName {
    pub(crate) fn new(name: &str) -> Result<Self> {
        let units: Vec<u16> = name.encode_utf16().collect();
        if units.is_empty() {
            return Ok(Self(String::new()));
        }
        let length = i32::try_from(units.len())
            .map_err(|_| Error::TooLong(name.to_owned(), i32::MAX.cast_unsigned()))?;
        let mut folded = vec![0u16; units.len()];
        // SAFETY: both buffers hold `length` units, and the invariant locale needs no version
        // information or sort handle.
        let written = unsafe {
            LCMapStringEx(
                LOCALE_NAME_INVARIANT,
                LCMAP_UPPERCASE,
                units.as_ptr(),
                length,
                folded.as_mut_ptr(),
                length,
                std::ptr::null(),
                std::ptr::null(),
                0,
            )
        };
        if written != length {
            return Err(decode_error());
        }
        // Upper-casing maps each unit to one unit and leaves surrogates alone, so `name`'s
        // valid UTF-16 stays valid.
        Ok(Self(String::from_utf16_lossy(&folded)))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
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
#[cfg(feature = "search")]
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
        if let Some(pat) = &pattern
            && !pat.is_match(&candidate.target_name)
        {
            continue;
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
#[cfg(feature = "search")]
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
        sealed: None,
    }
}

/// A password extractor for use with [extract_from_credential].
pub fn extract_password(credential: &CREDENTIALW) -> Result<String> {
    let blob = credential_blob(credential);
    if is_protected(blob) {
        return Err(Error::BadStoreFormat(
            "protected credential requires a sealed store".into(),
        ));
    }
    password_from_secret(blob.to_vec())
}

pub(crate) fn password_from_secret(mut blob: Vec<u8>) -> Result<String> {
    if !blob.len().is_multiple_of(2) {
        return Err(Error::BadEncoding(blob));
    }
    let mut blob_u16 = vec![0; blob.len() / 2];
    LittleEndian::read_u16_into(&blob, &mut blob_u16);
    let result = match String::from_utf16(&blob_u16) {
        Err(_) => Err(Error::BadEncoding(blob)),
        Ok(s) => {
            blob.zeroize();
            Ok(s)
        }
    };
    blob_u16.zeroize();
    result
}

/// A secret extractor for use with [extract_from_credential].
pub fn extract_secret(credential: &CREDENTIALW) -> Result<Vec<u8>> {
    Ok(credential_blob(credential).to_vec())
}

fn credential_blob(credential: &CREDENTIALW) -> &[u8] {
    if credential.CredentialBlobSize == 0 {
        return &[];
    }
    // SAFETY: Credential Manager owns `CredentialBlobSize` bytes at `CredentialBlob` while `credential` lives.
    unsafe {
        std::slice::from_raw_parts(
            credential.CredentialBlob,
            usize::try_from(credential.CredentialBlobSize).expect("u32 fits usize on Windows"),
        )
    }
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

/// The target name of a credential returned by `CredReadW` or `CredEnumerateW`.
pub(crate) fn target_name(credential: &CREDENTIALW) -> String {
    // SAFETY: Credential Manager returns a NUL-terminated `TargetName` valid while `credential` lives.
    unsafe { from_wstr(credential.TargetName) }
}

/// Lowercase hexadecimal encoding of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 15])
        .map(|nibble| char::from(DIGITS[usize::from(nibble)]))
        .collect()
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

/// Reads a NUL-terminated wide string, returning an empty string for null.
///
/// WebAuthn packs strings after odd-length byte arrays, so `ws` may be unaligned.
///
/// # Safety
/// `ws` must be null or point to a NUL-terminated UTF-16 string valid for the call.
pub(crate) unsafe fn from_wstr(ws: *const u16) -> String {
    if ws.is_null() {
        return String::new();
    }
    let units: Vec<u16> = (0..)
        // SAFETY: the caller guarantees the string is NUL-terminated, so reads stop in bounds.
        .map(|at| unsafe { ws.add(at).read_unaligned() })
        .take_while(|&unit| unit != 0)
        .collect();
    String::from_utf16_lossy(&units)
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

#[cfg(test)]
#[cfg(feature = "search")]
mod tests {
    use super::{SPELLING_KEYWORD, spelling, to_wstr};
    use windows_sys::Win32::Security::Credentials::{CREDENTIAL_ATTRIBUTEW, CREDENTIALW};

    /// A credential whose spelling is split over its `keyring:spelling:` attributes.
    struct Cred {
        credential: CREDENTIALW,
        _keywords: Vec<Vec<u16>>,
        _values: Vec<Vec<u8>>,
        _attributes: Vec<CREDENTIAL_ATTRIBUTEW>,
    }

    /// Builds a credential whose spelling chunks live under `keyring:spelling:<position>`.
    fn spelled(chunks: &[(usize, &[u8])]) -> Cred {
        let mut keywords: Vec<Vec<u16>> = chunks
            .iter()
            .map(|&(position, _)| to_wstr(&format!("{SPELLING_KEYWORD}{position}")))
            .collect();
        let mut values: Vec<Vec<u8>> = chunks.iter().map(|&(_, value)| value.to_vec()).collect();
        let mut attributes: Vec<CREDENTIAL_ATTRIBUTEW> = chunks
            .iter()
            .enumerate()
            .map(|(index, _)| CREDENTIAL_ATTRIBUTEW {
                Keyword: keywords[index].as_mut_ptr(),
                Flags: 0,
                ValueSize: u32::try_from(values[index].len()).expect("a test chunk fits u32"),
                Value: values[index].as_mut_ptr(),
            })
            .collect();
        let credential = CREDENTIALW {
            AttributeCount: u32::try_from(attributes.len()).expect("a test credential fits u32"),
            Attributes: if attributes.is_empty() {
                std::ptr::null_mut()
            } else {
                attributes.as_mut_ptr()
            },
            ..Default::default()
        };
        Cred {
            credential,
            _keywords: keywords,
            _values: values,
            _attributes: attributes,
        }
    }

    #[test]
    fn a_record_without_spelling_chunks_has_no_spelling() {
        let cred = spelled(&[]);
        assert_eq!(spelling(&cred.credential), None);
    }

    #[test]
    fn a_record_missing_a_spelling_chunk_has_no_spelling() {
        let cred = spelled(&[(1, b"world")]);
        assert_eq!(spelling(&cred.credential), None);
    }

    #[test]
    fn a_record_reassembles_its_spelling_chunks() {
        let cred = spelled(&[(1, b"world"), (0, b"hello ")]);
        assert_eq!(spelling(&cred.credential), Some("hello world".into()));
    }
}

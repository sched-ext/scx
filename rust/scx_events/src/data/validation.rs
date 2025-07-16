use ::core::ffi::{CStr, FromBytesWithNulError, c_char};
use ::memchr::memmem;
use ::std::sync::LazyLock;
use ::winnow::BStr;

/// The C nul.
#[allow(clippy::as_conversions, reason = "lack of literal syntax")]
#[allow(clippy::cast_possible_wrap, reason = "lack of literal syntax")]
static NUL_BYTE: &[u8; 1] = b"\0";

/// The C nul.
#[allow(clippy::as_conversions, reason = "lack of literal syntax")]
#[allow(clippy::cast_possible_wrap, reason = "lack of literal syntax")]
static NUL_C_CHAR: c_char = NUL_BYTE[0] as c_char;

/// A fast memchr finder for nul bytes.
static CSTR_NUL_FINDER: LazyLock<memmem::Finder<'static>> = LazyLock::new(|| memmem::Finder::new(NUL_BYTE));

/// Finds the first occurrence of a nul byte in `field`. Returns None if not found.
pub fn find_cstr_nul<const N: usize>(field: &[c_char; N]) -> Option<usize> {
    // SAFETY: Cast to compatible type repr: &[i8] -> &[u8].
    let bytes = unsafe { ::core::slice::from_raw_parts(field.as_ptr().cast::<u8>(), field.len()) };
    CSTR_NUL_FINDER.find(bytes)
}

/// Validates `field` as a C-string then check for valid UTF-8. Returns [`&str`] if valid.
pub fn validate_cstr<const N: usize>(field: &[c_char; N]) -> crate::Result<&BStr> {
    let nul = find_cstr_nul(field).ok_or(FromBytesWithNulError::NotNulTerminated)?;
    // Double check for nul byte.
    debug_assert!(field.get(nul).copied() == Some(NUL_C_CHAR), "expected nul byte");
    // SAFETY: Just validated presence of nul byte.
    let cstr = unsafe { CStr::from_ptr(field[..=nul].as_ptr().cast::<c_char>()) };
    // Skip UTF-8 validation since we don't really need it and just return a &BStr.
    Ok(BStr::new(cstr.to_bytes()))
}

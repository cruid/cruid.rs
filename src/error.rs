//! Error types.

use core::{array::TryFromSliceError, fmt};

/// Result type with the `cruid` crate's [`Error`] type.
pub type Result<T> = core::result::Result<T, Error>;

/// Error type.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Decryption failed.
    Decryption,

    /// Encoding is invalid.
    Encoding,

    /// Length is invalid.
    Length,
}

impl From<TryFromSliceError> for Error {
    fn from(_: TryFromSliceError) -> Error {
        Error::Length
    }
}

impl From<base16ct::Error> for Error {
    fn from(err: base16ct::Error) -> Error {
        match err {
            base16ct::Error::InvalidEncoding => Error::Encoding,
            base16ct::Error::InvalidLength => Error::Length,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Decryption => "decryption failed",
            Error::Encoding => "encoding invalid",
            Error::Length => "length invalid",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

//! Cryptographically Random Unique IDentifiers (CRUIDs)

#![no_std]
#![warn(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::checked_conversions,
    clippy::implicit_saturating_sub,
    clippy::integer_arithmetic,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

#[cfg(feature = "std")]
extern crate std;

mod cruid;
mod encryption;
mod error;

pub use crate::{
    cruid::Cruid,
    encryption::EncryptionKey,
    error::{Error, Result},
};

/// 128-bit (16-byte) buffer, i.e. the size of data in a CRUID.
pub type Bytes = [u8; 16];

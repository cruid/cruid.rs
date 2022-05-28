//! Cryptographically Random Unique IDentifier (CRUID).

use crate::{Bytes, Error, Result};
use core::{fmt, ops::RangeInclusive, str};

#[cfg(feature = "uuid")]
use uuid::Uuid;

/// Ranges within [`Bytes`] which correspond to CRUID fields.
const BYTES_RANGES: &[RangeInclusive<usize>] = &[0..=3, 4..=5, 6..=7, 8..=9, 10..=15];

/// Ranges within a CRUID where fields are located.
const FIELD_RANGES: &[RangeInclusive<usize>] = &[0..=7, 9..=12, 14..=17, 19..=22, 24..=35];

/// Cryptographically Random Unique IDentifier (CRUID).
#[derive(Copy, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct Cruid {
    /// ASCII bytes which comprise a serialized CRUID.
    bytes: [u8; Self::SERIALIZED_SIZE],
}

impl Cruid {
    /// Size of a serialized CRUID in bytes.
    const SERIALIZED_SIZE: usize = 36;

    /// Parse a CRUID from a UUID-like string.
    pub fn parse(string: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = <[u8; Self::SERIALIZED_SIZE]>::try_from(string.as_ref())?;

        // Validate characters that are expected to be hyphens
        if ![8, 13, 18, 23].into_iter().all(|i| bytes[i] == b'-') {
            return Err(Error::Encoding);
        }

        // Instantiate CRUID so we can call `iter_fields` to validate them.
        let cruid = Self { bytes };

        // Buffer which is the maximum size of a field in a CRUID
        let mut buf = [0u8; 6];

        // Ensure all fields will decode successfully
        for field in cruid.iter_fields() {
            base16ct::mixed::decode(field, &mut buf)?;
        }

        Ok(cruid)
    }

    /// Borrow the bytes of this CRUID as a string.
    pub fn as_str(&self) -> &str {
        debug_assert!(str::from_utf8(&self.bytes).is_ok());
        unsafe { str::from_utf8_unchecked(&self.bytes) }
    }

    /// Encode the provided 16-byte value into a CRUID.
    pub fn from_bytes(input: &Bytes) -> Cruid {
        let mut output = [b'-'; Self::SERIALIZED_SIZE];

        for (in_range, out_range) in BYTES_RANGES.iter().zip(FIELD_RANGES.iter()) {
            base16ct::lower::encode(&input[in_range.clone()], &mut output[out_range.clone()])
                .expect("hex encode failed");
        }

        #[cfg(debug_assertions)]
        assert!(Self::parse(output).is_ok());

        Self { bytes: output }
    }

    /// Decode the hex fields in a CRUID into raw bytes.
    pub fn to_bytes(&self) -> Bytes {
        let mut ret = Bytes::default();

        for (field, range) in self.iter_fields().zip(BYTES_RANGES.iter()) {
            base16ct::mixed::decode(field, &mut ret[range.clone()]).expect("hex decode failed");
        }

        ret
    }

    /// Iterate over the fields of a CRUID as slices.
    fn iter_fields(&self) -> impl Iterator<Item = &[u8]> {
        FIELD_RANGES.iter().map(|range| &self.bytes[range.clone()])
    }
}

impl AsRef<str> for Cruid {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for Cruid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Cruid").field(&self.as_str()).finish()
    }
}

impl fmt::Display for Cruid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl str::FromStr for Cruid {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(feature = "uuid")]
impl From<Cruid> for Uuid {
    fn from(cruid: Cruid) -> Uuid {
        Uuid::from_bytes(cruid.to_bytes())
    }
}

#[cfg(feature = "uuid")]
impl From<Uuid> for Cruid {
    fn from(uuid: Uuid) -> Cruid {
        Cruid::from_bytes(uuid.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::{Bytes, Cruid, Error};

    const EXAMPLE_CRUID: &str = "123e4567-e89b-12d3-a456-426614174000";
    const EXAMPLE_BYTES: Bytes = [
        18, 62, 69, 103, 232, 155, 18, 211, 164, 86, 66, 102, 20, 23, 64, 0,
    ];

    #[test]
    fn from_bytes() {
        let cruid = Cruid::from_bytes(&EXAMPLE_BYTES);
        assert_eq!(cruid.as_str(), EXAMPLE_CRUID);
    }

    #[test]
    fn parse_ok() {
        let cruid = Cruid::parse(EXAMPLE_CRUID).unwrap();
        assert_eq!(cruid.as_str(), EXAMPLE_CRUID);
    }

    #[test]
    fn parse_err() {
        let err = Cruid::parse(&[]).err().unwrap();
        assert_eq!(err, Error::Length);
    }

    #[test]
    fn to_bytes() {
        let cruid = Cruid::parse(EXAMPLE_CRUID).unwrap();
        assert_eq!(cruid.to_bytes(), EXAMPLE_BYTES);
    }

    #[cfg(feature = "uuid")]
    #[test]
    fn uuid_round_trip() {
        let cruid = Cruid::parse(EXAMPLE_CRUID).unwrap();
        let uuid = uuid::Uuid::from(cruid);
        assert_eq!(cruid, Cruid::from(uuid));
    }
}

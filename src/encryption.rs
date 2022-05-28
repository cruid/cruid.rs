//! CRUID encryption keys.

use crate::{Cruid, Error, Result};
use aes::{
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128, Block,
};

/// CRUID-AES-128 encryption key.
pub struct EncryptionKey(Aes128);

impl EncryptionKey {
    /// Size of an encryption key in bytes.
    pub const BYTE_SIZE: usize = 16;

    /// Create a new encryption key from the given bytes.
    pub fn new(bytes: &[u8; Self::BYTE_SIZE]) -> Self {
        Self(Aes128::new(bytes.into()))
    }

    /// Encrypt the given 64-bit integer, returning a [`Cruid`].
    pub fn encrypt(&self, plaintext: u64) -> Cruid {
        let mut block = Block::default();
        block[..8].copy_from_slice(&plaintext.to_le_bytes());
        self.0.encrypt_block(&mut block);
        Cruid::from_bytes(&block.into())
    }

    /// Decrypt the given [`Cruid`], returning a 64-bit integer if it
    /// authenticates successfully under this key.
    pub fn decrypt(&self, cruid: &Cruid) -> Result<u64> {
        let mut block = Block::from(cruid.to_bytes());
        self.0.decrypt_block(&mut block);

        let (a, b) = block.split_at(8);
        let value = u64::from_le_bytes(a.try_into()?);
        let tag = u64::from_le_bytes(b.try_into()?);

        if tag == 0 {
            Ok(value)
        } else {
            Err(Error::Decryption)
        }
    }
}

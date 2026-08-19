//! Pure-Rust ports of the Sapling primitives called by
//! `CVDXFEncryptor::Encrypt` / `::Decrypt` in
//! `VerusCoin/src/pbaas/vdxf.cpp:614-656` and `NoteEncryption.cpp:43-65`.
//!
//! Byte-parity for the DH + KDF + AEAD stack was proven at scoping time by
//! the `byte-parity-experiment` crate (see `scope-report.md`). This module is
//! the productionised port of the same code.
//!
//! Scope of this module: the primitives that don't depend on Sapling's
//! diversified-base group hash. That group hash is what turns an 11-byte
//! diversifier into the `g_d` point needed for `epk = esk * g_d` on the
//! encrypt side. It will land in a follow-up commit once we decide whether to
//! implement `group_hash` locally (Blake2s with `"Zcash_gd"` personalization
//! plus a Jubjub point-decode) or pull in `sapling-crypto`. Nothing in this
//! module blocks that decision.

use blake2b_simd::Params as Blake2bParams;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use jubjub::{AffinePoint, ExtendedPoint, Fr};

/// Result of a Sapling AEAD decrypt failure. Poly1305 tag mismatch, malformed
/// scalar/point, or truncated ciphertext all map here.
#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// The provided IVK/scalar bytes did not decode to a canonical Jubjub Fr.
    InvalidScalar,
    /// The provided point bytes did not decode to a canonical Jubjub affine
    /// point.
    InvalidPoint,
    /// ChaCha20Poly1305-IETF authenticated decryption failed (tag mismatch
    /// or ciphertext shorter than 16 bytes).
    AeadFailed,
}

/// `KDF_Sapling` — Blake2b-256 with personalization `"Zcash_SaplingKDF"`
/// over `dhsecret (32B) || epk (32B)`. Byte-identical to
/// `KDF_Sapling` at `VerusCoin/src/zcash/NoteEncryption.cpp:43-65`.
pub fn kdf_sapling(dhsecret: &[u8; 32], epk: &[u8; 32]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(dhsecret);
    block[32..].copy_from_slice(epk);
    let hash = Blake2bParams::new()
        .hash_length(32)
        .personal(b"Zcash_SaplingKDF")
        .to_state()
        .update(&block)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// Sapling key agreement — `scalar * point.mul_by_cofactor()`, encoded as
/// 32 compressed affine bytes.
///
/// Called by the daemon on both sides of the envelope:
///
/// - Decrypt: `scalar = ivk`, `point = epk` (`vdxf.cpp:555`).
/// - Encrypt: `scalar = esk`, `point = pk_d` (`vdxf.cpp:629`).
///
/// Both directions use the same underlying `sapling_ka_agree` primitive
/// (`librustzcash_sapling_ka_agree`), and both cofactor-clear the point
/// before scalar-multiplying. `pk_d` is derived by construction to be in the
/// prime-order subgroup, so the cofactor multiplication is a no-op on the
/// encrypt side; on the decrypt side `epk` is untrusted network data and
/// requires the clearing.
///
/// Returns `None` if `scalar_bytes` is not a canonical scalar or `point_bytes`
/// is not a canonical Jubjub point.
pub fn sapling_ka_agree(
    scalar_bytes: &[u8; 32],
    point_bytes: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let scalar = Option::<Fr>::from(Fr::from_bytes(scalar_bytes)).ok_or(CryptoError::InvalidScalar)?;
    let point_affine = Option::<AffinePoint>::from(AffinePoint::from_bytes(*point_bytes))
        .ok_or(CryptoError::InvalidPoint)?;
    let point_ext: ExtendedPoint = point_affine.into();
    let shared = point_ext.mul_by_cofactor() * scalar;
    Ok(AffinePoint::from(shared).to_bytes())
}

/// ChaCha20Poly1305-IETF encrypt with the daemon's fixed nonce convention:
/// 12-byte zero nonce, no AAD. Safe here because every `CVDXFEncryptor::Encrypt`
/// call has a freshly sampled `esk` (and therefore a fresh `K`), so no key is
/// ever reused across two encryptions. See the daemon comment at
/// `src/pbaas/vdxf.cpp:564`: *"The nonce is zero because we never reuse keys"*.
///
/// Output is `plaintext.len() + 16` bytes (Poly1305 tag appended).
pub fn aead_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from([0u8; 12]);
    cipher
        .encrypt(&nonce, plaintext)
        .expect("ChaCha20Poly1305 encrypt is infallible for in-memory buffers")
}

/// Inverse of [`aead_encrypt`]. Returns `Err(CryptoError::AeadFailed)` on
/// tag mismatch, malformed ciphertext, or ciphertext shorter than 16 bytes
/// (i.e., no tag).
pub fn aead_decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from([0u8; 12]);
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| CryptoError::AeadFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_encrypt_then_decrypt_round_trips_a_pinned_key() {
        let key = [0x11u8; 32];
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let ct = aead_encrypt(&key, plaintext);
        assert_eq!(ct.len(), plaintext.len() + 16, "tag is 16 bytes");
        let pt = aead_decrypt(&key, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn aead_decrypt_rejects_flipped_ciphertext_bit() {
        let key = [0x22u8; 32];
        let mut ct = aead_encrypt(&key, b"tamper me");
        ct[0] ^= 0x01;
        assert_eq!(aead_decrypt(&key, &ct), Err(CryptoError::AeadFailed));
    }

    #[test]
    fn aead_decrypt_rejects_flipped_tag_bit() {
        let key = [0x33u8; 32];
        let mut ct = aead_encrypt(&key, b"tamper me");
        let tag_start = ct.len() - 16;
        ct[tag_start] ^= 0x01;
        assert_eq!(aead_decrypt(&key, &ct), Err(CryptoError::AeadFailed));
    }

    #[test]
    fn aead_decrypt_rejects_wrong_key() {
        let ct = aead_encrypt(&[0x44u8; 32], b"secret");
        assert_eq!(
            aead_decrypt(&[0x55u8; 32], &ct),
            Err(CryptoError::AeadFailed)
        );
    }

    #[test]
    fn kdf_sapling_matches_byte_parity_fixture() {
        // From the byte-parity experiment against the t1_578528 fixture:
        //   dhsecret = 707a5867652106014c5ead2c2da8d2b1a42e9accff04fba3ca4b0ca6e76c4f6e
        //   epk      = 707bd1ff25dc07fb0a209f8859a332989ae0b81d0b4557e86cd7ce0a7a5f3fc3
        //   K        = a3fecb88afa9d2d0ae27e0ed41b9a91f980415bcc84005aebb74894f1744d872
        let dhsecret =
            hex_to_32("707a5867652106014c5ead2c2da8d2b1a42e9accff04fba3ca4b0ca6e76c4f6e");
        let epk = hex_to_32("707bd1ff25dc07fb0a209f8859a332989ae0b81d0b4557e86cd7ce0a7a5f3fc3");
        let k = kdf_sapling(&dhsecret, &epk);
        assert_eq!(
            hex::encode(k),
            "a3fecb88afa9d2d0ae27e0ed41b9a91f980415bcc84005aebb74894f1744d872"
        );
    }

    #[test]
    fn sapling_ka_agree_matches_byte_parity_fixture_decrypt_direction() {
        // Fixture: t1@ vrsctest height 578528, decrypt side.
        //   ivk        = a4ad4638eb96fb16c1a7d3e3cea86bcb7a243ace112286e1f4a64481a34c4100
        //   epk        = 707bd1ff25dc07fb0a209f8859a332989ae0b81d0b4557e86cd7ce0a7a5f3fc3
        //   dhsecret   = 707a5867652106014c5ead2c2da8d2b1a42e9accff04fba3ca4b0ca6e76c4f6e
        let ivk = hex_to_32("a4ad4638eb96fb16c1a7d3e3cea86bcb7a243ace112286e1f4a64481a34c4100");
        let epk = hex_to_32("707bd1ff25dc07fb0a209f8859a332989ae0b81d0b4557e86cd7ce0a7a5f3fc3");
        let shared = sapling_ka_agree(&ivk, &epk).expect("valid ka agree");
        assert_eq!(
            hex::encode(shared),
            "707a5867652106014c5ead2c2da8d2b1a42e9accff04fba3ca4b0ca6e76c4f6e"
        );
    }

    fn hex_to_32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).expect("valid hex");
        out
    }
}

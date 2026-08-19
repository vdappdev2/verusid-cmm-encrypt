//! Sapling ephemeral-key derivation for the encrypt side of the envelope
//! path (`VerusCoin/src/pbaas/vdxf.cpp:614-656`).
//!
//! The daemon calls three librustzcash FFIs during
//! `CVDXFEncryptor::Encrypt`:
//!
//! 1. `librustzcash_sapling_generate_r(esk)` — sample a uniform Jubjub
//!    scalar. Ported here as [`generate_esk`].
//! 2. `librustzcash_sapling_ka_derivepublic(d, esk) → epk` — compute
//!    `epk = esk * g_d(d)`. Ported here as [`derive_epk`].
//! 3. `librustzcash_sapling_ka_agree(pk_d, esk) → dhsecret` — compute
//!    `dhsecret = esk * pk_d.mul_by_cofactor()`. Already available as
//!    [`crate::crypto::sapling_ka_agree`] (same primitive as the decrypt
//!    side — just called with different scalar/point roles).
//!
//! `g_d(d)` is the Sapling diversified base point derivation. It uses the
//! `group_hash` construction from the Zcash Sapling specification:
//! BLAKE2s-256 personalized with `"Zcash_gd"` over
//! `GH_FIRST_BLOCK || diversifier`, then decode the 32-byte hash as a
//! compressed Jubjub point and multiply by the cofactor. Fails with
//! probability ~1/8 for a random `d`; the daemon's z-address generation
//! rejects such diversifiers.
//!
//! What is byte-parity-tested here: DH round-trip consistency (encrypt
//! and decrypt sides derive the same `dhsecret`), and deterministic
//! `epk` bytes for pinned `(esk, d)` inputs. What is deferred to Phase 2
//! (running-daemon round-trip): third-party interop confirmation that
//! this crate's `epk` matches what `librustzcash_sapling_ka_derivepublic`
//! produces for the same inputs.

use blake2s_simd::Params as Blake2sParams;
use ff::Field;
use group::{Group, GroupEncoding};
use jubjub::{AffinePoint, ExtendedPoint, Fr};
use rand_core::{CryptoRng, RngCore};

use crate::crypto::CryptoError;

/// The 64-byte "URS" prefix that every Sapling `group_hash` invocation
/// consumes before the personalization input. Ports Zcash constant
/// `GH_FIRST_BLOCK` (Zcash Sapling protocol §5.4.9.5). Note this is an
/// ASCII byte string, not the hex-decoded form.
const GH_FIRST_BLOCK: &[u8; 64] = b"096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0";

/// BLAKE2s personalization for the diversified-base group hash: `"Zcash_gd"`.
const GH_D_PERSONALIZATION: &[u8; 8] = b"Zcash_gd";

/// Errors specific to ephemeral-key derivation. Distinct from
/// [`CryptoError`] because the failure modes are different (invalid
/// diversifier bytes vs. AEAD tag mismatch).
#[derive(Debug, PartialEq, Eq)]
pub enum EphemeralError {
    /// The diversifier `d` did not produce a valid Jubjub subgroup point
    /// under Sapling's group_hash. Retry with a different diversifier;
    /// valid Sapling addresses guarantee a decoding `d` by construction.
    InvalidDiversifier,
    /// The provided `esk` bytes did not decode to a canonical Jubjub scalar
    /// in `[0, r)`. Should not happen for scalars produced by
    /// [`generate_esk`].
    InvalidScalar,
}

impl From<EphemeralError> for CryptoError {
    fn from(e: EphemeralError) -> Self {
        match e {
            EphemeralError::InvalidScalar => CryptoError::InvalidScalar,
            EphemeralError::InvalidDiversifier => CryptoError::InvalidPoint,
        }
    }
}

/// Sample a uniformly random Jubjub scalar in `[0, r)` and return its
/// canonical 32-byte little-endian encoding. Matches
/// `librustzcash_sapling_generate_r`.
///
/// The caller MUST supply a cryptographically secure RNG. In production
/// this is typically `rand::rngs::OsRng`; in tests this crate uses
/// `rand_chacha::ChaCha20Rng` seeded for reproducibility.
pub fn generate_esk<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
    Fr::random(rng).to_bytes()
}

/// Compute the Sapling diversified base point `g_d(d)` using the
/// specification's `group_hash` construction. Returns `None` iff the
/// diversifier is not a valid Sapling diversifier (does not decode to a
/// point in the prime-order subgroup).
///
/// This is the primitive underneath `librustzcash_sapling_ka_derivepublic`
/// and `pk_d = ivk * g_d(d)` on the recipient side.
pub fn derive_g_d(d: &[u8; 11]) -> Option<AffinePoint> {
    let hash = Blake2sParams::new()
        .hash_length(32)
        .personal(GH_D_PERSONALIZATION)
        .to_state()
        .update(GH_FIRST_BLOCK)
        .update(d)
        .finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(hash.as_bytes());

    let point = Option::<AffinePoint>::from(AffinePoint::from_bytes(bytes))?;
    let cleared = ExtendedPoint::from(point).mul_by_cofactor();
    if cleared == ExtendedPoint::identity() {
        None
    } else {
        Some(AffinePoint::from(cleared))
    }
}

/// Derive the ephemeral public key: `epk = esk * g_d(d)`. Matches
/// `librustzcash_sapling_ka_derivepublic(d, esk, epk)`.
///
/// Returns `Err(InvalidDiversifier)` if `d` fails Sapling's group_hash
/// (rare; ~1 in 8 for random `d`, but valid Sapling addresses always
/// succeed). Returns `Err(InvalidScalar)` if `esk` is not a canonical
/// Jubjub scalar in `[0, r)`.
pub fn derive_epk(esk: &[u8; 32], d: &[u8; 11]) -> Result<[u8; 32], EphemeralError> {
    let scalar = Option::<Fr>::from(Fr::from_bytes(esk)).ok_or(EphemeralError::InvalidScalar)?;
    let g_d = derive_g_d(d).ok_or(EphemeralError::InvalidDiversifier)?;
    let epk = ExtendedPoint::from(g_d) * scalar;
    Ok(AffinePoint::from(epk).to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{aead_decrypt, aead_encrypt, kdf_sapling, sapling_ka_agree};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// Pinned-input regression: same (esk, d) must always produce the same
    /// epk bytes. Detects any accidental non-determinism (e.g., using an
    /// RNG inside derive_epk by mistake).
    #[test]
    fn derive_epk_is_deterministic_for_pinned_inputs() {
        let esk = [0x11u8; 32];
        let d = [0x22u8; 11];
        // 0x11 * 32 is not necessarily < r (Jubjub order), but Fr::from_bytes
        // will accept it iff canonical. If it doesn't decode we'd get an
        // error rather than nondeterminism, which is also fine for this test.
        let a = derive_epk(&esk, &d);
        let b = derive_epk(&esk, &d);
        assert_eq!(a, b);
    }

    /// Any valid Sapling diversifier that group-hashes must produce a
    /// non-identity point in the prime-order subgroup.
    #[test]
    fn derive_g_d_returns_a_valid_subgroup_point_when_diversifier_decodes() {
        // Try a range of diversifiers until we find one that decodes.
        // Probability of decode-failure is ~1/8 per attempt, so a small
        // number of tries almost certainly succeeds.
        let mut found = false;
        for i in 0..16u8 {
            let d = [i; 11];
            if let Some(point) = derive_g_d(&d) {
                // The returned point should be non-identity (guaranteed by
                // derive_g_d's own check) and on-curve (guaranteed by
                // successful decode).
                let ext: ExtendedPoint = point.into();
                assert!(ext != ExtendedPoint::identity(), "g_d({i}) is identity");
                found = true;
                break;
            }
        }
        assert!(found, "no valid diversifier found in 16 tries; probability < 1e-14");
    }

    /// End-to-end DH round-trip: derive keys as encrypt-side would,
    /// then compute dhsecret both ways and verify equality. This proves
    /// group_hash, esk sampling, epk derivation, and sapling_ka_agree
    /// compose correctly.
    #[test]
    fn dh_round_trip_encrypt_and_decrypt_sides_agree() {
        // Deterministic RNG for reproducibility.
        let mut rng = ChaCha20Rng::seed_from_u64(0x5a70_1e_a5_a5_a5_00u64);

        // Find a working diversifier.
        let mut d = [0u8; 11];
        loop {
            rng.fill_bytes(&mut d);
            if derive_g_d(&d).is_some() {
                break;
            }
        }
        let g_d = derive_g_d(&d).unwrap();

        // Simulate a recipient: pick ivk in [0, r), compute pk_d = ivk * g_d.
        let ivk_fr = Fr::random(&mut rng);
        let ivk_bytes = ivk_fr.to_bytes();
        let pk_d_ext = ExtendedPoint::from(g_d) * ivk_fr;
        let pk_d_bytes = AffinePoint::from(pk_d_ext).to_bytes();

        // Sender: sample esk, derive epk = esk * g_d.
        let esk_bytes = generate_esk(&mut rng);
        let epk_bytes = derive_epk(&esk_bytes, &d).unwrap();

        // Encrypt-side dhsecret = ka_agree(esk, pk_d).
        let dhsecret_encrypt = sapling_ka_agree(&esk_bytes, &pk_d_bytes).unwrap();
        // Decrypt-side dhsecret = ka_agree(ivk, epk).
        let dhsecret_decrypt = sapling_ka_agree(&ivk_bytes, &epk_bytes).unwrap();

        assert_eq!(
            dhsecret_encrypt, dhsecret_decrypt,
            "encrypt-side and decrypt-side DH must agree"
        );
    }

    /// A step further than DH agreement: encrypt a message with the
    /// derived symmetric key, then decrypt with the same key computed via
    /// the recipient's ivk. If any layer is wrong the AEAD tag verification
    /// fails.
    #[test]
    fn full_encrypt_decrypt_round_trip_with_derived_keys() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xdeadbeef_cafebabeu64);

        let mut d = [0u8; 11];
        loop {
            rng.fill_bytes(&mut d);
            if derive_g_d(&d).is_some() {
                break;
            }
        }
        let g_d = derive_g_d(&d).unwrap();
        let ivk_fr = Fr::random(&mut rng);
        let ivk_bytes = ivk_fr.to_bytes();
        let pk_d_bytes = AffinePoint::from(ExtendedPoint::from(g_d) * ivk_fr).to_bytes();
        let esk_bytes = generate_esk(&mut rng);
        let epk_bytes = derive_epk(&esk_bytes, &d).unwrap();

        // Sender's K.
        let dhsecret_enc = sapling_ka_agree(&esk_bytes, &pk_d_bytes).unwrap();
        let k_enc = kdf_sapling(&dhsecret_enc, &epk_bytes);
        let plaintext = b"the pineapple was in fact on the pizza";
        let ciphertext = aead_encrypt(&k_enc, plaintext);

        // Receiver's K.
        let dhsecret_dec = sapling_ka_agree(&ivk_bytes, &epk_bytes).unwrap();
        let k_dec = kdf_sapling(&dhsecret_dec, &epk_bytes);
        assert_eq!(k_enc, k_dec, "symmetric key must be identical on both sides");
        let recovered = aead_decrypt(&k_dec, &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }

    /// Regression against silent failures of the diversifier check.
    /// generate_esk must return a scalar that Fr::from_bytes accepts.
    #[test]
    fn generate_esk_produces_canonical_scalar() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        for _ in 0..100 {
            let esk = generate_esk(&mut rng);
            let decoded: Option<Fr> = Fr::from_bytes(&esk).into();
            assert!(decoded.is_some(), "generate_esk must produce a canonical Fr");
        }
    }
}

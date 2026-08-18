use crate::traits::Kem;
use qrypt_core::algebra::QcPoly;
use qrypt_core::constant_time::ct_conditional_copy;
use qrypt_core::error::QryptError;
use rand_core::{CryptoRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use subtle::Choice;
use zeroize::Zeroize;

pub const QC_R: usize = 257;
pub const QC_W: usize = 16; // Weight w_0 = w_1 = 8 (total w = 16)
pub const QC_T: usize = 14; // Error weight t_0 = t_1 = 7 (total t = 14)
pub const QC_MAX_ITERS: usize = 10;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CodePublicKey {
    pub g: QcPoly,
}

#[derive(Clone)]
pub struct CodeSecretKey {
    pub h0: QcPoly,
    pub h1: QcPoly,
    pub pk: CodePublicKey,
    pub hpk: [u8; 32],
    pub z: [u8; 32], // Implicit rejection key
}

impl Zeroize for CodeSecretKey {
    fn zeroize(&mut self) {
        self.h0.zeroize();
        self.h1.zeroize();
        self.hpk.zeroize();
        self.z.zeroize();
    }
}

impl Drop for CodeSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CodeCiphertext {
    pub syndrome: QcPoly,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CodeSharedSecret(pub [u8; 32]);

impl Zeroize for CodeSharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for CodeSharedSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl AsRef<[u8]> for CodeSharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Compute inverse of polynomial `a` in GF(2)[X]/(X^r - 1) using Extended Euclidean Algorithm in GF(2)[X]
pub fn invert_qc_poly(a: &QcPoly) -> Option<QcPoly> {
    let r = a.r;
    // Polynomials in GF(2)[X] represented as Vec<u8> (degree-indexed)
    let mut rem0 = vec![0u8; r + 2];
    rem0[0] = 1; // X^r + 1
    rem0[r] = 1;

    let mut rem1 = vec![0u8; r + 2];
    for i in 0..r {
        rem1[i] = a.get_bit(i);
    }

    let mut aux0 = vec![0u8; r + 2];
    let mut aux1 = vec![0u8; r + 2];
    aux1[0] = 1; // 1

    fn deg(p: &[u8]) -> Option<usize> {
        (0..p.len()).rev().find(|&i| p[i] == 1)
    }

    while let Some(d1) = deg(&rem1) {
        if d1 == 0 {
            // rem1 is 1 -> gcd is 1!
            let mut inv = QcPoly::zero(r);
            for i in 0..r {
                if aux1[i] == 1 {
                    inv.set_bit(i);
                }
            }
            return Some(inv);
        }

        let d0 = match deg(&rem0) {
            Some(d) => d,
            None => break,
        };

        if d0 < d1 {
            std::mem::swap(&mut rem0, &mut rem1);
            std::mem::swap(&mut aux0, &mut aux1);
            continue;
        }

        let shift = d0 - d1;
        for i in 0..=d1 {
            if rem1[i] == 1 {
                rem0[i + shift] ^= 1;
            }
        }
        for i in 0..r {
            if aux1[i] == 1 {
                let target = (i + shift) % r;
                aux0[target] ^= 1;
            }
        }
    }

    None
}

/// Bit-flipping decoder for QC-MDPC
pub fn bit_flipping_decode(
    s: &QcPoly,
    h0: &QcPoly,
    h1: &QcPoly,
    max_iters: usize,
) -> Result<(QcPoly, QcPoly), QryptError> {
    let r = s.r;
    let mut e0 = QcPoly::zero(r);
    let mut e1 = QcPoly::zero(r);
    let mut cur_s = s.clone();

    for _ in 0..max_iters {
        if cur_s.weight() == 0 {
            break;
        }

        // Compute unsatisfied parity checks (counters) for each bit of e0 and e1
        let mut upc0 = vec![0usize; r];
        let mut upc1 = vec![0usize; r];
        let mut max_upc = 0;

        for i in 0..r {
            // upc0[i] = count of j such that cur_s has bit (i + j) % r set and h0 has bit j set
            let mut c0 = 0;
            let mut c1 = 0;
            for j in 0..r {
                if h0.get_bit(j) == 1 && cur_s.get_bit((i + j) % r) == 1 {
                    c0 += 1;
                }
                if h1.get_bit(j) == 1 && cur_s.get_bit((i + j) % r) == 1 {
                    c1 += 1;
                }
            }
            upc0[i] = c0;
            upc1[i] = c1;
            if c0 > max_upc {
                max_upc = c0;
            }
            if c1 > max_upc {
                max_upc = c1;
            }
        }

        let threshold = if max_upc > 2 { max_upc - 1 } else { max_upc };
        if threshold == 0 {
            break;
        }

        // Flip bits exceeding threshold
        for i in 0..r {
            if upc0[i] >= threshold {
                e0.flip_bit(i);
            }
            if upc1[i] >= threshold {
                e1.flip_bit(i);
            }
        }

        // Recompute syndrome: cur_s = s + e0*h0 + e1*h1
        let e0_h0 = e0.mul(h0);
        let e1_h1 = e1.mul(h1);
        cur_s = s.add(&e0_h0).add(&e1_h1);
    }

    if cur_s.weight() == 0 {
        Ok((e0, e1))
    } else {
        Err(QryptError::DecryptionFailure)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CodeKem;

fn hash_public_key(pk: &CodePublicKey) -> [u8; 32] {
    let bytes = CodeKem::serialize_public_key(pk);
    let mut hasher = Shake256::default();
    hasher.update(&bytes);
    let mut out = [0u8; 32];
    hasher.finalize_xof().read(&mut out);
    out
}

impl Kem for CodeKem {
    type PublicKey = CodePublicKey;
    type SecretKey = CodeSecretKey;
    type Ciphertext = CodeCiphertext;
    type SharedSecret = CodeSharedSecret;

    fn algorithm_name() -> &'static str {
        "QRYPTEX-Code-QCMDPC-KEM-Level1"
    }

    fn keygen<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), QryptError> {
        let mut z = [0u8; 32];
        rng.fill_bytes(&mut z);

        let mut h0;
        let mut h1;
        let inv_h0;

        loop {
            // Sample sparse polynomials with odd weight w/2 = 7 to guarantee invertibility
            h0 = QcPoly::sample_sparse(QC_R, QC_W / 2 - 1, rng);
            h0.set_bit(0); // Ensure odd weight
            h1 = QcPoly::sample_sparse(QC_R, QC_W / 2 - 1, rng);
            h1.set_bit(0);

            if let Some(inv) = invert_qc_poly(&h0) {
                inv_h0 = inv;
                break;
            }
        }

        // Public key g = inv(h0) * h1
        let g = inv_h0.mul(&h1);
        let pk = CodePublicKey { g };
        let hpk = hash_public_key(&pk);

        let sk = CodeSecretKey {
            h0,
            h1,
            pk: pk.clone(),
            hpk,
            z,
        };

        Ok((pk, sk))
    }

    fn encapsulate<R: RngCore + CryptoRng>(
        pk: &Self::PublicKey,
        rng: &mut R,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), QryptError> {
        // Sample error vector (e0, e1) of weight t/2 each
        let e0 = QcPoly::sample_sparse(QC_R, QC_T / 2, rng);
        let e1 = QcPoly::sample_sparse(QC_R, QC_T / 2, rng);

        // Ciphertext syndrome s = e0 + e1 * g
        let e1_g = e1.mul(&pk.g);
        let syndrome = e0.add(&e1_g);

        let ct = CodeCiphertext { syndrome };
        let ct_bytes = Self::serialize_ciphertext(&ct);

        // Derive shared secret = SHAKE256(e0 || e1 || H(ct))
        let mut hasher = Shake256::default();
        hasher.update(&e0.to_bytes());
        hasher.update(&e1.to_bytes());
        hasher.update(&ct_bytes);

        let mut ss = [0u8; 32];
        hasher.finalize_xof().read(&mut ss);

        Ok((ct, CodeSharedSecret(ss)))
    }

    fn decapsulate(
        sk: &Self::SecretKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, QryptError> {
        // Syndrome for decoding: s_h = ct.syndrome * h0 = (e0 + e1 * inv(h0)*h1) * h0 = e0*h0 + e1*h1
        let s_h = ct.syndrome.mul(&sk.h0);

        let ct_bytes = Self::serialize_ciphertext(ct);

        let mut h_ct = [0u8; 32];
        let mut ct_hasher = Shake256::default();
        ct_hasher.update(&ct_bytes);
        ct_hasher.finalize_xof().read(&mut h_ct);

        // Decode using bit-flipping decoder
        let decode_result = bit_flipping_decode(&s_h, &sk.h0, &sk.h1, QC_MAX_ITERS);

        let mut valid_ss = [0u8; 32];
        let is_valid = match decode_result {
            Ok((e0, e1)) => {
                // Verify weight and re-encode
                let weight_ok = (e0.weight() + e1.weight()) == QC_T;
                let recomputed_s = e0.add(&e1.mul(&sk.pk.g));
                let syndrome_match = recomputed_s == ct.syndrome;

                if weight_ok && syndrome_match {
                    let mut hasher = Shake256::default();
                    hasher.update(&e0.to_bytes());
                    hasher.update(&e1.to_bytes());
                    hasher.update(&ct_bytes);
                    hasher.finalize_xof().read(&mut valid_ss);
                    1u8
                } else {
                    0u8
                }
            }
            Err(_) => 0u8,
        };

        let mut reject_ss = [0u8; 32];
        let mut rej_hasher = Shake256::default();
        rej_hasher.update(&sk.z);
        rej_hasher.update(&h_ct);
        rej_hasher.finalize_xof().read(&mut reject_ss);

        let mut final_ss = reject_ss;
        ct_conditional_copy(Choice::from(is_valid), &mut final_ss, &valid_ss);

        Ok(CodeSharedSecret(final_ss))
    }

    fn serialize_public_key(pk: &Self::PublicKey) -> Vec<u8> {
        pk.g.to_bytes()
    }

    fn deserialize_public_key(bytes: &[u8]) -> Result<Self::PublicKey, QryptError> {
        let expected = QC_R.div_ceil(8);
        if bytes.len() != expected {
            return Err(QryptError::InvalidKeyLength);
        }
        let g = QcPoly::from_bytes(bytes, QC_R);
        Ok(CodePublicKey { g })
    }

    fn serialize_secret_key(sk: &Self::SecretKey) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&sk.h0.to_bytes());
        bytes.extend_from_slice(&sk.h1.to_bytes());
        bytes.extend_from_slice(&Self::serialize_public_key(&sk.pk));
        bytes.extend_from_slice(&sk.hpk);
        bytes.extend_from_slice(&sk.z);
        bytes
    }

    fn deserialize_secret_key(bytes: &[u8]) -> Result<Self::SecretKey, QryptError> {
        let poly_len = QC_R.div_ceil(8);
        let expected = 3 * poly_len + 32 + 32;
        if bytes.len() != expected {
            return Err(QryptError::InvalidKeyLength);
        }
        let h0 = QcPoly::from_bytes(&bytes[0..poly_len], QC_R);
        let h1 = QcPoly::from_bytes(&bytes[poly_len..2 * poly_len], QC_R);
        let pk = Self::deserialize_public_key(&bytes[2 * poly_len..3 * poly_len])?;
        let mut hpk = [0u8; 32];
        hpk.copy_from_slice(&bytes[3 * poly_len..3 * poly_len + 32]);
        let mut z = [0u8; 32];
        z.copy_from_slice(&bytes[3 * poly_len + 32..3 * poly_len + 64]);

        Ok(CodeSecretKey { h0, h1, pk, hpk, z })
    }

    fn serialize_ciphertext(ct: &Self::Ciphertext) -> Vec<u8> {
        ct.syndrome.to_bytes()
    }

    fn deserialize_ciphertext(bytes: &[u8]) -> Result<Self::Ciphertext, QryptError> {
        let expected = QC_R.div_ceil(8);
        if bytes.len() != expected {
            return Err(QryptError::InvalidCiphertextLength);
        }
        let syndrome = QcPoly::from_bytes(bytes, QC_R);
        Ok(CodeCiphertext { syndrome })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qrypt_core::csprng::DeterministicDrbg;

    #[test]
    fn test_code_kem_roundtrip() {
        let mut rng = DeterministicDrbg::from_seed([201u8; 32]);
        let (pk, sk) = CodeKem::keygen(&mut rng).unwrap();

        let (ct, ss_enc) = CodeKem::encapsulate(&pk, &mut rng).unwrap();
        let ss_dec = CodeKem::decapsulate(&sk, &ct).unwrap();

        assert_eq!(ss_enc, ss_dec);
    }
}

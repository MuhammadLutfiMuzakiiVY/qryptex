use crate::traits::SignatureScheme;
use qrypt_core::algebra::{barrett_reduce, Poly, N, Q};
use qrypt_core::error::QryptError;
use rand_core::{CryptoRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};
use zeroize::Zeroize;

pub const SIG_K: usize = 2; // Rank 2 for module
pub const SIG_L: usize = 2;
pub const BOUND_B: i16 = 4000; // Masking bound
pub const BETA: i16 = 10; // Challenge scaling bound
pub const TAU: usize = 5; // Number of non-zero coefficients in challenge

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LatticeSigPublicKey {
    pub seed: [u8; 32],
    pub t: [Poly; SIG_K],
}

#[derive(Clone)]
pub struct LatticeSigSecretKey {
    pub s1: [Poly; SIG_L],
    pub pk: LatticeSigPublicKey,
}

impl Zeroize for LatticeSigSecretKey {
    fn zeroize(&mut self) {
        self.s1.zeroize();
    }
}

impl Drop for LatticeSigSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LatticeSignature {
    pub z: [Poly; SIG_L],
    pub c_poly: Poly,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct LatticeSignatureScheme;

fn expand_sig_matrix(seed: &[u8; 32]) -> [[Poly; SIG_L]; SIG_K] {
    let mut matrix = [[Poly::ZERO; SIG_L]; SIG_K];
    for i in 0..SIG_K {
        for j in 0..SIG_L {
            let mut hasher = Shake128::default();
            hasher.update(seed);
            hasher.update(&[i as u8, j as u8]);
            let mut reader = hasher.finalize_xof();

            let mut coeffs = [0i16; N];
            let mut ctr = 0;
            let mut buf = [0u8; 3];
            while ctr < N {
                reader.read(&mut buf);
                let d1 = (buf[0] as u16 | ((buf[1] as u16 & 0x0F) << 8)) as i16;
                let d2 = ((buf[1] as u16 >> 4) | ((buf[2] as u16) << 4)) as i16;
                if d1 < Q {
                    coeffs[ctr] = d1;
                    ctr += 1;
                }
                if ctr < N && d2 < Q {
                    coeffs[ctr] = d2;
                    ctr += 1;
                }
            }
            matrix[i][j] = Poly { coeffs };
        }
    }
    matrix
}

/// Sample small secret polynomial in [-2, 2]
fn sample_small_poly(seed: &[u8; 32], nonce: u8) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    hasher.update(&[nonce]);
    let mut reader = hasher.finalize_xof();
    let mut buf = [0u8; 128];
    reader.read(&mut buf);
    Poly::cbd2(&buf)
}

/// Sample masking polynomial y with coefficients uniformly in [-BOUND_B, BOUND_B]
fn sample_masking_poly<R: RngCore + CryptoRng>(rng: &mut R) -> Poly {
    let mut p = Poly::ZERO;
    let span = (2 * BOUND_B + 1) as u32;
    for i in 0..N {
        let rand_val = (rng.next_u32() % span) as i16;
        p.coeffs[i] = rand_val - BOUND_B;
    }
    p
}

/// Compute sparse challenge polynomial from message, commitment, and public key
fn sample_challenge(msg: &[u8], w: &[Poly; SIG_K], pk_bytes: &[u8]) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(msg);
    for poly in w {
        hasher.update(&poly.to_bytes_12());
    }
    hasher.update(pk_bytes);
    let mut reader = hasher.finalize_xof();

    let mut c = Poly::ZERO;
    let mut signs = [0u8; 4];
    reader.read(&mut signs);
    let sign_bits = u32::from_le_bytes(signs);

    let mut pos_buf = [0u8; 1];
    let mut set_count = 0;
    while set_count < TAU {
        reader.read(&mut pos_buf);
        let idx = pos_buf[0] as usize;
        if idx < N && c.coeffs[idx] == 0 {
            let sign = if (sign_bits >> set_count) & 1 == 1 {
                1i16
            } else {
                -1i16
            };
            c.coeffs[idx] = sign;
            set_count += 1;
        }
    }
    c
}

/// Exact integer polynomial multiplication in Z[X]/(X^256 + 1) for sparse challenge c and small poly s
fn poly_mul_small(c: &Poly, s: &Poly) -> Poly {
    let mut res = Poly::ZERO;
    for i in 0..N {
        let ci = c.coeffs[i];
        if ci != 0 {
            for j in 0..N {
                if i + j < N {
                    res.coeffs[i + j] += ci * s.coeffs[j];
                } else {
                    res.coeffs[i + j - N] -= ci * s.coeffs[j];
                }
            }
        }
    }
    res
}

/// Exact polynomial multiplication in R_q = Z_q[X]/(X^256 + 1) for sparse challenge c and public poly t
fn poly_mul_challenge_t(c: &Poly, t: &Poly) -> Poly {
    let mut res = Poly::ZERO;
    for i in 0..N {
        let ci = c.coeffs[i];
        if ci != 0 {
            for j in 0..N {
                if i + j < N {
                    res.coeffs[i + j] = barrett_reduce(res.coeffs[i + j] + ci * t.coeffs[j]);
                } else {
                    res.coeffs[i + j - N] =
                        barrett_reduce(res.coeffs[i + j - N] - ci * t.coeffs[j]);
                }
            }
        }
    }
    res
}

impl SignatureScheme for LatticeSignatureScheme {
    type PublicKey = LatticeSigPublicKey;
    type SecretKey = LatticeSigSecretKey;
    type Signature = LatticeSignature;

    fn algorithm_name() -> &'static str {
        "QRYPTEX-Lattice-FiatShamir-Signature-Level1"
    }

    fn keygen<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), QryptError> {
        let mut seed = [0u8; 32];
        let mut sec_seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        rng.fill_bytes(&mut sec_seed);

        let matrix = expand_sig_matrix(&seed);

        let mut s1 = [Poly::ZERO; SIG_L];
        for i in 0..SIG_L {
            s1[i] = sample_small_poly(&sec_seed, i as u8);
        }

        let mut s1_ntt = s1;
        for poly in s1_ntt.iter_mut() {
            poly.ntt();
        }

        // t = A * s1 mod q
        let mut t = [Poly::ZERO; SIG_K];
        for i in 0..SIG_K {
            let mut acc = Poly::ZERO;
            for j in 0..SIG_L {
                let prod = matrix[i][j].mul_ntt(&s1_ntt[j]);
                acc = acc.add(&prod);
            }
            acc.inv_ntt();
            acc.freeze();
            t[i] = acc;
        }

        let pk = LatticeSigPublicKey { seed, t };
        let sk = LatticeSigSecretKey { s1, pk: pk.clone() };

        Ok((pk, sk))
    }

    fn sign<R: RngCore + CryptoRng>(
        sk: &Self::SecretKey,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, QryptError> {
        let matrix = expand_sig_matrix(&sk.pk.seed);
        let pk_bytes = Self::serialize_public_key(&sk.pk);

        for _ in 0..512 {
            // 1. Sample masking vector y uniformly in [-BOUND_B, BOUND_B]
            let mut y = [Poly::ZERO; SIG_L];
            for i in 0..SIG_L {
                y[i] = sample_masking_poly(rng);
            }

            // 2. Compute commitment w = A * y mod q
            let mut y_ntt = y;
            for poly in y_ntt.iter_mut() {
                poly.ntt();
            }
            let mut w = [Poly::ZERO; SIG_K];
            for i in 0..SIG_K {
                let mut acc = Poly::ZERO;
                for j in 0..SIG_L {
                    let prod = matrix[i][j].mul_ntt(&y_ntt[j]);
                    acc = acc.add(&prod);
                }
                acc.inv_ntt();
                acc.freeze();
                w[i] = acc;
            }

            // 3. Challenge c = H(msg || w || pk)
            let c_poly = sample_challenge(msg, &w, &pk_bytes);

            // 4. Response z = y + c * s1
            let mut z = [Poly::ZERO; SIG_L];
            let mut reject = false;

            for i in 0..SIG_L {
                let c_s1 = poly_mul_small(&c_poly, &sk.s1[i]);
                for n in 0..N {
                    let val = y[i].coeffs[n] + c_s1.coeffs[n];
                    if val.abs() >= (BOUND_B - BETA) {
                        reject = true;
                        break;
                    }
                    z[i].coeffs[n] = val;
                }
                if reject {
                    break;
                }
            }

            if !reject {
                return Ok(LatticeSignature { z, c_poly });
            }
        }

        Err(QryptError::RngFailure)
    }

    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> Result<bool, QryptError> {
        // 1. Check norm bound on signature z
        for i in 0..SIG_L {
            for n in 0..N {
                if sig.z[i].coeffs[n].abs() >= (BOUND_B - BETA) {
                    return Ok(false);
                }
            }
        }

        let matrix = expand_sig_matrix(&pk.seed);
        let pk_bytes = Self::serialize_public_key(pk);

        // 2. Recompute w' = A * z - c * t mod q
        let mut z_ntt = sig.z;
        for poly in z_ntt.iter_mut() {
            poly.ntt();
        }

        let mut w_prime = [Poly::ZERO; SIG_K];
        for i in 0..SIG_K {
            let mut acc = Poly::ZERO;
            for j in 0..SIG_L {
                let prod = matrix[i][j].mul_ntt(&z_ntt[j]);
                acc = acc.add(&prod);
            }
            acc.inv_ntt();

            let c_t = poly_mul_challenge_t(&sig.c_poly, &pk.t[i]);
            let diff = acc.sub(&c_t);
            let mut diff_frozen = diff;
            diff_frozen.freeze();
            w_prime[i] = diff_frozen;
        }

        // 3. Verify c' == c
        let c_prime = sample_challenge(msg, &w_prime, &pk_bytes);
        let matches = sig.c_poly.coeffs == c_prime.coeffs;
        Ok(matches)
    }

    fn serialize_public_key(pk: &Self::PublicKey) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + SIG_K * 384);
        bytes.extend_from_slice(&pk.seed);
        for poly in &pk.t {
            bytes.extend_from_slice(&poly.to_bytes_12());
        }
        bytes
    }

    fn deserialize_public_key(bytes: &[u8]) -> Result<Self::PublicKey, QryptError> {
        if bytes.len() != 32 + SIG_K * 384 {
            return Err(QryptError::InvalidKeyLength);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[0..32]);
        let mut t = [Poly::ZERO; SIG_K];
        for i in 0..SIG_K {
            let offset = 32 + i * 384;
            let p_bytes: &[u8; 384] = bytes[offset..offset + 384].try_into().unwrap();
            t[i] = Poly::from_bytes_12(p_bytes);
        }
        Ok(LatticeSigPublicKey { seed, t })
    }

    fn serialize_secret_key(sk: &Self::SecretKey) -> Vec<u8> {
        let mut bytes = Vec::new();
        for poly in &sk.s1 {
            bytes.extend_from_slice(&poly.to_bytes_12());
        }
        bytes.extend_from_slice(&Self::serialize_public_key(&sk.pk));
        bytes
    }

    fn deserialize_secret_key(bytes: &[u8]) -> Result<Self::SecretKey, QryptError> {
        let expected = SIG_L * 384 + (32 + SIG_K * 384);
        if bytes.len() != expected {
            return Err(QryptError::InvalidKeyLength);
        }
        let mut s1 = [Poly::ZERO; SIG_L];
        for i in 0..SIG_L {
            let offset = i * 384;
            let p_bytes: &[u8; 384] = bytes[offset..offset + 384].try_into().unwrap();
            s1[i] = Poly::from_bytes_12(p_bytes);
        }
        let pk_offset = SIG_L * 384;
        let pk = Self::deserialize_public_key(&bytes[pk_offset..])?;
        Ok(LatticeSigSecretKey { s1, pk })
    }

    fn serialize_signature(sig: &Self::Signature) -> Vec<u8> {
        let mut bytes = Vec::new();
        for poly in &sig.z {
            // Encode z coefficients as 16-bit integers
            for c in poly.coeffs {
                bytes.extend_from_slice(&c.to_le_bytes());
            }
        }
        for c in sig.c_poly.coeffs {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        bytes
    }

    fn deserialize_signature(bytes: &[u8]) -> Result<Self::Signature, QryptError> {
        let expected = (SIG_L + 1) * N * 2;
        if bytes.len() != expected {
            return Err(QryptError::InvalidSignatureLength);
        }
        let mut z = [Poly::ZERO; SIG_L];
        let mut offset = 0;
        for i in 0..SIG_L {
            for n in 0..N {
                z[i].coeffs[n] = i16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
                offset += 2;
            }
        }
        let mut c_poly = Poly::ZERO;
        for n in 0..N {
            c_poly.coeffs[n] = i16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap());
            offset += 2;
        }
        Ok(LatticeSignature { z, c_poly })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qrypt_core::csprng::DeterministicDrbg;

    #[test]
    fn test_lattice_sig_roundtrip() {
        let mut rng = DeterministicDrbg::from_seed([41u8; 32]);
        let (pk, sk) = LatticeSignatureScheme::keygen(&mut rng).unwrap();

        let msg = b"QRYPTEX Research Framework Lattice Signature Test";
        let sig = LatticeSignatureScheme::sign(&sk, msg, &mut rng).unwrap();
        let valid = LatticeSignatureScheme::verify(&pk, msg, &sig).unwrap();
        assert!(valid);
    }
}

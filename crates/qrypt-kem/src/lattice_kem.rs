use crate::traits::Kem;
use qrypt_core::algebra::{Poly, N, Q};
use qrypt_core::constant_time::{ct_conditional_copy, ct_eq_bytes};
use qrypt_core::error::QryptError;
use rand_core::{CryptoRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};
use subtle::Choice;
use zeroize::Zeroize;

pub const K: usize = 2; // Rank 2 for Module-LWE Level 1

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LatticePublicKey {
    pub seed: [u8; 32],
    pub t: [Poly; K],
}

#[derive(Clone)]
pub struct LatticeSecretKey {
    pub s: [Poly; K],
    pub pk: LatticePublicKey,
    pub hpk: [u8; 32],
    pub z: [u8; 32], // Implicit rejection key
}

impl Zeroize for LatticeSecretKey {
    fn zeroize(&mut self) {
        self.s.zeroize();
        self.hpk.zeroize();
        self.z.zeroize();
    }
}

impl Drop for LatticeSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LatticeCiphertext {
    pub u: [Poly; K],
    pub v: Poly,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LatticeSharedSecret(pub [u8; 32]);

impl Zeroize for LatticeSharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for LatticeSharedSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl AsRef<[u8]> for LatticeSharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct LatticeKem;

/// Expand 32-byte seed into k x k polynomial matrix in NTT domain
fn expand_matrix(seed: &[u8; 32]) -> [[Poly; K]; K] {
    let mut matrix = [[Poly::ZERO; K]; K];
    for i in 0..K {
        for j in 0..K {
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

/// Sample noise polynomial from seed + nonce using SHAKE256 + CBD2
fn sample_noise(seed: &[u8; 32], nonce: u8) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    hasher.update(&[nonce]);
    let mut reader = hasher.finalize_xof();
    let mut buf = [0u8; 128];
    reader.read(&mut buf);
    Poly::cbd2(&buf)
}

fn hash_public_key(pk: &LatticePublicKey) -> [u8; 32] {
    let bytes = LatticeKem::serialize_public_key(pk);
    let mut hasher = Shake256::default();
    hasher.update(&bytes);
    let mut out = [0u8; 32];
    hasher.finalize_xof().read(&mut out);
    out
}

impl Kem for LatticeKem {
    type PublicKey = LatticePublicKey;
    type SecretKey = LatticeSecretKey;
    type Ciphertext = LatticeCiphertext;
    type SharedSecret = LatticeSharedSecret;

    fn algorithm_name() -> &'static str {
        "QRYPTEX-Lattice-MLWE-KEM-Level1"
    }

    fn keygen<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), QryptError> {
        let mut seed = [0u8; 32];
        let mut noise_seed = [0u8; 32];
        let mut z = [0u8; 32];
        rng.fill_bytes(&mut seed);
        rng.fill_bytes(&mut noise_seed);
        rng.fill_bytes(&mut z);

        let matrix = expand_matrix(&seed);

        let mut s = [Poly::ZERO; K];
        let mut e = [Poly::ZERO; K];
        for i in 0..K {
            s[i] = sample_noise(&noise_seed, i as u8);
            e[i] = sample_noise(&noise_seed, (K + i) as u8);
        }

        // Convert s to NTT domain
        let mut s_ntt = s;
        for poly in s_ntt.iter_mut() {
            poly.ntt();
        }

        // Compute t = A * s + e
        let mut t = [Poly::ZERO; K];
        for i in 0..K {
            let mut acc = Poly::ZERO;
            for j in 0..K {
                let prod = matrix[i][j].mul_ntt(&s_ntt[j]);
                acc = acc.add(&prod);
            }
            acc.inv_ntt();
            t[i] = acc.add(&e[i]);
            t[i].freeze();
        }

        let pk = LatticePublicKey { seed, t };
        let hpk = hash_public_key(&pk);

        let sk = LatticeSecretKey { s, pk: pk.clone(), hpk, z };
        Ok((pk, sk))
    }

    fn encapsulate<R: RngCore + CryptoRng>(
        pk: &Self::PublicKey,
        rng: &mut R,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), QryptError> {
        let mut msg = [0u8; 32];
        rng.fill_bytes(&mut msg);

        let hpk = hash_public_key(pk);

        // Derive coins = SHAKE256(msg || hpk)
        let mut hasher = Shake256::default();
        hasher.update(&msg);
        hasher.update(&hpk);
        let mut coins = [0u8; 64];
        hasher.finalize_xof().read(&mut coins);

        let coins_seed: [u8; 32] = coins[0..32].try_into().unwrap();
        let kr: [u8; 32] = coins[32..64].try_into().unwrap();

        let matrix = expand_matrix(&pk.seed);

        // Sample r, e1, e2 from coins
        let mut r = [Poly::ZERO; K];
        let mut e1 = [Poly::ZERO; K];
        for i in 0..K {
            r[i] = sample_noise(&coins_seed, i as u8);
            e1[i] = sample_noise(&coins_seed, (K + i) as u8);
        }
        let e2 = sample_noise(&coins_seed, (2 * K) as u8);

        // r in NTT domain
        let mut r_ntt = r;
        for poly in r_ntt.iter_mut() {
            poly.ntt();
        }

        // u = A^T * r + e1
        let mut u = [Poly::ZERO; K];
        for i in 0..K {
            let mut acc = Poly::ZERO;
            for j in 0..K {
                // A^T[i][j] = A[j][i]
                let prod = matrix[j][i].mul_ntt(&r_ntt[j]);
                acc = acc.add(&prod);
            }
            acc.inv_ntt();
            let mut ui = acc.add(&e1[i]);
            ui.freeze();
            u[i] = ui;
        }

        // v = t^T * r + e2 + Encode(msg)
        let mut t_ntt = pk.t;
        for poly in t_ntt.iter_mut() {
            poly.ntt();
        }
        let mut v_acc = Poly::ZERO;
        for i in 0..K {
            let prod = t_ntt[i].mul_ntt(&r_ntt[i]);
            v_acc = v_acc.add(&prod);
        }
        v_acc.inv_ntt();
        let msg_poly = Poly::from_msg_bytes(&msg);
        let mut v = v_acc.add(&e2).add(&msg_poly);
        v.freeze();

        let ct = LatticeCiphertext { u, v };
        let ct_bytes = Self::serialize_ciphertext(&ct);

        // Shared Secret = SHAKE256(kr || H(ct))
        let mut h_ct = [0u8; 32];
        let mut ct_hasher = Shake256::default();
        ct_hasher.update(&ct_bytes);
        ct_hasher.finalize_xof().read(&mut h_ct);

        let mut ss_hasher = Shake256::default();
        ss_hasher.update(&kr);
        ss_hasher.update(&h_ct);
        let mut ss = [0u8; 32];
        ss_hasher.finalize_xof().read(&mut ss);

        Ok((ct, LatticeSharedSecret(ss)))
    }

    fn decapsulate(
        sk: &Self::SecretKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, QryptError> {
        // Compute m' = Decode(v - s^T * u)
        let mut s_ntt = sk.s;
        for poly in s_ntt.iter_mut() {
            poly.ntt();
        }
        let mut u_ntt = ct.u;
        for poly in u_ntt.iter_mut() {
            poly.ntt();
        }
        let mut s_dot_u = Poly::ZERO;
        for i in 0..K {
            let prod = s_ntt[i].mul_ntt(&u_ntt[i]);
            s_dot_u = s_dot_u.add(&prod);
        }
        s_dot_u.inv_ntt();

        let diff = ct.v.sub(&s_dot_u);
        let msg_prime = diff.to_msg_bytes();

        // Re-derive coins' = SHAKE256(msg' || hpk)
        let mut hasher = Shake256::default();
        hasher.update(&msg_prime);
        hasher.update(&sk.hpk);
        let mut coins = [0u8; 64];
        hasher.finalize_xof().read(&mut coins);

        let coins_seed: [u8; 32] = coins[0..32].try_into().unwrap();
        let kr_prime: [u8; 32] = coins[32..64].try_into().unwrap();

        // Re-encrypt
        let matrix = expand_matrix(&sk.pk.seed);
        let mut r = [Poly::ZERO; K];
        let mut e1 = [Poly::ZERO; K];
        for i in 0..K {
            r[i] = sample_noise(&coins_seed, i as u8);
            e1[i] = sample_noise(&coins_seed, (K + i) as u8);
        }
        let e2 = sample_noise(&coins_seed, (2 * K) as u8);

        let mut r_ntt = r;
        for poly in r_ntt.iter_mut() {
            poly.ntt();
        }

        let mut u_prime = [Poly::ZERO; K];
        for i in 0..K {
            let mut acc = Poly::ZERO;
            for j in 0..K {
                let prod = matrix[j][i].mul_ntt(&r_ntt[j]);
                acc = acc.add(&prod);
            }
            acc.inv_ntt();
            let mut ui = acc.add(&e1[i]);
            ui.freeze();
            u_prime[i] = ui;
        }

        let mut t_ntt = sk.pk.t;
        for poly in t_ntt.iter_mut() {
            poly.ntt();
        }
        let mut v_acc = Poly::ZERO;
        for i in 0..K {
            let prod = t_ntt[i].mul_ntt(&r_ntt[i]);
            v_acc = v_acc.add(&prod);
        }
        v_acc.inv_ntt();
        let msg_prime_poly = Poly::from_msg_bytes(&msg_prime);
        let mut v_prime = v_acc.add(&e2).add(&msg_prime_poly);
        v_prime.freeze();

        let ct_prime = LatticeCiphertext { u: u_prime, v: v_prime };

        let ct_bytes = Self::serialize_ciphertext(ct);
        let ct_prime_bytes = Self::serialize_ciphertext(&ct_prime);

        // Constant time comparison of ct and ct'
        let match_choice: Choice = ct_eq_bytes(&ct_bytes, &ct_prime_bytes);

        // Calculate both valid and reject shared secrets in constant-time
        let mut h_ct = [0u8; 32];
        let mut ct_hasher = Shake256::default();
        ct_hasher.update(&ct_bytes);
        ct_hasher.finalize_xof().read(&mut h_ct);

        let mut valid_ss = [0u8; 32];
        let mut ss_hasher = Shake256::default();
        ss_hasher.update(&kr_prime);
        ss_hasher.update(&h_ct);
        ss_hasher.finalize_xof().read(&mut valid_ss);

        let mut reject_ss = [0u8; 32];
        let mut rej_hasher = Shake256::default();
        rej_hasher.update(&sk.z);
        rej_hasher.update(&h_ct);
        rej_hasher.finalize_xof().read(&mut reject_ss);

        let mut final_ss = reject_ss;
        ct_conditional_copy(match_choice, &mut final_ss, &valid_ss);

        Ok(LatticeSharedSecret(final_ss))
    }

    fn serialize_public_key(pk: &Self::PublicKey) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + K * 384);
        bytes.extend_from_slice(&pk.seed);
        for poly in &pk.t {
            bytes.extend_from_slice(&poly.to_bytes_12());
        }
        bytes
    }

    fn deserialize_public_key(bytes: &[u8]) -> Result<Self::PublicKey, QryptError> {
        if bytes.len() != 32 + K * 384 {
            return Err(QryptError::InvalidKeyLength);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[0..32]);
        let mut t = [Poly::ZERO; K];
        for i in 0..K {
            let offset = 32 + i * 384;
            let p_bytes: &[u8; 384] = bytes[offset..offset + 384].try_into().unwrap();
            t[i] = Poly::from_bytes_12(p_bytes);
        }
        Ok(LatticePublicKey { seed, t })
    }

    fn serialize_secret_key(sk: &Self::SecretKey) -> Vec<u8> {
        let mut bytes = Vec::new();
        for poly in &sk.s {
            bytes.extend_from_slice(&poly.to_bytes_12());
        }
        bytes.extend_from_slice(&Self::serialize_public_key(&sk.pk));
        bytes.extend_from_slice(&sk.hpk);
        bytes.extend_from_slice(&sk.z);
        bytes
    }

    fn deserialize_secret_key(bytes: &[u8]) -> Result<Self::SecretKey, QryptError> {
        let expected_len = K * 384 + (32 + K * 384) + 32 + 32;
        if bytes.len() != expected_len {
            return Err(QryptError::InvalidKeyLength);
        }
        let mut s = [Poly::ZERO; K];
        for i in 0..K {
            let offset = i * 384;
            let p_bytes: &[u8; 384] = bytes[offset..offset + 384].try_into().unwrap();
            s[i] = Poly::from_bytes_12(p_bytes);
        }
        let pk_offset = K * 384;
        let pk = Self::deserialize_public_key(&bytes[pk_offset..pk_offset + 32 + K * 384])?;
        let hpk_offset = pk_offset + 32 + K * 384;
        let mut hpk = [0u8; 32];
        hpk.copy_from_slice(&bytes[hpk_offset..hpk_offset + 32]);
        let mut z = [0u8; 32];
        z.copy_from_slice(&bytes[hpk_offset + 32..hpk_offset + 64]);

        Ok(LatticeSecretKey { s, pk, hpk, z })
    }

    fn serialize_ciphertext(ct: &Self::Ciphertext) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(K * 384 + 384);
        for poly in &ct.u {
            bytes.extend_from_slice(&poly.to_bytes_12());
        }
        bytes.extend_from_slice(&ct.v.to_bytes_12());
        bytes
    }

    fn deserialize_ciphertext(bytes: &[u8]) -> Result<Self::Ciphertext, QryptError> {
        if bytes.len() != (K + 1) * 384 {
            return Err(QryptError::InvalidCiphertextLength);
        }
        let mut u = [Poly::ZERO; K];
        for i in 0..K {
            let offset = i * 384;
            let p_bytes: &[u8; 384] = bytes[offset..offset + 384].try_into().unwrap();
            u[i] = Poly::from_bytes_12(p_bytes);
        }
        let v_offset = K * 384;
        let v_bytes: &[u8; 384] = bytes[v_offset..v_offset + 384].try_into().unwrap();
        let v = Poly::from_bytes_12(v_bytes);
        Ok(LatticeCiphertext { u, v })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qrypt_core::csprng::DeterministicDrbg;

    #[test]
    fn test_lattice_kem_roundtrip() {
        let mut rng = DeterministicDrbg::from_seed([101u8; 32]);
        let (pk, sk) = LatticeKem::keygen(&mut rng).unwrap();

        let (ct, ss_enc) = LatticeKem::encapsulate(&pk, &mut rng).unwrap();
        let ss_dec = LatticeKem::decapsulate(&sk, &ct).unwrap();

        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn test_lattice_kem_rejection_on_tampered_ciphertext() {
        let mut rng = DeterministicDrbg::from_seed([102u8; 32]);
        let (pk, sk) = LatticeKem::keygen(&mut rng).unwrap();

        let (mut ct, ss_enc) = LatticeKem::encapsulate(&pk, &mut rng).unwrap();
        // Tamper with ciphertext
        ct.v.coeffs[0] ^= 1;

        let ss_dec = LatticeKem::decapsulate(&sk, &ct).unwrap();
        assert_ne!(ss_enc, ss_dec); // Must yield implicit rejection key
    }
}

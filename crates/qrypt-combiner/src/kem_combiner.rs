use hkdf::Hkdf;
use qrypt_core::error::QryptError;
use qrypt_kem::traits::Kem;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use std::marker::PhantomData;
use zeroize::Zeroize;

/// Multi-Paradigm Hybrid KEM Combiner
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct QryptHybridKem<K1: Kem, K2: Kem> {
    _phantom: PhantomData<(K1, K2)>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HybridPublicKey<K1: Kem, K2: Kem> {
    pub pk1: K1::PublicKey,
    pub pk2: K2::PublicKey,
}

#[derive(Clone)]
pub struct HybridSecretKey<K1: Kem, K2: Kem> {
    pub sk1: K1::SecretKey,
    pub sk2: K2::SecretKey,
    pub pk1: K1::PublicKey,
    pub pk2: K2::PublicKey,
}

impl<K1: Kem, K2: Kem> Zeroize for HybridSecretKey<K1, K2> {
    fn zeroize(&mut self) {
        self.sk1.zeroize();
        self.sk2.zeroize();
    }
}

impl<K1: Kem, K2: Kem> Drop for HybridSecretKey<K1, K2> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HybridCiphertext<K1: Kem, K2: Kem> {
    pub ct1: K1::Ciphertext,
    pub ct2: K2::Ciphertext,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HybridSharedSecret(pub [u8; 32]);

impl Zeroize for HybridSharedSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for HybridSharedSecret {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl AsRef<[u8]> for HybridSharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<K1: Kem, K2: Kem> Kem for QryptHybridKem<K1, K2> {
    type PublicKey = HybridPublicKey<K1, K2>;
    type SecretKey = HybridSecretKey<K1, K2>;
    type Ciphertext = HybridCiphertext<K1, K2>;
    type SharedSecret = HybridSharedSecret;

    fn algorithm_name() -> &'static str {
        "QRYPTEX-Hybrid-SplitKDF-KEM-V1"
    }

    fn keygen<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), QryptError> {
        let (pk1, sk1) = K1::keygen(rng)?;
        let (pk2, sk2) = K2::keygen(rng)?;

        let pk = HybridPublicKey {
            pk1: pk1.clone(),
            pk2: pk2.clone(),
        };

        let sk = HybridSecretKey {
            sk1,
            sk2,
            pk1,
            pk2,
        };

        Ok((pk, sk))
    }

    fn encapsulate<R: RngCore + CryptoRng>(
        pk: &Self::PublicKey,
        rng: &mut R,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), QryptError> {
        let (ct1, ss1) = K1::encapsulate(&pk.pk1, rng)?;
        let (ct2, ss2) = K2::encapsulate(&pk.pk2, rng)?;

        let pk1_bytes = K1::serialize_public_key(&pk.pk1);
        let pk2_bytes = K2::serialize_public_key(&pk.pk2);
        let ct1_bytes = K1::serialize_ciphertext(&ct1);
        let ct2_bytes = K2::serialize_ciphertext(&ct2);

        // Robust binding salt = SHAKE256(ct1 || ct2 || pk1 || pk2 || "QRYPTEX-SALT")
        let mut hasher = Shake256::default();
        hasher.update(&ct1_bytes);
        hasher.update(&ct2_bytes);
        hasher.update(&pk1_bytes);
        hasher.update(&pk2_bytes);
        hasher.update(b"QRYPTEX-KEM-SALT-V1");
        let mut salt = [0u8; 32];
        hasher.finalize_xof().read(&mut salt);

        // IKM = ss1 || ss2
        let mut ikm = Vec::new();
        ikm.extend_from_slice(ss1.as_ref());
        ikm.extend_from_slice(ss2.as_ref());

        // Derive final combined shared secret via HKDF-SHA256
        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = [0u8; 32];
        hk.expand(b"QRYPTEX-HYBRID-KEM-FINAL-SECRET-V1", &mut okm)
            .map_err(|_| QryptError::DecapsulationFailed)?;

        let ct = HybridCiphertext { ct1, ct2 };
        Ok((ct, HybridSharedSecret(okm)))
    }

    fn decapsulate(
        sk: &Self::SecretKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, QryptError> {
        // Execute both decapsulations unconditionally to eliminate timing leakage
        let res1 = K1::decapsulate(&sk.sk1, &ct.ct1);
        let res2 = K2::decapsulate(&sk.sk2, &ct.ct2);

        let ss1 = res1?;
        let ss2 = res2?;

        let pk1_bytes = K1::serialize_public_key(&sk.pk1);
        let pk2_bytes = K2::serialize_public_key(&sk.pk2);
        let ct1_bytes = K1::serialize_ciphertext(&ct.ct1);
        let ct2_bytes = K2::serialize_ciphertext(&ct.ct2);

        let mut hasher = Shake256::default();
        hasher.update(&ct1_bytes);
        hasher.update(&ct2_bytes);
        hasher.update(&pk1_bytes);
        hasher.update(&pk2_bytes);
        hasher.update(b"QRYPTEX-KEM-SALT-V1");
        let mut salt = [0u8; 32];
        hasher.finalize_xof().read(&mut salt);

        let mut ikm = Vec::new();
        ikm.extend_from_slice(ss1.as_ref());
        ikm.extend_from_slice(ss2.as_ref());

        let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut okm = [0u8; 32];
        hk.expand(b"QRYPTEX-HYBRID-KEM-FINAL-SECRET-V1", &mut okm)
            .map_err(|_| QryptError::DecapsulationFailed)?;

        Ok(HybridSharedSecret(okm))
    }

    fn serialize_public_key(pk: &Self::PublicKey) -> Vec<u8> {
        let b1 = K1::serialize_public_key(&pk.pk1);
        let b2 = K2::serialize_public_key(&pk.pk2);
        let mut out = Vec::with_capacity(8 + b1.len() + b2.len());
        out.extend_from_slice(&(b1.len() as u32).to_be_bytes());
        out.extend_from_slice(&b1);
        out.extend_from_slice(&(b2.len() as u32).to_be_bytes());
        out.extend_from_slice(&b2);
        out
    }

    fn deserialize_public_key(bytes: &[u8]) -> Result<Self::PublicKey, QryptError> {
        if bytes.len() < 8 {
            return Err(QryptError::InvalidKeyLength);
        }
        let len1 = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        if bytes.len() < 4 + len1 + 4 {
            return Err(QryptError::InvalidKeyLength);
        }
        let b1 = &bytes[4..4 + len1];
        let len2 = u32::from_be_bytes(bytes[4 + len1..4 + len1 + 4].try_into().unwrap()) as usize;
        if bytes.len() != 4 + len1 + 4 + len2 {
            return Err(QryptError::InvalidKeyLength);
        }
        let b2 = &bytes[4 + len1 + 4..];

        let pk1 = K1::deserialize_public_key(b1)?;
        let pk2 = K2::deserialize_public_key(b2)?;
        Ok(HybridPublicKey { pk1, pk2 })
    }

    fn serialize_secret_key(sk: &Self::SecretKey) -> Vec<u8> {
        let b1 = K1::serialize_secret_key(&sk.sk1);
        let b2 = K2::serialize_secret_key(&sk.sk2);
        let pb1 = K1::serialize_public_key(&sk.pk1);
        let pb2 = K2::serialize_public_key(&sk.pk2);

        let mut out = Vec::new();
        out.extend_from_slice(&(b1.len() as u32).to_be_bytes());
        out.extend_from_slice(&b1);
        out.extend_from_slice(&(b2.len() as u32).to_be_bytes());
        out.extend_from_slice(&b2);
        out.extend_from_slice(&(pb1.len() as u32).to_be_bytes());
        out.extend_from_slice(&pb1);
        out.extend_from_slice(&(pb2.len() as u32).to_be_bytes());
        out.extend_from_slice(&pb2);
        out
    }

    fn deserialize_secret_key(bytes: &[u8]) -> Result<Self::SecretKey, QryptError> {
        let mut offset = 0;
        if bytes.len() < 4 {
            return Err(QryptError::InvalidKeyLength);
        }
        let len1 = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let sk1 = K1::deserialize_secret_key(&bytes[offset..offset + len1])?;
        offset += len1;

        let len2 = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let sk2 = K2::deserialize_secret_key(&bytes[offset..offset + len2])?;
        offset += len2;

        let len_p1 = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let pk1 = K1::deserialize_public_key(&bytes[offset..offset + len_p1])?;
        offset += len_p1;

        let len_p2 = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let pk2 = K2::deserialize_public_key(&bytes[offset..offset + len_p2])?;

        Ok(HybridSecretKey {
            sk1,
            sk2,
            pk1,
            pk2,
        })
    }

    fn serialize_ciphertext(ct: &Self::Ciphertext) -> Vec<u8> {
        let b1 = K1::serialize_ciphertext(&ct.ct1);
        let b2 = K2::serialize_ciphertext(&ct.ct2);
        let mut out = Vec::with_capacity(8 + b1.len() + b2.len());
        out.extend_from_slice(&(b1.len() as u32).to_be_bytes());
        out.extend_from_slice(&b1);
        out.extend_from_slice(&(b2.len() as u32).to_be_bytes());
        out.extend_from_slice(&b2);
        out
    }

    fn deserialize_ciphertext(bytes: &[u8]) -> Result<Self::Ciphertext, QryptError> {
        if bytes.len() < 8 {
            return Err(QryptError::InvalidCiphertextLength);
        }
        let len1 = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        if bytes.len() < 4 + len1 + 4 {
            return Err(QryptError::InvalidCiphertextLength);
        }
        let b1 = &bytes[4..4 + len1];
        let len2 = u32::from_be_bytes(bytes[4 + len1..4 + len1 + 4].try_into().unwrap()) as usize;
        if bytes.len() != 4 + len1 + 4 + len2 {
            return Err(QryptError::InvalidCiphertextLength);
        }
        let b2 = &bytes[4 + len1 + 4..];

        let ct1 = K1::deserialize_ciphertext(b1)?;
        let ct2 = K2::deserialize_ciphertext(b2)?;
        Ok(HybridCiphertext { ct1, ct2 })
    }
}

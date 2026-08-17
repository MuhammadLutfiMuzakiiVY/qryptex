use qrypt_core::error::QryptError;
use qrypt_signature::traits::SignatureScheme;
use rand_core::{CryptoRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use std::marker::PhantomData;
use zeroize::Zeroize;

/// Multi-Paradigm Strong-Binding Digital Signature Combiner
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct QryptHybridSignature<S1: SignatureScheme, S2: SignatureScheme> {
    _phantom: PhantomData<(S1, S2)>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HybridSigPublicKey<S1: SignatureScheme, S2: SignatureScheme> {
    pub pk1: S1::PublicKey,
    pub pk2: S2::PublicKey,
}

#[derive(Clone)]
pub struct HybridSigSecretKey<S1: SignatureScheme, S2: SignatureScheme> {
    pub sk1: S1::SecretKey,
    pub sk2: S2::SecretKey,
    pub pk1: S1::PublicKey,
    pub pk2: S2::PublicKey,
}

impl<S1: SignatureScheme, S2: SignatureScheme> Zeroize for HybridSigSecretKey<S1, S2> {
    fn zeroize(&mut self) {
        self.sk1.zeroize();
        self.sk2.zeroize();
    }
}

impl<S1: SignatureScheme, S2: SignatureScheme> Drop for HybridSigSecretKey<S1, S2> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HybridSignature<S1: SignatureScheme, S2: SignatureScheme> {
    pub sig1: S1::Signature,
    pub sig2: S2::Signature,
}

fn compute_binding_digest<S1: SignatureScheme, S2: SignatureScheme>(
    msg: &[u8],
    sig1: &S1::Signature,
    pk1: &S1::PublicKey,
    pk2: &S2::PublicKey,
) -> [u8; 32] {
    let sig1_bytes = S1::serialize_signature(sig1);
    let pk1_bytes = S1::serialize_public_key(pk1);
    let pk2_bytes = S2::serialize_public_key(pk2);

    let mut hasher = Shake256::default();
    hasher.update(msg);
    hasher.update(&sig1_bytes);
    hasher.update(&pk1_bytes);
    hasher.update(&pk2_bytes);
    hasher.update(b"QRYPTEX-HYBRID-SIG-BINDING-V1");
    let mut out = [0u8; 32];
    hasher.finalize_xof().read(&mut out);
    out
}

impl<S1: SignatureScheme, S2: SignatureScheme> SignatureScheme for QryptHybridSignature<S1, S2> {
    type PublicKey = HybridSigPublicKey<S1, S2>;
    type SecretKey = HybridSigSecretKey<S1, S2>;
    type Signature = HybridSignature<S1, S2>;

    fn algorithm_name() -> &'static str {
        "QRYPTEX-Hybrid-StrongBinding-Signature-V1"
    }

    fn keygen<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), QryptError> {
        let (pk1, sk1) = S1::keygen(rng)?;
        let (pk2, sk2) = S2::keygen(rng)?;

        let pk = HybridSigPublicKey {
            pk1: pk1.clone(),
            pk2: pk2.clone(),
        };

        let sk = HybridSigSecretKey {
            sk1,
            sk2,
            pk1,
            pk2,
        };

        Ok((pk, sk))
    }

    fn sign<R: RngCore + CryptoRng>(
        sk: &Self::SecretKey,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, QryptError> {
        // 1. Sign original message with S1
        let sig1 = S1::sign(&sk.sk1, msg, rng)?;

        // 2. Compute strong binding digest M' = H(msg || sig1 || pk1 || pk2 || "CONTEXT")
        let binding_digest = compute_binding_digest::<S1, S2>(msg, &sig1, &sk.pk1, &sk.pk2);

        // 3. Sign binding digest with S2
        let sig2 = S2::sign(&sk.sk2, &binding_digest, rng)?;

        Ok(HybridSignature { sig1, sig2 })
    }

    fn verify(
        pk: &Self::PublicKey,
        msg: &[u8],
        sig: &Self::Signature,
    ) -> Result<bool, QryptError> {
        // 1. Verify S1 signature on original message
        let v1 = S1::verify(&pk.pk1, msg, &sig.sig1)?;
        if !v1 {
            return Ok(false);
        }

        // 2. Recompute binding digest
        let binding_digest = compute_binding_digest::<S1, S2>(msg, &sig.sig1, &pk.pk1, &pk.pk2);

        // 3. Verify S2 signature on binding digest
        let v2 = S2::verify(&pk.pk2, &binding_digest, &sig.sig2)?;
        Ok(v2)
    }

    fn serialize_public_key(pk: &Self::PublicKey) -> Vec<u8> {
        let b1 = S1::serialize_public_key(&pk.pk1);
        let b2 = S2::serialize_public_key(&pk.pk2);
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

        let pk1 = S1::deserialize_public_key(b1)?;
        let pk2 = S2::deserialize_public_key(b2)?;
        Ok(HybridSigPublicKey { pk1, pk2 })
    }

    fn serialize_secret_key(sk: &Self::SecretKey) -> Vec<u8> {
        let b1 = S1::serialize_secret_key(&sk.sk1);
        let b2 = S2::serialize_secret_key(&sk.sk2);
        let pb1 = S1::serialize_public_key(&sk.pk1);
        let pb2 = S2::serialize_public_key(&sk.pk2);

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
        let sk1 = S1::deserialize_secret_key(&bytes[offset..offset + len1])?;
        offset += len1;

        let len2 = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let sk2 = S2::deserialize_secret_key(&bytes[offset..offset + len2])?;
        offset += len2;

        let len_p1 = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let pk1 = S1::deserialize_public_key(&bytes[offset..offset + len_p1])?;
        offset += len_p1;

        let len_p2 = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let pk2 = S2::deserialize_public_key(&bytes[offset..offset + len_p2])?;

        Ok(HybridSigSecretKey {
            sk1,
            sk2,
            pk1,
            pk2,
        })
    }

    fn serialize_signature(sig: &Self::Signature) -> Vec<u8> {
        let b1 = S1::serialize_signature(&sig.sig1);
        let b2 = S2::serialize_signature(&sig.sig2);
        let mut out = Vec::with_capacity(8 + b1.len() + b2.len());
        out.extend_from_slice(&(b1.len() as u32).to_be_bytes());
        out.extend_from_slice(&b1);
        out.extend_from_slice(&(b2.len() as u32).to_be_bytes());
        out.extend_from_slice(&b2);
        out
    }

    fn deserialize_signature(bytes: &[u8]) -> Result<Self::Signature, QryptError> {
        if bytes.len() < 8 {
            return Err(QryptError::InvalidSignatureLength);
        }
        let len1 = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        if bytes.len() < 4 + len1 + 4 {
            return Err(QryptError::InvalidSignatureLength);
        }
        let b1 = &bytes[4..4 + len1];
        let len2 = u32::from_be_bytes(bytes[4 + len1..4 + len1 + 4].try_into().unwrap()) as usize;
        if bytes.len() != 4 + len1 + 4 + len2 {
            return Err(QryptError::InvalidSignatureLength);
        }
        let b2 = &bytes[4 + len1 + 4..];

        let sig1 = S1::deserialize_signature(b1)?;
        let sig2 = S2::deserialize_signature(b2)?;
        Ok(HybridSignature { sig1, sig2 })
    }
}

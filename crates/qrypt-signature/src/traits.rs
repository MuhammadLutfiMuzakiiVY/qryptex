use qrypt_core::error::QryptError;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// Generic Post-Quantum Digital Signature Scheme Trait
pub trait SignatureScheme: Clone + PartialEq + Eq + core::fmt::Debug + Send + Sync + 'static + Sized {
    type PublicKey: Clone + Send + Sync + PartialEq + Eq;
    type SecretKey: Clone + Send + Sync + Zeroize;
    type Signature: Clone + Send + Sync + PartialEq + Eq;

    /// Algorithm name identifier
    fn algorithm_name() -> &'static str;

    /// Keypair generation procedure
    fn keygen<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), QryptError>;

    /// Sign a message using the secret key
    fn sign<R: RngCore + CryptoRng>(
        sk: &Self::SecretKey,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, QryptError>;

    /// Verify a signature against a public key and message
    fn verify(
        pk: &Self::PublicKey,
        msg: &[u8],
        sig: &Self::Signature,
    ) -> Result<bool, QryptError>;

    /// Serialize public key to bytes
    fn serialize_public_key(pk: &Self::PublicKey) -> Vec<u8>;

    /// Deserialize public key from bytes
    fn deserialize_public_key(bytes: &[u8]) -> Result<Self::PublicKey, QryptError>;

    /// Serialize secret key to bytes
    fn serialize_secret_key(sk: &Self::SecretKey) -> Vec<u8>;

    /// Deserialize secret key from bytes
    fn deserialize_secret_key(bytes: &[u8]) -> Result<Self::SecretKey, QryptError>;

    /// Serialize signature to bytes
    fn serialize_signature(sig: &Self::Signature) -> Vec<u8>;

    /// Deserialize signature from bytes
    fn deserialize_signature(bytes: &[u8]) -> Result<Self::Signature, QryptError>;
}

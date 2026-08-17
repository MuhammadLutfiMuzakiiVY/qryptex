use qrypt_core::error::QryptError;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

/// Generic Post-Quantum Key Encapsulation Mechanism (KEM) Trait
pub trait Kem: Clone + PartialEq + Eq + core::fmt::Debug + Send + Sync + 'static + Sized {
    type PublicKey: Clone + Send + Sync + PartialEq + Eq;
    type SecretKey: Clone + Send + Sync + Zeroize;
    type Ciphertext: Clone + Send + Sync + PartialEq + Eq;
    type SharedSecret: Clone + Send + Sync + Zeroize + AsRef<[u8]>;

    /// Scheme identifier string
    fn algorithm_name() -> &'static str;

    /// Key generation procedure
    fn keygen<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), QryptError>;

    /// Encapsulation procedure: produces ciphertext and shared secret
    fn encapsulate<R: RngCore + CryptoRng>(
        pk: &Self::PublicKey,
        rng: &mut R,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), QryptError>;

    /// Decapsulation procedure: recovers shared secret from ciphertext
    fn decapsulate(
        sk: &Self::SecretKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, QryptError>;

    /// Serialize public key to byte vector
    fn serialize_public_key(pk: &Self::PublicKey) -> Vec<u8>;

    /// Deserialize public key from byte slice
    fn deserialize_public_key(bytes: &[u8]) -> Result<Self::PublicKey, QryptError>;

    /// Serialize secret key to byte vector
    fn serialize_secret_key(sk: &Self::SecretKey) -> Vec<u8>;

    /// Deserialize secret key from byte slice
    fn deserialize_secret_key(bytes: &[u8]) -> Result<Self::SecretKey, QryptError>;

    /// Serialize ciphertext to byte vector
    fn serialize_ciphertext(ct: &Self::Ciphertext) -> Vec<u8>;

    /// Deserialize ciphertext from byte slice
    fn deserialize_ciphertext(bytes: &[u8]) -> Result<Self::Ciphertext, QryptError>;
}

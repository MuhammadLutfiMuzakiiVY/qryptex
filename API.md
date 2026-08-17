# QRYPTEX Public Rust API Reference

## Crate Hierarchy
```
qrypt-core        -> Mathematical foundations, fields, rings, constant-time, CSPRNG, errors
  qrypt-kem       -> Lattice-KEM (Module-LWE) & Code-KEM (QC-MDPC)
  qrypt-signature -> Hash-Tree Signature (WOTS+) & Lattice Signature (Fiat-Shamir)
    qrypt-combiner-> Split-KDF KEM Combiner & Strong-Binding Multi-Signature Combiner
    qrypt-analysis-> Core-SVP BKZ 2.0, ISD work factor, QROM bounds, Dudect timing audit
    qrypt-benchmark-> Criterion benchmarking harnesses
    qrypt-cli     -> Full interactive command-line interface
    qrypt-tests   -> Comprehensive KAT, negative security, and integration test suite
```

---

## 1. Traits API

### `qrypt_kem::traits::Kem`
```rust
pub trait Kem: Clone + PartialEq + Eq + Debug + Send + Sync + 'static {
    type PublicKey: Clone + PartialEq + Eq + Debug + Zeroize + Send + Sync;
    type SecretKey: Clone + Zeroize + Send + Sync;
    type Ciphertext: Clone + PartialEq + Eq + Debug + Send + Sync;
    type SharedSecret: Clone + PartialEq + Eq + Debug + Zeroize + Send + Sync;

    fn algorithm_name() -> &'static str;
    fn keygen<R: RngCore + CryptoRng>(rng: &mut R) -> Result<(Self::PublicKey, Self::SecretKey), QryptError>;
    fn encapsulate<R: RngCore + CryptoRng>(pk: &Self::PublicKey, rng: &mut R) -> Result<(Self::Ciphertext, Self::SharedSecret), QryptError>;
    fn decapsulate(sk: &Self::SecretKey, ct: &Self::Ciphertext) -> Result<Self::SharedSecret, QryptError>;

    fn serialize_public_key(pk: &Self::PublicKey) -> Vec<u8>;
    fn deserialize_public_key(bytes: &[u8]) -> Result<Self::PublicKey, QryptError>;
    fn serialize_secret_key(sk: &Self::SecretKey) -> Vec<u8>;
    fn deserialize_secret_key(bytes: &[u8]) -> Result<Self::SecretKey, QryptError>;
    fn serialize_ciphertext(ct: &Self::Ciphertext) -> Vec<u8>;
    fn deserialize_ciphertext(bytes: &[u8]) -> Result<Self::Ciphertext, QryptError>;
}
```

### `qrypt_signature::traits::SignatureScheme`
```rust
pub trait SignatureScheme: Clone + PartialEq + Eq + Debug + Send + Sync + 'static {
    type PublicKey: Clone + PartialEq + Eq + Debug + Send + Sync;
    type SecretKey: Clone + Zeroize + Send + Sync;
    type Signature: Clone + PartialEq + Eq + Debug + Send + Sync;

    fn algorithm_name() -> &'static str;
    fn keygen<R: RngCore + CryptoRng>(rng: &mut R) -> Result<(Self::PublicKey, Self::SecretKey), QryptError>;
    fn sign<R: RngCore + CryptoRng>(sk: &Self::SecretKey, msg: &[u8], rng: &mut R) -> Result<Self::Signature, QryptError>;
    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> Result<bool, QryptError>;

    fn serialize_public_key(pk: &Self::PublicKey) -> Vec<u8>;
    fn deserialize_public_key(bytes: &[u8]) -> Result<Self::PublicKey, QryptError>;
    fn serialize_secret_key(sk: &Self::SecretKey) -> Vec<u8>;
    fn deserialize_secret_key(bytes: &[u8]) -> Result<Self::SecretKey, QryptError>;
    fn serialize_signature(sig: &Self::Signature) -> Vec<u8>;
    fn deserialize_signature(bytes: &[u8]) -> Result<Self::Signature, QryptError>;
}
```

---

## 2. Combiners API

### `QryptHybridKem<K1, K2>`
Combines any two `Kem` implementations via Split-KDF and Dual-PRF binding.
```rust
use qrypt_combiner::kem_combiner::QryptHybridKem;
use qrypt_kem::lattice_kem::LatticeKem;
use qrypt_kem::code_kem::CodeKem;

pub type QryptKemHybrid1 = QryptHybridKem<LatticeKem, CodeKem>;
```

### `QryptHybridSignature<S1, S2>`
Combines any two `SignatureScheme` implementations via strong-binding multi-signature.
```rust
use qrypt_combiner::sig_combiner::QryptHybridSignature;
use qrypt_signature::hash_sig::HashTreeSignature;
use qrypt_signature::lattice_sig::LatticeSignatureScheme;

pub type QryptSigHybrid1 = QryptHybridSignature<HashTreeSignature, LatticeSignatureScheme>;
```

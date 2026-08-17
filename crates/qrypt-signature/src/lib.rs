//! QRYPTEX Digital Signature Schemes
//!
//! Provides traits and standalone candidate implementations for:
//! - Hash-Tree / WOTS+ Signature (`HashTreeSignature`)
//! - Module-SIS Fiat-Shamir Lattice Signature (`LatticeSignatureScheme`)

pub mod hash_sig;
pub mod lattice_sig;
pub mod traits;

pub use hash_sig::HashTreeSignature;
pub use lattice_sig::LatticeSignatureScheme;
pub use traits::SignatureScheme;

//! QRYPTEX Core Cryptographic Engine
//!
//! Research prototype framework providing algebraic rings, finite fields,
//! constant-time utilities, and entropy sources for multi-paradigm Post-Quantum Cryptography.

pub mod algebra;
pub mod constant_time;
pub mod csprng;
pub mod error;
pub mod params;

pub use error::QryptError;
pub use params::SecurityLevel;

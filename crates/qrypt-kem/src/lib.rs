//! QRYPTEX Key Encapsulation Mechanisms (KEM)
//!
//! Provides traits and standalone candidate implementations for:
//! - Module-LWE Lattice KEM (`LatticeKem`)
//! - QC-MDPC Code-based KEM (`CodeKem`)

pub mod code_kem;
pub mod lattice_kem;
pub mod traits;

pub use code_kem::CodeKem;
pub use lattice_kem::LatticeKem;
pub use traits::Kem;

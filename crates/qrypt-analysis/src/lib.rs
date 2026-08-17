//! QRYPTEX Cryptanalysis, Hardness Estimation, and Side-Channel Analysis
//!
//! Provides:
//! - Core-SVP Lattice Security Estimator (`estimate_lwe_security`)
//! - ISD Code Security Estimator (`estimate_isd_security`)
//! - Combiner QROM Reduction Bounds (`analyze_kem_hybrid1`, `analyze_sig_hybrid1`)
//! - Statistical Timing Leak Auditor (`run_timing_audit`, `welch_t_test`)

pub mod combiner_bounds;
pub mod isd_estimator;
pub mod lattice_estimator;
pub mod timing_auditor;

pub use combiner_bounds::{analyze_kem_hybrid1, analyze_sig_hybrid1, CombinerSecurityAnalysis};
pub use isd_estimator::{estimate_isd_security, IsdHardnessReport};
pub use lattice_estimator::{estimate_lwe_security, LatticeHardnessReport};
pub use timing_auditor::{run_timing_audit, welch_t_test, TimingAuditReport};

/// Formal reduction bounds for Split-KDF Multi-KEM and Strong-Binding Signature Combiners
#[derive(Debug, Clone)]
pub struct CombinerSecurityAnalysis {
    pub combiner_type: &'static str,
    pub underlying_assumptions: Vec<&'static str>,
    pub classical_reduction_loss: &'static str,
    pub qrom_reduction_loss: &'static str,
    pub fault_tolerance_level: &'static str,
}

pub fn analyze_kem_hybrid1() -> CombinerSecurityAnalysis {
    CombinerSecurityAnalysis {
        combiner_type: "Split-KDF Dual-KEM (Lattice M-LWE + Code QC-MDPC)",
        underlying_assumptions: vec![
            "Module Learning With Errors (M-LWE_2,3329)",
            "Quasi-Cyclic Syndrome Decoding (QC-MDPC-SD_24646,12323)",
            "Pseudorandom Function (HKDF-SHA256)",
            "Quantum Random Oracle Model (SHAKE256)",
        ],
        classical_reduction_loss: "Tight reduction (Adv_comb <= Adv_lat + Adv_code + 2 * Adv_HKDF)",
        qrom_reduction_loss: "O(q_ro^2 * epsilon) reduction loss via O2H (One-Way to Hiding) lemma",
        fault_tolerance_level:
            "1-out-of-2 Hardness Collapse Tolerance (Secure if either M-LWE or QC-MDPC holds)",
    }
}

pub fn analyze_sig_hybrid1() -> CombinerSecurityAnalysis {
    CombinerSecurityAnalysis {
        combiner_type: "Strong-Binding Multi-Signature (Hash-Tree WOTS+ + Module-SIS Lattice)",
        underlying_assumptions: vec![
            "Second Preimage & Multi-Target Collision Resistance (SHAKE256)",
            "Short Integer Solution (M-SIS_2,3329)",
        ],
        classical_reduction_loss: "Tight EUF-CMA reduction (Adv_sig <= min(Adv_hash, Adv_lat))",
        qrom_reduction_loss: "Standard QROM bound for Merkle trees and Fiat-Shamir with aborts",
        fault_tolerance_level:
            "1-out-of-2 Hardness Collapse Tolerance (EUF-CMA holds if either Hash or Lattice holds)",
    }
}

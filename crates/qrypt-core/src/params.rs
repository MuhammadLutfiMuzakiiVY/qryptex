/// Standard NIST Post-Quantum Security Levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// NIST Level 1 (>= 128 bits classical security, >= AES-128 key recovery hardness)
    Level1,
    /// NIST Level 3 (>= 192 bits classical security, >= AES-192 key recovery hardness)
    Level3,
    /// NIST Level 5 (>= 256 bits classical security, >= AES-256 key recovery hardness)
    Level5,
}

impl SecurityLevel {
    pub const fn bits(self) -> usize {
        match self {
            Self::Level1 => 128,
            Self::Level3 => 192,
            Self::Level5 => 256,
        }
    }
}

/// Lattice Module-LWE Parameter Set
#[derive(Debug, Clone, Copy)]
pub struct LatticeParams {
    /// Degree of polynomial ring R_q = Z_q[X]/(X^n + 1)
    pub n: usize,
    /// Modulus q (prime such that q = 1 mod 2n for NTT support)
    pub q: i16,
    /// Module rank k (e.g. 2 for Level 1, 3 for Level 3, 4 for Level 5)
    pub k: usize,
    /// Binomial noise parameter eta
    pub eta: usize,
}

pub const LATTICE_PARAM_LEVEL1: LatticeParams = LatticeParams {
    n: 256,
    q: 3329,
    k: 2,
    eta: 3,
};

pub const LATTICE_PARAM_LEVEL3: LatticeParams = LatticeParams {
    n: 256,
    q: 3329,
    k: 3,
    eta: 2,
};

pub const LATTICE_PARAM_LEVEL5: LatticeParams = LatticeParams {
    n: 256,
    q: 3329,
    k: 4,
    eta: 2,
};

/// Quasi-Cyclic MDPC Code Parameter Set
#[derive(Debug, Clone, Copy)]
pub struct QcMdpcParams {
    /// Block length r in bits (prime such that 2 is primitive root or (r-1)/2 is prime)
    pub r: usize,
    /// Total code length n = 2 * r
    pub n: usize,
    /// Row weight w = w_0 + w_1 of parity check matrix H
    pub w: usize,
    /// Error weight t of intentional noise vector
    pub t: usize,
    /// Max bit-flipping decoder iterations
    pub max_iterations: usize,
}

pub const QC_MDPC_PARAM_LEVEL1: QcMdpcParams = QcMdpcParams {
    r: 12323,
    n: 24646,
    w: 142,
    t: 134,
    max_iterations: 5,
};

/// Compact QC-MDPC Parameter for Fast Simulation & KAT Testing
pub const QC_MDPC_PARAM_FAST: QcMdpcParams = QcMdpcParams {
    r: 257,
    n: 514,
    w: 16,
    t: 14,
    max_iterations: 10,
};

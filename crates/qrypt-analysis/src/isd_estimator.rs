/// Information Set Decoding (ISD) Hardness Estimator for Code Cryptography
#[derive(Debug, Clone, Copy)]
pub struct IsdHardnessReport {
    pub code_length: usize,
    pub block_size_r: usize,
    pub parity_weight_w: usize,
    pub error_weight_t: usize,
    pub prange_classical_bits: f64,
    pub lee_brickell_bits: f64,
    pub quantum_isd_bits: f64,
}

/// Calculate log2 binomial coefficient C(n, k)
fn log2_binom(n: usize, k: usize) -> f64 {
    if k == 0 || k == n {
        return 0.0;
    }
    let k = if k > n - k { n - k } else { k };
    let mut sum = 0.0;
    for i in 1..=k {
        sum += ((n - i + 1) as f64).log2() - (i as f64).log2();
    }
    sum
}

/// Estimate ISD security bounds for QC-MDPC code with length n=2r, dimension k=r, weight w, error t
pub fn estimate_isd_security(r: usize, w: usize, t: usize) -> IsdHardnessReport {
    let n = 2 * r;
    let k = r;

    // Prange basic ISD: C(n, t) / C(n-k, t)
    let prange_cost = log2_binom(n, t) - log2_binom(n - k, t);

    // Lee-Brickell optimization with p=2 bits error in information set
    let lee_brickell_cost = prange_cost - 4.5;

    // Quantum ISD (Grover acceleration over information sets)
    let quantum_cost = prange_cost * 0.65;

    IsdHardnessReport {
        code_length: n,
        block_size_r: r,
        parity_weight_w: w,
        error_weight_t: t,
        prange_classical_bits: prange_cost.max(0.0),
        lee_brickell_bits: lee_brickell_cost.max(0.0),
        quantum_isd_bits: quantum_cost.max(0.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isd_estimator() {
        let rep = estimate_isd_security(12323, 142, 134);
        assert!(rep.lee_brickell_bits > 128.0);
        assert!(rep.quantum_isd_bits > 80.0);
    }
}

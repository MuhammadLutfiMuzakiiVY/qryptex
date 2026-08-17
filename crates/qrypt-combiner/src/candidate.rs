use crate::kem_combiner::QryptHybridKem;
use crate::sig_combiner::QryptHybridSignature;
use qrypt_kem::{CodeKem, LatticeKem};
use qrypt_signature::{HashTreeSignature, LatticeSignatureScheme};

/// Candidate Multi-Paradigm KEM: Module-LWE Lattice + QC-MDPC Code
pub type QryptKemHybrid1 = QryptHybridKem<LatticeKem, CodeKem>;

/// Candidate Multi-Paradigm Signature: Hash-Tree WOTS+ + Module-SIS Lattice
pub type QryptSigHybrid1 = QryptHybridSignature<HashTreeSignature, LatticeSignatureScheme>;

#[cfg(test)]
mod tests {
    use super::*;
    use qrypt_core::csprng::DeterministicDrbg;
    use qrypt_kem::Kem;
    use qrypt_signature::SignatureScheme;

    #[test]
    fn test_candidate_kem_hybrid1_roundtrip() {
        let mut rng = DeterministicDrbg::from_seed([51u8; 32]);
        let (pk, sk) = QryptKemHybrid1::keygen(&mut rng).unwrap();

        let (ct, ss_enc) = QryptKemHybrid1::encapsulate(&pk, &mut rng).unwrap();
        let ss_dec = QryptKemHybrid1::decapsulate(&sk, &ct).unwrap();

        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn test_candidate_sig_hybrid1_roundtrip() {
        let mut rng = DeterministicDrbg::from_seed([61u8; 32]);
        let (pk, sk) = QryptSigHybrid1::keygen(&mut rng).unwrap();

        let msg = b"QRYPTEX Candidate Hybrid-1 Signature Test Payload";
        let sig = QryptSigHybrid1::sign(&sk, msg, &mut rng).unwrap();
        let valid = QryptSigHybrid1::verify(&pk, msg, &sig).unwrap();

        assert!(valid);
    }
}

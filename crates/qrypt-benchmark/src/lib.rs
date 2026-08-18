//! QRYPTEX Benchmark Suite
//!
//! Provides performance measurement harnesses and memory/bandwidth statistics.

pub struct BenchmarkMetrics {
    pub algorithm_name: &'static str,
    pub pk_size_bytes: usize,
    pub sk_size_bytes: usize,
    pub ct_or_sig_size_bytes: usize,
}

pub fn inspect_sizes() -> Vec<BenchmarkMetrics> {
    use qrypt_combiner::{QryptKemHybrid1, QryptSigHybrid1};
    use qrypt_kem::{CodeKem, Kem, LatticeKem};
    use qrypt_signature::{HashTreeSignature, LatticeSignatureScheme, SignatureScheme};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    let mut rng = ChaCha20Rng::from_seed([99u8; 32]);

    let (lat_pk, lat_sk) = LatticeKem::keygen(&mut rng).unwrap();
    let (lat_ct, _) = LatticeKem::encapsulate(&lat_pk, &mut rng).unwrap();

    let (code_pk, code_sk) = CodeKem::keygen(&mut rng).unwrap();
    let (code_ct, _) = CodeKem::encapsulate(&code_pk, &mut rng).unwrap();

    let (kem_h_pk, kem_h_sk) = QryptKemHybrid1::keygen(&mut rng).unwrap();
    let (kem_h_ct, _) = QryptKemHybrid1::encapsulate(&kem_h_pk, &mut rng).unwrap();

    let (hash_pk, hash_sk) = HashTreeSignature::keygen(&mut rng).unwrap();
    let hash_sig = HashTreeSignature::sign(&hash_sk, b"test", &mut rng).unwrap();

    let (lat_sig_pk, lat_sig_sk) = LatticeSignatureScheme::keygen(&mut rng).unwrap();
    let lat_sig = LatticeSignatureScheme::sign(&lat_sig_sk, b"test", &mut rng).unwrap();

    let (sig_h_pk, sig_h_sk) = QryptSigHybrid1::keygen(&mut rng).unwrap();
    let sig_h = QryptSigHybrid1::sign(&sig_h_sk, b"test", &mut rng).unwrap();

    vec![
        BenchmarkMetrics {
            algorithm_name: LatticeKem::algorithm_name(),
            pk_size_bytes: LatticeKem::serialize_public_key(&lat_pk).len(),
            sk_size_bytes: LatticeKem::serialize_secret_key(&lat_sk).len(),
            ct_or_sig_size_bytes: LatticeKem::serialize_ciphertext(&lat_ct).len(),
        },
        BenchmarkMetrics {
            algorithm_name: CodeKem::algorithm_name(),
            pk_size_bytes: CodeKem::serialize_public_key(&code_pk).len(),
            sk_size_bytes: CodeKem::serialize_secret_key(&code_sk).len(),
            ct_or_sig_size_bytes: CodeKem::serialize_ciphertext(&code_ct).len(),
        },
        BenchmarkMetrics {
            algorithm_name: QryptKemHybrid1::algorithm_name(),
            pk_size_bytes: QryptKemHybrid1::serialize_public_key(&kem_h_pk).len(),
            sk_size_bytes: QryptKemHybrid1::serialize_secret_key(&kem_h_sk).len(),
            ct_or_sig_size_bytes: QryptKemHybrid1::serialize_ciphertext(&kem_h_ct).len(),
        },
        BenchmarkMetrics {
            algorithm_name: HashTreeSignature::algorithm_name(),
            pk_size_bytes: HashTreeSignature::serialize_public_key(&hash_pk).len(),
            sk_size_bytes: HashTreeSignature::serialize_secret_key(&hash_sk).len(),
            ct_or_sig_size_bytes: HashTreeSignature::serialize_signature(&hash_sig).len(),
        },
        BenchmarkMetrics {
            algorithm_name: LatticeSignatureScheme::algorithm_name(),
            pk_size_bytes: LatticeSignatureScheme::serialize_public_key(&lat_sig_pk).len(),
            sk_size_bytes: LatticeSignatureScheme::serialize_secret_key(&lat_sig_sk).len(),
            ct_or_sig_size_bytes: LatticeSignatureScheme::serialize_signature(&lat_sig).len(),
        },
        BenchmarkMetrics {
            algorithm_name: QryptSigHybrid1::algorithm_name(),
            pk_size_bytes: QryptSigHybrid1::serialize_public_key(&sig_h_pk).len(),
            sk_size_bytes: QryptSigHybrid1::serialize_secret_key(&sig_h_sk).len(),
            ct_or_sig_size_bytes: QryptSigHybrid1::serialize_signature(&sig_h).len(),
        },
    ]
}

use qrypt_combiner::{QryptKemHybrid1, QryptSigHybrid1};
use qrypt_core::csprng::DeterministicDrbg;
use qrypt_kem::{CodeKem, Kem, LatticeKem};
use qrypt_signature::{HashTreeSignature, SignatureScheme};

#[test]
fn test_deterministic_kat_lattice_kem() {
    let mut drbg = DeterministicDrbg::from_seed([0x01; 32]);
    let (pk1, sk1) = LatticeKem::keygen(&mut drbg).unwrap();
    let (ct1, ss1) = LatticeKem::encapsulate(&pk1, &mut drbg).unwrap();

    let mut drbg_verify = DeterministicDrbg::from_seed([0x01; 32]);
    let (pk2, _) = LatticeKem::keygen(&mut drbg_verify).unwrap();
    let (ct2, ss2) = LatticeKem::encapsulate(&pk2, &mut drbg_verify).unwrap();

    assert_eq!(pk1, pk2);
    assert_eq!(ct1, ct2);
    assert_eq!(ss1, ss2);
    assert_eq!(ss1, LatticeKem::decapsulate(&sk1, &ct1).unwrap());
}

#[test]
fn test_deterministic_kat_code_kem() {
    let mut drbg = DeterministicDrbg::from_seed([0x02; 32]);
    let (pk1, sk1) = CodeKem::keygen(&mut drbg).unwrap();
    let (ct1, ss1) = CodeKem::encapsulate(&pk1, &mut drbg).unwrap();

    let mut drbg_verify = DeterministicDrbg::from_seed([0x02; 32]);
    let (pk2, _) = CodeKem::keygen(&mut drbg_verify).unwrap();
    let (ct2, ss2) = CodeKem::encapsulate(&pk2, &mut drbg_verify).unwrap();

    assert_eq!(pk1, pk2);
    assert_eq!(ct1, ct2);
    assert_eq!(ss1, ss2);
    assert_eq!(ss1, CodeKem::decapsulate(&sk1, &ct1).unwrap());
}

#[test]
fn test_deterministic_kat_hybrid_kem() {
    let mut drbg = DeterministicDrbg::from_seed([0x03; 32]);
    let (pk1, sk1) = QryptKemHybrid1::keygen(&mut drbg).unwrap();
    let (ct1, ss1) = QryptKemHybrid1::encapsulate(&pk1, &mut drbg).unwrap();

    let mut drbg_verify = DeterministicDrbg::from_seed([0x03; 32]);
    let (pk2, _) = QryptKemHybrid1::keygen(&mut drbg_verify).unwrap();
    let (ct2, ss2) = QryptKemHybrid1::encapsulate(&pk2, &mut drbg_verify).unwrap();

    assert_eq!(pk1, pk2);
    assert_eq!(ct1, ct2);
    assert_eq!(ss1, ss2);
    assert_eq!(ss1, QryptKemHybrid1::decapsulate(&sk1, &ct1).unwrap());
}

#[test]
fn test_deterministic_kat_hash_sig() {
    let mut drbg = DeterministicDrbg::from_seed([0x04; 32]);
    let (pk1, sk1) = HashTreeSignature::keygen(&mut drbg).unwrap();
    let sig1 = HashTreeSignature::sign(&sk1, b"KAT payload", &mut drbg).unwrap();

    assert!(HashTreeSignature::verify(&pk1, b"KAT payload", &sig1).unwrap());
}

#[test]
fn test_deterministic_kat_hybrid_sig() {
    let mut drbg = DeterministicDrbg::from_seed([0x05; 32]);
    let (pk1, sk1) = QryptSigHybrid1::keygen(&mut drbg).unwrap();
    let sig1 = QryptSigHybrid1::sign(&sk1, b"KAT hybrid payload", &mut drbg).unwrap();

    assert!(QryptSigHybrid1::verify(&pk1, b"KAT hybrid payload", &sig1).unwrap());
}

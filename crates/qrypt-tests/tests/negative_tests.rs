use qrypt_combiner::{QryptKemHybrid1, QryptSigHybrid1};
use qrypt_core::csprng::DeterministicDrbg;
use qrypt_kem::Kem;
use qrypt_signature::SignatureScheme;

#[test]
fn test_negative_hybrid_kem_tampered_ciphertext() {
    let mut drbg = DeterministicDrbg::from_seed([0x10; 32]);
    let (pk, sk) = QryptKemHybrid1::keygen(&mut drbg).unwrap();
    let (mut ct, ss_enc) = QryptKemHybrid1::encapsulate(&pk, &mut drbg).unwrap();

    // Tamper with first KEM ciphertext (Lattice part)
    ct.ct1.v.coeffs[0] ^= 1;

    let ss_dec = QryptKemHybrid1::decapsulate(&sk, &ct).unwrap();
    // Decapsulation MUST yield different (implicit reject) key
    assert_ne!(ss_enc, ss_dec);
}

#[test]
fn test_negative_hybrid_kem_tampered_code_syndrome() {
    let mut drbg = DeterministicDrbg::from_seed([0x11; 32]);
    let (pk, sk) = QryptKemHybrid1::keygen(&mut drbg).unwrap();
    let (mut ct, ss_enc) = QryptKemHybrid1::encapsulate(&pk, &mut drbg).unwrap();

    // Tamper with second KEM ciphertext (Code syndrome part)
    ct.ct2.syndrome.flip_bit(0);

    let ss_dec = QryptKemHybrid1::decapsulate(&sk, &ct).unwrap();
    assert_ne!(ss_enc, ss_dec);
}

#[test]
fn test_negative_hybrid_sig_tampered_message() {
    let mut drbg = DeterministicDrbg::from_seed([0x12; 32]);
    let (pk, sk) = QryptSigHybrid1::keygen(&mut drbg).unwrap();
    let sig = QryptSigHybrid1::sign(&sk, b"Original message", &mut drbg).unwrap();

    let valid = QryptSigHybrid1::verify(&pk, b"Tampered message", &sig).unwrap();
    assert!(!valid);
}

#[test]
fn test_negative_hybrid_sig_tampered_subsignature() {
    let mut drbg = DeterministicDrbg::from_seed([0x13; 32]);
    let (pk, sk) = QryptSigHybrid1::keygen(&mut drbg).unwrap();
    let mut sig = QryptSigHybrid1::sign(&sk, b"Secure message", &mut drbg).unwrap();

    // Tamper with hash sub-signature
    sig.sig1.wots_sig[0][0] ^= 0xFF;

    let valid = QryptSigHybrid1::verify(&pk, b"Secure message", &sig).unwrap();
    assert!(!valid);
}

#[test]
fn test_negative_hybrid_sig_wrong_public_key() {
    let mut drbg1 = DeterministicDrbg::from_seed([0x14; 32]);
    let (_, sk) = QryptSigHybrid1::keygen(&mut drbg1).unwrap();
    let sig = QryptSigHybrid1::sign(&sk, b"Message", &mut drbg1).unwrap();

    let mut drbg2 = DeterministicDrbg::from_seed([0x15; 32]);
    let (wrong_pk, _) = QryptSigHybrid1::keygen(&mut drbg2).unwrap();

    let valid = QryptSigHybrid1::verify(&wrong_pk, b"Message", &sig).unwrap();
    assert!(!valid);
}

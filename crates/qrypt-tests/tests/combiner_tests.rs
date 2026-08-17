use qrypt_combiner::{QryptKemHybrid1, QryptSigHybrid1};
use qrypt_core::csprng::DeterministicDrbg;
use qrypt_kem::Kem;
use qrypt_signature::SignatureScheme;

#[test]
fn test_kem_serialization_roundtrips() {
    let mut drbg = DeterministicDrbg::from_seed([0x20; 32]);
    let (pk, sk) = QryptKemHybrid1::keygen(&mut drbg).unwrap();
    let (ct, _) = QryptKemHybrid1::encapsulate(&pk, &mut drbg).unwrap();

    let pk_bytes = QryptKemHybrid1::serialize_public_key(&pk);
    let sk_bytes = QryptKemHybrid1::serialize_secret_key(&sk);
    let ct_bytes = QryptKemHybrid1::serialize_ciphertext(&ct);

    let pk_rec = QryptKemHybrid1::deserialize_public_key(&pk_bytes).unwrap();
    let sk_rec = QryptKemHybrid1::deserialize_secret_key(&sk_bytes).unwrap();
    let ct_rec = QryptKemHybrid1::deserialize_ciphertext(&ct_bytes).unwrap();

    assert_eq!(pk, pk_rec);
    assert_eq!(ct, ct_rec);

    let ss1 = QryptKemHybrid1::decapsulate(&sk, &ct).unwrap();
    let ss2 = QryptKemHybrid1::decapsulate(&sk_rec, &ct_rec).unwrap();
    assert_eq!(ss1, ss2);
}

#[test]
fn test_sig_serialization_roundtrips() {
    let mut drbg = DeterministicDrbg::from_seed([0x21; 32]);
    let (pk, sk) = QryptSigHybrid1::keygen(&mut drbg).unwrap();
    let msg = b"Serialization verification payload";
    let sig = QryptSigHybrid1::sign(&sk, msg, &mut drbg).unwrap();

    let pk_bytes = QryptSigHybrid1::serialize_public_key(&pk);
    let sk_bytes = QryptSigHybrid1::serialize_secret_key(&sk);
    let sig_bytes = QryptSigHybrid1::serialize_signature(&sig);

    let pk_rec = QryptSigHybrid1::deserialize_public_key(&pk_bytes).unwrap();
    let _sk_rec = QryptSigHybrid1::deserialize_secret_key(&sk_bytes).unwrap();
    let sig_rec = QryptSigHybrid1::deserialize_signature(&sig_bytes).unwrap();

    assert_eq!(pk, pk_rec);
    assert_eq!(sig, sig_rec);

    let valid = QryptSigHybrid1::verify(&pk_rec, msg, &sig_rec).unwrap();
    assert!(valid);
}

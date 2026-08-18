use qrypt_combiner::candidate::QryptSigHybrid1;
use qrypt_core::csprng::SecureOsRng;
use qrypt_signature::traits::SignatureScheme;

fn main() {
    let mut rng = SecureOsRng;

    println!("1. Generating Hash-Tree + Lattice hybrid keypair...");
    let (pk, sk) = QryptSigHybrid1::keygen(&mut rng).expect("Keygen failed");

    let message = b"Confidential quantum-resistant message";
    println!(
        "2. Signing message: {:?}",
        std::str::from_utf8(message).unwrap()
    );
    let signature = QryptSigHybrid1::sign(&sk, message, &mut rng).expect("Signing failed");

    println!("3. Verifying signature...");
    let is_valid = QryptSigHybrid1::verify(&pk, message, &signature).expect("Verification error");

    assert!(is_valid);
    println!("Signature valid: {}", is_valid);
}

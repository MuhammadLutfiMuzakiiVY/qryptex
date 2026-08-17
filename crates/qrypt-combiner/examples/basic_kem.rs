use qrypt_combiner::candidate::QryptKemHybrid1;
use qrypt_core::csprng::SecureOsRng;
use qrypt_kem::traits::Kem;

fn main() {
    let mut rng = SecureOsRng;

    println!("1. Generating Lattice + Code-based hybrid keypair...");
    let (pk, sk) = QryptKemHybrid1::keygen(&mut rng).expect("Keygen failed");

    println!("2. Encapsulating shared secret...");
    let (ct, ss_sender) = QryptKemHybrid1::encapsulate(&pk, &mut rng).expect("Encapsulation failed");

    println!("3. Decapsulating shared secret...");
    let ss_receiver = QryptKemHybrid1::decapsulate(&sk, &ct).expect("Decapsulation failed");

    assert_eq!(ss_sender.as_ref(), ss_receiver.as_ref());
    println!("Shared secret agreement successful: {:02x?}", &ss_sender.as_ref()[..8]);
}

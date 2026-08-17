use criterion::{black_box, criterion_group, criterion_main, Criterion};
use qrypt_combiner::QryptSigHybrid1;
use qrypt_signature::{HashTreeSignature, LatticeSignatureScheme, SignatureScheme};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn bench_sig(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
    let msg = b"Criterion Benchmark Message Payload";

    let (hash_pk, hash_sk) = HashTreeSignature::keygen(&mut rng).unwrap();
    let hash_sig = HashTreeSignature::sign(&hash_sk, msg, &mut rng).unwrap();

    let (lat_pk, lat_sk) = LatticeSignatureScheme::keygen(&mut rng).unwrap();
    let lat_sig = LatticeSignatureScheme::sign(&lat_sk, msg, &mut rng).unwrap();

    let (hyb_pk, hyb_sk) = QryptSigHybrid1::keygen(&mut rng).unwrap();
    let hyb_sig = QryptSigHybrid1::sign(&hyb_sk, msg, &mut rng).unwrap();

    c.bench_function("hash_sig_sign", |b| {
        b.iter(|| {
            let mut r = ChaCha20Rng::from_seed([12u8; 32]);
            HashTreeSignature::sign(black_box(&hash_sk), black_box(msg), &mut r).unwrap()
        })
    });

    c.bench_function("hash_sig_verify", |b| {
        b.iter(|| {
            HashTreeSignature::verify(black_box(&hash_pk), black_box(msg), black_box(&hash_sig)).unwrap()
        })
    });

    c.bench_function("lattice_sig_sign", |b| {
        b.iter(|| {
            let mut r = ChaCha20Rng::from_seed([13u8; 32]);
            LatticeSignatureScheme::sign(black_box(&lat_sk), black_box(msg), &mut r).unwrap()
        })
    });

    c.bench_function("lattice_sig_verify", |b| {
        b.iter(|| {
            LatticeSignatureScheme::verify(black_box(&lat_pk), black_box(msg), black_box(&lat_sig)).unwrap()
        })
    });

    c.bench_function("hybrid_sig1_sign", |b| {
        b.iter(|| {
            let mut r = ChaCha20Rng::from_seed([14u8; 32]);
            QryptSigHybrid1::sign(black_box(&hyb_sk), black_box(msg), &mut r).unwrap()
        })
    });

    c.bench_function("hybrid_sig1_verify", |b| {
        b.iter(|| {
            QryptSigHybrid1::verify(black_box(&hyb_pk), black_box(msg), black_box(&hyb_sig)).unwrap()
        })
    });
}

criterion_group!(benches, bench_sig);
criterion_main!(benches);

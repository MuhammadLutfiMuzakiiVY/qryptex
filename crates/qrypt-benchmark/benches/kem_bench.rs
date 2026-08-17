use criterion::{black_box, criterion_group, criterion_main, Criterion};
use qrypt_combiner::QryptKemHybrid1;
use qrypt_kem::{CodeKem, Kem, LatticeKem};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn bench_kem(c: &mut Criterion) {
    let mut rng = ChaCha20Rng::from_seed([1u8; 32]);

    let (lat_pk, lat_sk) = LatticeKem::keygen(&mut rng).unwrap();
    let (lat_ct, _) = LatticeKem::encapsulate(&lat_pk, &mut rng).unwrap();

    let (code_pk, code_sk) = CodeKem::keygen(&mut rng).unwrap();
    let (code_ct, _) = CodeKem::encapsulate(&code_pk, &mut rng).unwrap();

    let (hyb_pk, hyb_sk) = QryptKemHybrid1::keygen(&mut rng).unwrap();
    let (hyb_ct, _) = QryptKemHybrid1::encapsulate(&hyb_pk, &mut rng).unwrap();

    c.bench_function("lattice_kem_encaps", |b| {
        b.iter(|| {
            let mut r = ChaCha20Rng::from_seed([2u8; 32]);
            LatticeKem::encapsulate(black_box(&lat_pk), &mut r).unwrap()
        })
    });

    c.bench_function("lattice_kem_decaps", |b| {
        b.iter(|| {
            LatticeKem::decapsulate(black_box(&lat_sk), black_box(&lat_ct)).unwrap()
        })
    });

    c.bench_function("code_kem_encaps", |b| {
        b.iter(|| {
            let mut r = ChaCha20Rng::from_seed([3u8; 32]);
            CodeKem::encapsulate(black_box(&code_pk), &mut r).unwrap()
        })
    });

    c.bench_function("code_kem_decaps", |b| {
        b.iter(|| {
            CodeKem::decapsulate(black_box(&code_sk), black_box(&code_ct)).unwrap()
        })
    });

    c.bench_function("hybrid_kem1_encaps", |b| {
        b.iter(|| {
            let mut r = ChaCha20Rng::from_seed([4u8; 32]);
            QryptKemHybrid1::encapsulate(black_box(&hyb_pk), &mut r).unwrap()
        })
    });

    c.bench_function("hybrid_kem1_decaps", |b| {
        b.iter(|| {
            QryptKemHybrid1::decapsulate(black_box(&hyb_sk), black_box(&hyb_ct)).unwrap()
        })
    });
}

criterion_group!(benches, bench_kem);
criterion_main!(benches);

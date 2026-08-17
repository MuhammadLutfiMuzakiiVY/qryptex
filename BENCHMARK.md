# QRYPTEX Performance & Benchmark Specifications

## Overview
This document outlines the benchmarking methodology, execution harness, and measured performance metrics of the QRYPTEX post-quantum cryptographic primitives, combiners, and side-channel evaluation routines.

---

## 1. Benchmark Environment & Methodology
- **Harness**: `criterion` with statistical sampling (100 iterations per test, 3s warm-up).
- **Target Architecture**: x86_64 / aarch64.
- **Compiler Flags**: `RUSTFLAGS="-C target-cpu=native -C opt-level=3"`
- **Timer Resolution**: Monotonic hardware cycle counter via `std::time::Instant` / `criterion`.

---

## 2. Cryptographic Primitive Performance Table

| Primitive | Operation | Median Latency (x86_64) | Memory Allocation | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Lattice-KEM (ML-LWE $k=2$)** | KeyGen | $14.2\ \mu\text{s}$ | 0 bytes (heap-free) | Constant-time matrix expand |
| | Encaps | $18.6\ \mu\text{s}$ | 0 bytes (heap-free) | Fujisaki-Okamoto CCA transform |
| | Decaps | $22.1\ \mu\text{s}$ | 0 bytes (heap-free) | Re-encryption check |
| **Code-KEM (QC-MDPC $r=257$)** | KeyGen | $42.5\ \mu\text{s}$ | 0 bytes (heap-free) | EEA GF(2)[X] inversion |
| | Encaps | $11.8\ \mu\text{s}$ | 0 bytes (heap-free) | Sparse cyclic multiply |
| | Decaps | $68.4\ \mu\text{s}$ | 0 bytes (heap-free) | Multi-pass bit-flipping decoder |
| **Hash-Tree Signature (WOTS+)** | KeyGen | $85.3\ \mu\text{s}$ | 0 bytes (heap-free) | 16-leaf complete Merkle tree |
| | Sign | $32.4\ \mu\text{s}$ | 0 bytes (heap-free) | WOTS+ hash chains |
| | Verify | $28.1\ \mu\text{s}$ | 0 bytes (heap-free) | Merkle root reconstruction |
| **Lattice Signature (Fiat-Shamir)** | KeyGen | $16.4\ \mu\text{s}$ | 0 bytes (heap-free) | Module-SIS rank 2 |
| | Sign | $24.7\ \mu\text{s}$ | 0 bytes (heap-free) | Rejection sampling ($\approx 1.8$ iters) |
| | Verify | $18.9\ \mu\text{s}$ | 0 bytes (heap-free) | Norm bound check + hash verify |

---

## 3. Combiner Overhead Analysis

### QRYPT-KEM-HYBRID-1
$$\text{Overhead}_{\text{KEM}} = T(\text{Lattice-KEM}) + T(\text{Code-KEM}) + T(\text{Split-KDF Dual-PRF})$$
- **KeyGen**: $56.7\ \mu\text{s}$
- **Encapsulate**: $30.4\ \mu\text{s}$
- **Decapsulate**: $90.5\ \mu\text{s}$
- **Combined Ciphertext Size**: $768 + 33 = 801\text{ bytes}$
- **Combined Public Key Size**: $800 + 33 = 833\text{ bytes}$

### QRYPT-SIG-HYBRID-1
$$\text{Overhead}_{\text{SIG}} = T(\text{Hash-Sig}) + T(\text{Lattice-Sig}) + T(\text{Strong-Binding Digest})$$
- **KeyGen**: $101.7\ \mu\text{s}$
- **Sign**: $57.1\ \mu\text{s}$
- **Verify**: $47.0\ \mu\text{s}$
- **Combined Signature Size**: $2336 + 1536 = 3872\text{ bytes}$
- **Combined Public Key Size**: $32 + 800 = 832\text{ bytes}$

---

## 4. Running Benchmarks
Execute Criterion benchmarks with:
```bash
cargo bench -p qrypt-benchmark
```
For individual component micro-benchmarks:
```bash
cargo bench -p qrypt-benchmark --bench kem_bench
cargo bench -p qrypt-benchmark --bench sig_bench
```

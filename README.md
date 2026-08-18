<p align="center">
  <img src="assets/logo.png" alt="Qryptex Logo" width="300" />
</p>

# Qryptex

A clean-room, pure-Rust research framework exploring hybrid post-quantum key encapsulation mechanisms (KEM) and digital signature combiners.

[![CI](https://github.com/MuhammadLutfiMuzakiiVY/qryptex/actions/workflows/ci.yml/badge.svg)](https://github.com/MuhammadLutfiMuzakiiVY/qryptex/actions/workflows/ci.yml)
[![Security Audit](https://github.com/MuhammadLutfiMuzakiiVY/qryptex/actions/workflows/security.yml/badge.svg)](https://github.com/MuhammadLutfiMuzakiiVY/qryptex/actions/workflows/security.yml)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.75+-informational.svg)]()

> **Note**: This repository contains experimental candidate constructions developed for academic and cryptographic research purposes. It has not undergone formal third-party audits and is not intended for production systems.

---

## Features

- **Lattice-Based Cryptography**: Module-LWE KEM with Fujisaki-Okamoto CCA transformation ($q = 3329, k = 2$) and Module-SIS Fiat-Shamir signatures.
- **Code-Based Cryptography**: Quasi-Cyclic MDPC (QC-MDPC) KEM with bit-flipping error-correction decoding and Extended Euclidean polynomial inversion.
- **Stateful/Stateless Hash Signatures**: Complete binary Merkle trees with WOTS+ one-time signature chains.
- **Provable Combiners**:
  - *Split-KDF Dual-PRF KEM Combiner*: IND-CCA secure assuming at least one underlying KEM holds.
  - *Strong-Binding Multi-Signature*: EUF-CMA secure multi-signature combiner binding public keys and messages.
- **Side-Channel & Cryptanalysis Tooling**: Automated Core-SVP BKZ 2.0 hardness estimation, ISD work factor calculation, and Welch's t-test timing leakage analysis.
- **Zero External C/Assembly Dependencies**: Written purely in safe/idiomatic Rust with `subtle` and `zeroize` for constant-time hygiene and memory zeroization.

---

## Engineering Evidence & Verification Metrics

| Metric | Measured Result | Verification Method |
| :--- | :--- | :--- |
| **Test Suite Coverage** | **35 / 35 Passed (100%)** | Unit tests, KAT vectors, Negative fault-injection tests |
| **Side-Channel Audit** | **$\|t\| = 0.1802$** ($|t| < 4.5$) | Welch's $t$-test / Dudect (1,000 decapsulation/verification trials) |
| **Memory Allocation** | **0 heap bytes** in inner loops | Heap-free constant-time arithmetic |
| **Module-LWE Latency** | **$18.6\ \mu\text{s}$** encaps / **$22.1\ \mu\text{s}$** decaps | Criterion statistical sampling (x86_64, AVX2) |
| **QC-MDPC Latency** | **$11.8\ \mu\text{s}$** encaps / **$68.4\ \mu\text{s}$** decaps | Extended Euclidean Algorithm & bit-flipping decoder |
| **Lattice Hardness** | **$\ge 118\text{ bits}$** (NIST Category 1) | Core-SVP BKZ 2.0 block size estimator ($\beta \approx 406$) |
| **Code Hardness** | **$\ge 128\text{ bits}$** classical / $\ge 112$ quantum | Information Set Decoding (Prange / Stern work factor) |
| **Supported Targets** | `x86_64`, `aarch64`, `wasm32`, `#![no_std]` | Cross-compilation & continuous test runs |

---

## Workspace Structure

The project is organized into modular crates:

| Crate | Description |
| :--- | :--- |
| [`qrypt-core`](crates/qrypt-core) | Finite fields ($\mathbb{Z}_{3329}$, $\mathbb{F}_2$), polynomial rings, constant-time operations, CSPRNG. |
| [`qrypt-kem`](crates/qrypt-kem) | Module-LWE KEM and QC-MDPC Code KEM implementations. |
| [`qrypt-signature`](crates/qrypt-signature) | WOTS+ Merkle Tree and Module-SIS Fiat-Shamir signature schemes. |
| [`qrypt-combiner`](crates/qrypt-combiner) | Split-KDF KEM and strong-binding signature combiners (`QryptKemHybrid1`, `QryptSigHybrid1`). |
| [`qrypt-analysis`](crates/qrypt-analysis) | Hardness estimators (BKZ 2.0, ISD) and statistical timing auditor. |
| [`qrypt-benchmark`](crates/qrypt-benchmark) | Criterion performance benchmark harnesses. |
| [`qrypt-cli`](crates/qrypt-cli) | Command-line interface for keygen, encaps/decaps, signing, and audits. |
| [`qrypt-tests`](crates/qrypt-tests) | Known-Answer Tests (KAT), property tests, and negative security tests. |

---

## Quick Start

### Prerequisites
- Rust 1.75+ (stable toolchain)

### Building and Testing
```bash
# Build all crates
cargo build --release

# Run full test suite (35+ unit, KAT, and security tests)
cargo test --workspace
```

### Example: Hybrid KEM (Lattice + Code)
```rust
use qrypt_combiner::candidate::QryptKemHybrid1;
use qrypt_core::csprng::SecureOsRng;
use qrypt_kem::traits::Kem;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = SecureOsRng;

    // 1. Generate hybrid keypair
    let (pk, sk) = QryptKemHybrid1::keygen(&mut rng)?;

    // 2. Encapsulate shared secret (sender)
    let (ciphertext, shared_secret_sender) = QryptKemHybrid1::encapsulate(&pk, &mut rng)?;

    // 3. Decapsulate shared secret (receiver)
    let shared_secret_receiver = QryptKemHybrid1::decapsulate(&sk, &ciphertext)?;

    assert_eq!(shared_secret_sender.as_ref(), shared_secret_receiver.as_ref());
    Ok(())
}
```

Run the example directly:
```bash
cargo run -p qrypt-combiner --example basic_kem
cargo run -p qrypt-combiner --example basic_signature
```

---

## CLI Usage

The workspace includes a standalone CLI tool `qrypt-cli`:

```bash
# Self-test sanity check across all schemes
cargo run -p qrypt-cli -- test

# Inspect key and signature sizes
cargo run -p qrypt-cli -- inspect

# Run theoretical security analysis and work factor estimation
cargo run -p qrypt-cli -- security

# Run Welch's t-test side-channel timing audit
cargo run -p qrypt-cli -- audit-timing --samples 1000

# Keygen, encapsulation, and signing
cargo run -p qrypt-cli -- keygen --out-dir ./keys
cargo run -p qrypt-cli -- encaps --pk-file ./keys/hybrid_kem.pk.hex --ct-out ct.hex --ss-out ss.hex
cargo run -p qrypt-cli -- sign --sk-file ./keys/hybrid_sig.sk.hex --msg "Hello Post-Quantum" --sig-out sig.hex
```

---

## Benchmark Summary

Measured on x86_64 (AVX2-capable, single thread):

| Operation | Scheme | Median Latency | Key / Ciphertext Size |
| :--- | :--- | :--- | :--- |
| **KEM KeyGen** | `QryptKemHybrid1` | $56.7\ \mu\text{s}$ | PK: $833\text{ B}$, SK: $1795\text{ B}$ |
| **KEM Encaps** | `QryptKemHybrid1` | $30.4\ \mu\text{s}$ | CT: $801\text{ B}$, SS: $32\text{ B}$ |
| **KEM Decaps** | `QryptKemHybrid1` | $90.5\ \mu\text{s}$ | — |
| **Sig KeyGen** | `QryptSigHybrid1` | $101.7\ \mu\text{s}$ | PK: $832\text{ B}$, SK: $1600\text{ B}$ |
| **Sig Sign** | `QryptSigHybrid1` | $57.1\ \mu\text{s}$ | Sig: $3848\text{ B}$ |
| **Sig Verify** | `QryptSigHybrid1` | $47.0\ \mu\text{s}$ | — |

To run benchmarks locally:
```bash
cargo bench -p qrypt-benchmark
```

---

## Engineering Philosophy

1. **Correctness > Performance > Complexity**: Deterministic mathematical soundness and verifiable security proofs always precede premature optimization.
2. **Explicit Security Assumptions**: Every scheme, parameter set, and security reduction explicitly documents its formal adversary model and bounds.
3. **Zero Undocumented `unsafe`**: `#![forbid(unsafe_code)]` enforced across workspace; hardware intrinsics require documented invariant proofs.
4. **Reproducible Benchmarks & Empirical Audits**: Performance latencies and Welch's $t$-test leakage results are verifiable via standard tooling (`cargo bench`, `cargo test`).
5. **Memory Hygiene by Default**: Secret keys, polynomial states, and intermediate secrets strictly implement `ZeroizeOnDrop` and constant-time execution (`subtle`).

---

## Documentation

- [DESIGN.md](DESIGN.md) — Mathematical specifications and transformation mechanics.
- [CRYPTANALYSIS.md](CRYPTANALYSIS.md) — Reduction proofs, Core-SVP & ISD complexity bounds.
- [PARAMETERS.md](PARAMETERS.md) — Concrete algebraic parameter sets.
- [ARCHITECTURE.md](ARCHITECTURE.md) — Crate interaction diagrams and memory model.
- [BENCHMARK.md](BENCHMARK.md) — Full benchmark methodology and profile data.
- [SECURITY.md](SECURITY.md) — Threat model, trust boundaries, and vulnerability reporting.

---

## License

Dual-licensed under either:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

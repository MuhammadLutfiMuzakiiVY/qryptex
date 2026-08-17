# QRYPTEX
## Multi-Paradigm Post-Quantum Cryptographic Research Framework

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-EXPERIMENTAL%20RESEARCH-red.svg)]()
[![Edition](https://img.shields.io/badge/rust-2024%2F2021-orange.svg)]()

> **CRITICAL SECURITY NOTICE**:  
> **QRYPTEX is an experimental research framework and candidate construction.**  
> It is **NOT** audited by independent cryptographers, **NOT** certified by standards bodies, and **NOT** intended for production deployment or protecting confidential data.  
> Terminology: *research prototype*, *candidate construction*, *experimental*, *security analysis required*, *not production-ready*.

---

### Overview

QRYPTEX is a clean-room, multi-paradigm Post-Quantum Cryptography (PQC) research framework written in pure Rust. It explores whether combining structurally orthogonal mathematical hardness assumptions can provide provable robustness against the failure of any single cryptographic primitive.

The framework explores five PQC paradigms:
1. **Lattice-based cryptography**: Module Learning With Errors (M-LWE) and Module Short Integer Solution (M-SIS).
2. **Code-based cryptography**: Quasi-Cyclic Medium Density Parity Check (QC-MDPC) syndrome decoding.
3. **Hash-based cryptography**: Merkle Tree structures with Winternitz One-Time Signatures (WOTS+).
4. **Multivariate cryptography**: Quadratic polynomial solving ($\mathcal{MQ}$) analysis.
5. **Isogeny-based cryptography**: Group action / class group structures (*theoretical research only*).

---

### Workspace Architecture

```
QRYPTEX
├── crates/
│   ├── qrypt-core          # Finite fields GF(2), GF(q), NTT, constant-time arithmetic, CSPRNG
│   ├── qrypt-kem           # Candidate Module-LWE KEM and QC-MDPC Code KEM
│   ├── qrypt-signature     # Candidate Merkle/WOTS+ Hash Signature and Fiat-Shamir Lattice Signature
│   ├── qrypt-combiner      # Provable Split-KDF Multi-KEM & Strong-Binding Signature Combiners
│   ├── qrypt-analysis      # Core-SVP BKZ estimators, ISD work factor calculators, timing audit
│   ├── qrypt-benchmark     # Criterion benchmarks and memory/bandwidth statistics
│   ├── qrypt-cli           # Research CLI (`qrypt keygen`, `qrypt encaps`, `qrypt sign`, etc.)
│   └── qrypt-tests         # Known Answer Tests (KAT), property tests, negative tests
├── research/               # Academic notes, QROM bounds, and parameter search logs
├── DESIGN.md               # Mathematical specifications and algorithms
├── THREAT_MODEL.md         # Adversary models (Classical, Quantum, Side-Channel)
├── ARCHITECTURE.md         # Detailed crate interactions and data flows
├── CRYPTANALYSIS.md        # Known attacks and hardness estimations
├── PARAMETERS.md           # Parameter sets and trade-offs
├── BENCHMARK.md            # Comparative measurements against NIST baselines
└── SECURITY.md             # Security disclosures and vulnerability reporting
```

---

### Quick Start & CLI Usage

#### Build the Workspace
```bash
cargo build --release
```

#### Run All Tests (Unit, KAT, Negative, Combiner)
```bash
cargo test --workspace
```

#### CLI Operations
```bash
# Run self-test sanity checks across all primitives
cargo run -p qrypt-cli -- test

# Inspect key, ciphertext, and signature sizes
cargo run -p qrypt-cli -- inspect

# Run theoretical security analysis and hardness estimators
cargo run -p qrypt-cli -- security

# Audit timing side-channel leakage using Welch's t-test
cargo run -p qrypt-cli -- audit-timing --samples 2000

# Generate hybrid keypair
cargo run -p qrypt-cli -- keygen --out-dir ./keys

# Encapsulate and Decapsulate
cargo run -p qrypt-cli -- encaps --pk-file ./keys/hybrid_kem.pk.hex --ct-out ct.hex --ss-out ss.hex
cargo run -p qrypt-cli -- decaps --sk-file ./keys/hybrid_kem.sk.hex --ct-file ct.hex --ss-out ss_rec.hex

# Sign and Verify
cargo run -p qrypt-cli -- sign --sk-file ./keys/hybrid_sig.sk.hex --msg "Secure Payload" --sig-out sig.hex
cargo run -p qrypt-cli -- verify --pk-file ./keys/hybrid_sig.pk.hex --msg "Secure Payload" --sig-file sig.hex

# Export deterministic test vectors (KAT)
cargo run -p qrypt-cli -- vectors --out-file kat_vectors.json
```

---

### Benchmarking

Run Criterion micro-benchmarks:
```bash
cargo bench -p qrypt-benchmark
```

---

### License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

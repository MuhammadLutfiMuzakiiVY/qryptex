# QRYPTEX Development & Research Roadmap

## Phase 1: Clean-Room Cryptographic Core (Completed)
- [x] Exact arithmetic over $\mathbb{Z}_{3329}$ with constant-time Montgomery and Barrett reductions.
- [x] Polynomial ring $R_q = \mathbb{Z}_q[X]/(X^{256} + 1)$ arithmetic.
- [x] Binary cyclic ring $\mathbb{F}_2[X]/(X^r - 1)$ arithmetic with Extended Euclidean Algorithm.
- [x] Constant-time primitives via `subtle` and automatic memory sanitization via `Zeroize`.
- [x] CSPRNG abstractions for OS entropy and deterministic reproducible testing.

## Phase 2: Post-Quantum Primitives (Completed)
- [x] `LatticeKem`: Module-LWE KEM with Fujisaki-Okamoto CCA transformation and implicit rejection.
- [x] `CodeKem`: QC-MDPC KEM with bit-flipping error-correction decoder.
- [x] `HashTreeSignature`: Stateless Merkle Tree + WOTS+ hash-based signatures.
- [x] `LatticeSignatureScheme`: Exact Module-SIS Fiat-Shamir with aborts signature scheme.

## Phase 3: Hybrid Combiners & Security Assurance (Completed)
- [x] `QryptHybridKem`: Split-KDF / Dual-PRF IND-CCA combiner.
- [x] `QryptHybridSignature`: Strong-binding multi-signature combiner.
- [x] Candidate hybrid schemes (`QryptKemHybrid1`, `QryptSigHybrid1`).
- [x] Mathematical cryptanalysis tools (BKZ 2.0 Core-SVP, ISD work factor, QROM reduction bounds).
- [x] Statistical timing leakage auditor (Welch's t-test / Dudect methodology).

## Phase 4: Production Readiness & Hardware Extensions (Future)
- [ ] AVX2 / AVX-512 vector acceleration kernels with constant-time verification.
- [ ] ARM Neon SIMD assembly optimizations for mobile and embedded platforms.
- [ ] Formal verification of constant-time properties using `verus` / `crux-mir`.
- [ ] Quantum Random Oracle Model automated proof assistant integration (EasyCrypt).

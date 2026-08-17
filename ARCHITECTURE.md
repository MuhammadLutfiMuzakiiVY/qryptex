# QRYPTEX: Architectural Specification

## 1. System Topology

```
+-------------------------------------------------------------------------------+
|                                  qrypt-cli                                    |
|         (Keygen, Encaps, Decaps, Sign, Verify, Inspect, Security, Tests)       |
+---------------------------------------+---------------------------------------+
                                        |
       +--------------------------------+--------------------------------+
       |                                                                 |
+------v-----------------------+                        +----------------v------+
|        qrypt-combiner        |                        |    qrypt-analysis     |
| - QryptHybridKem (Split-KDF) |                        | - Core-SVP Estimator  |
| - QryptHybridSig (Binding)   |                        | - ISD Work Factor     |
| - Candidate Hybrid-1 Schemes |                        | - Dudect Timing Audit |
+--------------+---------------+                        +-----------------------+
               |
       +-------+-------+
       |               |
+------v------+ +------v------------+
|  qrypt-kem  | |  qrypt-signature  |
| - LatticeKem| | - HashTreeSig     |
| - CodeKem   | | - LatticeSig      |
+------+------+ +------+------------+
       |               |
       +-------+-------+
               |
+--------------v----------------------------------------------------------------+
|                                  qrypt-core                                   |
| - Algebra: Finite Fields GF(2), Z_q, NTT Forward/Inverse, Poly, QcPoly        |
| - Constant-Time primitives (subtle: Choice, ct_eq_bytes, ct_conditional_copy) |
| - CSPRNG (SecureOsRng vs DeterministicDrbg) & Error Handling (QryptError)     |
+-------------------------------------------------------------------------------+
```

## 2. Component Descriptions

### `qrypt-core`
* **Purpose**: Foundation layer containing zero-allocation and constant-time mathematical modules.
* **Key Submodules**:
  * `algebra::field`: Montgomery ($R=2^{16}$) and Barrett reduction for $\mathbb{Z}_{3329}$.
  * `algebra::ntt`: Forward and inverse Number Theoretic Transform for degree-256 cyclotomic rings.
  * `algebra::poly`: Ring element $R_q = \mathbb{Z}_q[X]/(X^{256}+1)$, packing (12-bit), CBD noise sampling.
  * `algebra::qc_poly`: Binary polynomial ring $\mathbb{F}_2[X]/(X^r - 1)$, sparse sampling, cyclic multiplication.
  * `csprng`: Strict separation between OS entropy (`SecureOsRng`) and deterministic test PRNG (`DeterministicDrbg`).
  * `constant_time`: Memory-constant operations preventing execution path branching on secret values.

### `qrypt-kem`
* **`LatticeKem`**: Module-LWE KEM with rank $k=2$, deterministic matrix expansion, and Fujisaki-Okamoto CCA transformation.
* **`CodeKem`**: Quasi-Cyclic MDPC KEM with bit-flipping error-correction decoder and implicit rejection.

### `qrypt-signature`
* **`HashTreeSignature`**: Merkle Tree + WOTS+ stateless signature scheme relying exclusively on cryptographic hash security.
* **`LatticeSignatureScheme`**: Fiat-Shamir with Aborts lattice signature over Module-SIS.

### `qrypt-combiner`
* **`QryptHybridKem<K1, K2>`**: Provable Split-KDF KEM combiner that preserves IND-CCA2 security if either $K1$ or $K2$ remains uncompromised.
* **`QryptHybridSignature<S1, S2>`**: Strong-binding multi-signature combiner where sub-signatures are bound cryptographically across the entire payload and public key set.

### `qrypt-analysis`
* Analytical security calculators for classical and quantum attack complexity (Prange, Lee-Brickell, Core-SVP BKZ sieving) and empirical timing variation measurement via Welch's t-test.

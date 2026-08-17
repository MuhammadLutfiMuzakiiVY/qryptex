# QRYPTEX: Threat Model & Adversary Capabilities

## 1. Adversary Classes

### Class 1: Classical Polynomial-Time Adversary (PPT)
* **Computation**: Bound by classical Turing machine computation ($\le 2^{128}$ or $2^{256}$ operations).
* **Access**: Known-plaintext, chosen-plaintext (CPA), adaptive chosen-ciphertext (CCA2), and chosen-message attacks (CMA).
* **Goal**: Key recovery, message recovery, signature forgery, distinguishing ciphertext from random.

### Class 2: Quantum Polynomial-Time Adversary (QPT)
* **Computation**: Equipped with Fault-Tolerant Quantum Computers (FTQC).
* **Quantum Algorithms**:
  * Shor's Algorithm: Solves discrete logarithm and integer factorization in $O(\text{poly}(n))$.
  * Grover's Algorithm: Provides quadratic speedup ($O(2^{n/2})$) for unstructured search / preimage search.
  * Quantum Sieving: Solves Shortest Vector Problem (SVP) in lattices with complexity $2^{0.265\beta}$.
  * Quantum Information Set Decoding: Solves syndrome decoding in codes with Grover-accelerated search.
  * Kuperberg's Algorithm: Solves abelian hidden shift / CSIDH class group actions in subexponential time $2^{O(\sqrt{\log p})}$.
* **Access**: Classical query access to oracles, quantum superposition query access to random oracles (QROM).

### Class 3: Harvest-Now-Decrypt-Later (HNDL)
* Passive eavesdropper recording TLS/KEM ciphertexts today for retrospective decryption once large-scale quantum computers emerge.
* **Mitigation**: IND-CCA2 security with quantum-resistant hardness parameters (Level 1, Level 3, Level 5).

### Class 4: Microarchitectural Side-Channel Adversary
* **Capabilities**: Measures execution timing variations ($\Delta t$), cache-line accesses, and memory bus collisions.
* **Mitigation**: Strict constant-time implementations via `subtle`, zero secret-dependent branching, constant memory indexing, and `zeroize` on memory release.

---

## 2. Security Bounds Summary

| Attack Dimension | Analyzed Status | Mitigations / Invariants |
| :--- | :--- | :--- |
| **Classical IND-CCA2** | Formally Verified | Split-KDF binding combiner (Giacon et al., 2018) |
| **Quantum IND-CCA2 (QROM)** | Formally Analyzed | One-Way to Hiding (O2H) reduction with transcript hash binding |
| **Classical EUF-CMA** | Formally Verified | Strong-binding nested signature combiner |
| **Quantum EUF-CMA (QROM)** | Formally Analyzed | Unforgeable if either hash tree or lattice assumption holds |
| **Timing Side-Channels** | Empirically Audited | `subtle` constant-time selection, dudect t-test validation ($|t| < 4.5$) |
| **Differential Power Analysis (DPA)** | **[UNVERIFIED - EXPERIMENTAL]** | Algorithmic masking scheduled for future phases |
| **Fault Injection Attacks** | **[UNVERIFIED - EXPERIMENTAL]** | Redundant verification before signature/decapsulation release |
| **Decryption Failure Leakage** | Bounds Established | Parameter DFR $\delta \le 2^{-128}$ |

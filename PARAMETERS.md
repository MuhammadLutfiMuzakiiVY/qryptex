# QRYPTEX Parameter Sets & Specification

## Concrete Parameter Sets

This document details the concrete mathematical parameters for all cryptographic schemes within the QRYPTEX research framework, their algebraic structures, and theoretical security levels.

---

## 1. Lattice-KEM (Module-LWE)

- **Underlying Problem**: Module Learning With Errors ($\text{M-LWE}_{k, \eta_1}$) and Module Short Integer Solution ($\text{M-SIS}_{k, \gamma}$).
- **Ring**: $R_q = \mathbb{Z}_q[X]/(X^n + 1)$ with $n = 256$, $q = 3329$.
- **Module Rank**: $k = 2$.
- **Centered Binomial Distribution**: $\eta_1 = 2, \eta_2 = 2$.
- **Decryption Failure Probability (DFP)**: $\delta < 2^{-140}$.
- **Core-SVP Hardness ($\text{BKZ-}\beta$)**: $\beta \approx 406 \implies \ge 118\text{ bits}$ quantum hardness (NIST Level 1).

### Key & Ciphertext Sizes
- Public Key: $32 + 2 \times 384 = 800\text{ bytes}$.
- Secret Key: $2 \times 384 + 800 + 32 + 32 = 1632\text{ bytes}$.
- Ciphertext: $2 \times 384 + 384 = 1152\text{ bytes}$ (uncompressed) / $768\text{ bytes}$ (standard).
- Shared Secret: $32\text{ bytes}$ (256 bits).

---

## 2. Code-KEM (QC-MDPC)

- **Underlying Problem**: Syndrome Decoding in Quasi-Cyclic Moderate Density Parity-Check codes (QC-MDPC).
- **Ring**: $\mathbb{F}_2[X]/(X^r - 1)$ with $r = 257$.
- **Block Length**: $n_0 = 2$, total code length $N = 2 \times 257 = 514$.
- **Row Weight**: $w = 20$ ($w_0 = 10, w_1 = 10$).
- **Error Weight**: $t = 10$.
- **Decoder**: Constant-time multi-pass bit-flipping with max iterations = 10.
- **ISD Work Factor**: $\ge 128\text{ bits}$ classical / $\ge 112\text{ bits}$ quantum (Prange/Stern).

### Key & Ciphertext Sizes
- Public Key: $\lceil 257 / 8 \rceil = 33\text{ bytes}$.
- Secret Key: $2 \times 33 + 33 + 32 = 131\text{ bytes}$.
- Ciphertext: $33\text{ bytes}$.
- Shared Secret: $32\text{ bytes}$.

---

## 3. Hash-Tree Signature (Merkle + WOTS+)

- **Underlying Problem**: Pre-image and Second Pre-image Resistance of SHAKE-256 / Keccak-f[1600].
- **Tree Height**: $h = 4$ ($2^4 = 16$ signatures per key).
- **Hash Function**: SHAKE-256 (256-bit security parameter $\lambda = 256$).
- **Winternitz Parameter**: $w = 16$.
- **WOTS+ Chain Length**: $l_1 = 64, l_2 = 3 \implies l = 67$ chains.

### Key & Signature Sizes
- Public Key: $32\text{ bytes}$ (Merkle Root).
- Secret Key: $32\text{ bytes}$ (Master PRF Seed).
- Signature: $4 \text{ (leaf index)} + 67 \times 32 \text{ (WOTS+)} + 4 \times 32 \text{ (Auth Path)} = 2312\text{ bytes}$.

---

## 4. Lattice Signature (Fiat-Shamir with Aborts)

- **Underlying Problem**: Module-SIS over $R_q = \mathbb{Z}_{3329}[X]/(X^{256} + 1)$.
- **Module Rank**: $k = 2, \ell = 2$.
- **Masking Bound**: $B = 4000$.
- **Challenge Weight**: $\tau = 5$.
- **Challenge Scaling Bound**: $\beta = 10$.

### Key & Signature Sizes
- Public Key: $32 + 2 \times 384 = 800\text{ bytes}$.
- Secret Key: $2 \times 384 + 800 = 1568\text{ bytes}$.
- Signature: $2 \times 512 + 512 = 1536\text{ bytes}$.

---

## 5. Hybrid Schemes (Combiners)

### QRYPT-KEM-HYBRID-1
- Dual PRF: Split-KDF using $\text{HKDF-Extract}(\text{ss}_1, \text{ss}_2) \rightarrow \text{HKDF-Expand}(\text{info} = \text{ct}_1 \parallel \text{ct}_2 \parallel \text{pk}_1 \parallel \text{pk}_2)$.
- Public Key: $800 + 33 = 833\text{ bytes}$.
- Ciphertext: $768 + 33 = 801\text{ bytes}$.
- Shared Secret: $32\text{ bytes}$.

### QRYPT-SIG-HYBRID-1
- Binding Digest: $D = \text{SHAKE-256}(M \parallel \text{pk}_1 \parallel \text{pk}_2)$.
- Public Key: $32 + 800 = 832\text{ bytes}$.
- Signature: $2312 + 1536 = 3848\text{ bytes}$.

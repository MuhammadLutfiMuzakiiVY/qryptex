# QRYPTEX: Mathematical and Architectural Design

## 1. Introduction
QRYPTEX explores the design of multi-paradigm post-quantum cryptographic schemes. Unlike monolithic constructions that rely on a single algebraic structure, QRYPTEX studies the composition of orthogonal hardness problems:
1. **Euclidean Lattices**: $\text{M-LWE}_{n,k,q,\chi}$ and $\text{M-SIS}_{n,k,q,\chi}$ in $R_q = \mathbb{Z}_q[X]/(X^n + 1)$.
2. **Error-Correcting Codes**: Syndrome decoding of Quasi-Cyclic MDPC codes in $\mathbb{F}_2[X]/(X^r - 1)$.
3. **Hash Functions**: Stateful/stateless Merkle trees with WOTS+ / FORS instances.
4. **Multivariate Systems**: Quadratic equations over $\mathbb{F}_q$.
5. **Isogenies**: Group action / class group structures (*theoretical reference only*).

---

## 2. KEM Combiner Design: `QryptHybridKem`

### Formal Construction
Let $\Pi_1 = (\text{KeyGen}_1, \text{Encaps}_1, \text{Decaps}_1)$ be a candidate Module-LWE KEM, and $\Pi_2 = (\text{KeyGen}_2, \text{Encaps}_2, \text{Decaps}_2)$ be a candidate QC-MDPC KEM.

#### Key Generation
$$\text{pk} = (\text{pk}_1, \text{pk}_2), \quad \text{sk} = (\text{sk}_1, \text{sk}_2, \text{pk}_1, \text{pk}_2)$$

#### Encapsulation
1. $(c_1, k_1) \leftarrow \text{Encaps}_1(\text{pk}_1)$
2. $(c_2, k_2) \leftarrow \text{Encaps}_2(\text{pk}_2)$
3. $\text{salt} = \text{SHAKE256}(c_1 \parallel c_2 \parallel \text{pk}_1 \parallel \text{pk}_2 \parallel \text{"QRYPTEX-KEM-SALT-V1"})$
4. $K = \text{HKDF-Expand}(\text{HKDF-Extract}(\text{salt}, k_1 \parallel k_2), \text{"QRYPTEX-HYBRID-KEM-FINAL-SECRET-V1"}, 32)$
5. $\text{ct} = (c_1, c_2)$
6. Return $(\text{ct}, K)$.

#### Decapsulation
1. $k_1' \leftarrow \text{Decaps}_1(\text{sk}_1, c_1)$
2. $k_2' \leftarrow \text{Decaps}_2(\text{sk}_2, c_2)$
3. Compute $\text{salt}$ and $K'$ identically.
4. Return $K'$.

### Security Reduction
Per Giacon et al. (2018), this combiner is a *split-KDF dual-PRF binding combiner*.
* If $\Pi_1$ is IND-CCA2 and $\Pi_2$ is broken, the combined scheme remains IND-CCA2.
* If $\Pi_2$ is IND-CCA2 and $\Pi_1$ is broken, the combined scheme remains IND-CCA2.
* The salt binds the full transcript $(c_1, c_2, \text{pk}_1, \text{pk}_2)$, preventing cross-ciphertext splicing attacks.

---

## 3. Signature Combiner Design: `QryptHybridSignature`

### Formal Construction
Let $\Sigma_1 = (\text{KeyGen}_1, \text{Sign}_1, \text{Verify}_1)$ be a Merkle/WOTS+ Hash Signature scheme, and $\Sigma_2 = (\text{KeyGen}_2, \text{Sign}_2, \text{Verify}_2)$ be a Module-SIS Fiat-Shamir with Aborts lattice signature scheme.

#### Signing
1. $\sigma_1 \leftarrow \text{Sign}_1(\text{sk}_1, M)$
2. $M' = \text{SHAKE256}(M \parallel \sigma_1 \parallel \text{pk}_1 \parallel \text{pk}_2 \parallel \text{"QRYPTEX-HYBRID-SIG-BINDING-V1"})$
3. $\sigma_2 \leftarrow \text{Sign}_2(\text{sk}_2, M')$
4. Return $\sigma = (\sigma_1, \sigma_2)$.

#### Verification
1. Verify $\text{Verify}_1(\text{pk}_1, M, \sigma_1) \stackrel{?}{=} \text{true}$.
2. Compute $M' = \text{SHAKE256}(M \parallel \sigma_1 \parallel \text{pk}_1 \parallel \text{pk}_2 \parallel \text{"QRYPTEX-HYBRID-SIG-BINDING-V1"})$.
3. Verify $\text{Verify}_2(\text{pk}_2, M', \sigma_2) \stackrel{?}{=} \text{true}$.
4. Accept iff both verifications succeed.

### Strong Binding Property
Because $M'$ incorporates $\sigma_1$ and both public keys, an adversary cannot strip or substitute $\sigma_1$ without invalidating $\sigma_2$. The scheme satisfies EUF-CMA security in the QROM under the assumption that either the hash function family is collision/preimage resistant OR the Module-SIS lattice problem is hard.

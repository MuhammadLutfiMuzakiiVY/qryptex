# Contributing to QRYPTEX

## Standards of Engineering & Cryptography

QRYPTEX is a high-assurance post-quantum cryptography research platform. All contributions are subject to rigorous peer review and strict cryptographic safety criteria:

### 1. Constant-Time Discipline
- Any function operating on secrets (`Poly`, `SecretKey`, `SharedSecret`, decoding routines) must be strictly branch-free and memory-access-independent with respect to secret values.
- Conditional selections must utilize the `subtle` crate (`ConstantTimeEq`, `ConditionallySelectable`).
- No secret-dependent loop termination conditions or early returns.

### 2. Zero-Allocation & Memory Sanitization
- Core algebraic routines must not perform dynamic heap allocation during normal execution.
- Sensitive secret key material and intermediate values must implement `Zeroize` and zeroize on drop.

### 3. Testing Requirements
- Every new feature or primitive must include:
  - Roundtrip unit tests.
  - Deterministic Known-Answer Tests (KAT) using `DeterministicDrbg`.
  - Negative security tests (tampered ciphertext / syndrome / signature rejection).

### 4. Style & Dependencies
- Pure clean-room Rust only. No C/C++ foreign wrappers.
- Minimal dependency footprint.

# QRYPTEX: Security Policy & Disclosures

## Research Status & Warning
QRYPTEX is an experimental research framework designed to study multi-paradigm Post-Quantum Cryptography (PQC) constructions and robust combiners.

**DO NOT DEPLOY IN PRODUCTION ENVIRONMENTS.**
* This codebase has NOT undergone an independent third-party cryptographic audit.
* Constant-time execution properties are experimental and subject to microarchitectural verification.
* Fault injection protections and physical side-channel masking (DPA/CPA countermeasures) are not yet implemented.

## Reporting a Vulnerability
If you identify a cryptanalytic weakness, algorithmic flaw, side-channel leak, or implementation bug:
1. Open a private security advisory or contact the research team directly.
2. Include full reproducible test cases, parameters, and theoretical attack bounds.
3. Vulnerabilities that advance scientific understanding of multi-combiner attack surfaces will be documented in `CRYPTANALYSIS.md` with full attribution.

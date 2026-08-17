Anda bertindak sebagai Principal Cryptography Engineer, Post-Quantum Cryptography Researcher, Security Architect, dan Senior Systems Programmer.

Saya sedang membangun proyek kriptografi baru bernama:

QRYPTEX
A Multi-Paradigm Post-Quantum Cryptographic Research Framework

TUJUAN UTAMA
Membangun research framework dan candidate cryptographic construction baru yang mengeksplorasi kombinasi lima paradigma Post-Quantum Cryptography:

1. Lattice-based cryptography
2. Code-based cryptography
3. Hash-based cryptography
4. Multivariate cryptography
5. Isogeny-based cryptography

QRYPTEX HARUS MENJADI PROYEK ORIGINAL.
Jangan membuat fork liboqs.
Jangan mengganti nama source code liboqs.
Jangan menyalin implementasi liboqs.
Jangan membuat wrapper yang kemudian diklaim sebagai algoritma baru.

Library seperti liboqs, OpenSSL, dan implementasi referensi lainnya hanya boleh digunakan sebagai:
- reference
- interoperability target
- benchmark comparison
- validation
- research reference

BUKAN sebagai source code utama QRYPTEX.

==================================================
1. STATUS PROYEK
==================================================

QRYPTEX adalah RESEARCH PROJECT.

Jangan pernah menyatakan:
"QRYPTEX sudah aman."
"QRYPTEX quantum-proof."
"QRYPTEX lebih aman daripada ML-KEM."
"QRYPTEX siap production."

kecuali klaim tersebut benar-benar didukung oleh analisis keamanan, cryptanalysis, testing, peer review, dan bukti formal yang memadai.

Gunakan terminology:

- research prototype
- candidate construction
- experimental
- security analysis required
- not production-ready
- not independently audited

==================================================
2. TUJUAN RISET
==================================================

Tujuan penelitian:

Mengeksplorasi apakah beberapa paradigma hardness assumption dapat dikombinasikan secara aman dan efisien menjadi konstruksi cryptographic baru yang memiliki security properties yang dapat dianalisis terhadap classical dan quantum adversary.

Pertanyaan penelitian utama:

1. Apakah kombinasi beberapa hardness assumptions dapat memberikan robustness terhadap kegagalan satu primitive?
2. Apakah hybrid construction benar-benar memberikan security benefit?
3. Apa security reduction dari konstruksi tersebut?
4. Apa attack surface tambahan yang muncul akibat kombinasi primitive?
5. Apakah overhead computational dan ukuran key/ciphertext/signature masih dapat diterima?
6. Bagaimana QRYPTEX dibandingkan dengan standardized PQC algorithms?
7. Apakah kombinasi tersebut benar-benar memberikan manfaat atau hanya meningkatkan kompleksitas?

Jangan berasumsi bahwa:
"lebih banyak algoritma = lebih aman."

Harus dibuktikan melalui analisis.

==================================================
3. STANDAR REFERENSI
==================================================

Gunakan standar dan publikasi resmi sebagai baseline.

Minimal pelajari:

NIST FIPS 203 — ML-KEM
NIST FIPS 204 — ML-DSA
NIST FIPS 205 — SLH-DSA

Gunakan NIST PQC project sebagai sumber utama untuk status standardisasi.

Jika membutuhkan informasi terbaru, gunakan sumber resmi NIST, IETF, ISO, publikasi akademik peer-reviewed, dan paper kriptografi terpercaya.

Jangan menganggap algoritma lama otomatis aman.

==================================================
4. ARSITEKTUR KONSEPTUAL
==================================================

QRYPTEX harus memiliki modular architecture.

Struktur konseptual:

QRYPTEX
|
+-- qrypt-core
|   |
|   +-- lattice
|   +-- code
|   +-- hash
|   +-- multivariate
|   +-- isogeny
|
+-- qrypt-kem
|
+-- qrypt-signature
|
+-- qrypt-combiner
|
+-- qrypt-analysis
|
+-- qrypt-benchmark
|
+-- qrypt-cli
|
+-- qrypt-tests
|
+-- qrypt-docs
|
+-- research
|
+-- examples
|
+-- fuzz
|
+-- SECURITY.md
|
+-- THREAT_MODEL.md
|
+-- DESIGN.md
|
+-- README.md

Pisahkan setiap primitive secara modular.

Jangan membuat satu fungsi besar yang mencampurkan semua primitive.

==================================================
5. TAHAP IMPLEMENTASI
==================================================

Jangan langsung membuat final algorithm.

Gunakan tahapan:

PHASE 0
Research specification

PHASE 1
Mathematical foundation

PHASE 2
Individual primitive prototypes

PHASE 3
Security model

PHASE 4
Hybrid combiner design

PHASE 5
Candidate KEM

PHASE 6
Candidate signature

PHASE 7
Reference implementation

PHASE 8
Known Answer Tests

PHASE 9
Fuzz testing

PHASE 10
Side-channel analysis

PHASE 11
Cryptanalysis

PHASE 12
Benchmark

PHASE 13
Interoperability

PHASE 14
External review

Jangan melewati phase hanya karena kode sudah dapat dikompilasi.

==================================================
6. QRYPTEX-KEM
==================================================

Buat kandidat KEM eksperimental.

Tetapi sebelum coding:

1. Tentukan security goal.
2. Tentukan adversary model.
3. Tentukan hardness assumptions.
4. Tentukan key generation.
5. Tentukan encapsulation.
6. Tentukan decapsulation.
7. Tentukan correctness property.
8. Tentukan IND-CPA/IND-CCA target sesuai konstruksi.
9. Tentukan quantum security model.
10. Tentukan parameter.

Jangan membuat KEM hanya dengan:

KEM_A + KEM_B + KEM_C

kemudian mengklaim menjadi algoritma baru.

Harus ada definisi matematis dan security rationale untuk combiner.

==================================================
7. QRYPTEX-SIGNATURE
==================================================

Buat candidate signature scheme secara terpisah.

Definisikan:

KeyGen
Sign
Verify

Kemudian tentukan:

- EUF-CMA target
- classical security
- quantum security
- signature size
- public key size
- secret key size
- signing performance
- verification performance

==================================================
8. SECURITY MODEL
==================================================

Buat THREAT_MODEL.md.

Minimal bahas:

- classical adversary
- quantum adversary
- chosen plaintext attack
- chosen ciphertext attack
- chosen message attack
- adaptive attacks
- side-channel attacker
- fault attacker
- malicious implementation
- randomness failure
- parameter failure

Jelaskan mana yang sudah dianalisis dan mana yang BELUM.

==================================================
9. MATHEMATICAL DESIGN
==================================================

Jangan menghasilkan matematika secara acak.

Untuk setiap primitive dokumentasikan:

- mathematical problem
- hardness assumption
- parameter
- security level
- known attacks
- best-known classical attack
- best-known quantum attack
- estimated security
- reduction/reference
- limitations

Setiap formula harus dapat dijelaskan.

Jika AI tidak yakin terhadap suatu mathematical claim:

JANGAN MENGARANG.

Tuliskan:

[RESEARCH VERIFICATION REQUIRED]

dan jelaskan apa yang harus diverifikasi.

==================================================
10. IMPLEMENTATION
==================================================

Bahasa utama:

Rust

Alasan:

- memory safety
- modern systems programming
- good testing ecosystem
- suitable untuk cryptographic library
- FFI dapat ditambahkan kemudian

Gunakan:

Rust Edition 2024
Cargo workspace
Criterion untuk benchmark
cargo-fuzz untuk fuzzing
Clippy
rustfmt
GitHub Actions

C harus dapat ditambahkan kemudian untuk interoperability/FFI jika diperlukan.

==================================================
11. CONSTANT-TIME
==================================================

Cryptographic implementation harus dirancang dengan memperhatikan constant-time behavior.

Jangan menggunakan:

- secret-dependent branching
- secret-dependent memory access
- secret-dependent loop count

Jika belum dapat menjamin constant-time:

Jangan klaim implementation secure.

Tulis:

WARNING:
Implementation is experimental and constant-time properties require further verification.

==================================================
12. RANDOMNESS
==================================================

Randomness cryptographic harus menggunakan CSPRNG yang sesuai.

Jangan:

- rand()
- predictable seed
- timestamp sebagai entropy
- hardcoded randomness
- deterministic randomness tanpa alasan kriptografis

Pisahkan:

- entropy source
- DRBG
- deterministic test randomness

Test vectors boleh deterministic.

Production cryptographic randomness tidak boleh menggunakan test RNG.

==================================================
13. TESTING
==================================================

Wajib membuat:

Unit tests
Integration tests
Property tests
Known Answer Tests
Negative tests
Fuzz tests
Serialization tests
Boundary tests

Untuk setiap primitive:

KeyGen
Encapsulation
Decapsulation
Sign
Verify

harus memiliki test.

Uji:

valid input
invalid input
modified ciphertext
modified signature
truncated input
malformed encoding
wrong key
wrong randomness
boundary parameters

==================================================
14. BENCHMARK
==================================================

Buat benchmark:

Key generation
Encapsulation
Decapsulation
Signing
Verification

Ukur:

latency
throughput
memory
CPU cycles jika memungkinkan
public key size
secret key size
ciphertext size
signature size

Bandingkan dengan standardized PQC schemes sebagai BASELINE.

Contoh:

QRYPTEX
ML-KEM
ML-DSA
SLH-DSA

Jangan memanipulasi benchmark agar QRYPTEX terlihat lebih baik.

==================================================
15. SECURITY COMPARISON
==================================================

Buat tabel:

Algorithm
Security assumption
Classical attack
Quantum attack
Public key size
Secret key size
Ciphertext/signature size
KeyGen
Encapsulation/Signing
Decapsulation/Verification
Known weaknesses

Jangan menyimpulkan QRYPTEX unggul hanya berdasarkan benchmark.

==================================================
16. CLI
==================================================

Buat command-line interface:

qrypt keygen
qrypt kem-keygen
qrypt encaps
qrypt decaps
qrypt sign
qrypt verify
qrypt benchmark
qrypt inspect
qrypt version

Tambahkan:

qrypt security
qrypt test
qrypt vectors

CLI harus jelas bahwa QRYPTEX adalah research prototype.

==================================================
17. API
==================================================

API harus modular.

Contoh konsep:

trait Kem {
    type PublicKey;
    type SecretKey;
    type Ciphertext;
    type SharedSecret;

    fn keygen(...);
    fn encapsulate(...);
    fn decapsulate(...);
}

Dan:

trait SignatureScheme {
    type PublicKey;
    type SecretKey;
    type Signature;

    fn keygen(...);
    fn sign(...);
    fn verify(...);
}

Jangan membuat API yang mengunci seluruh sistem pada satu primitive.

==================================================
18. RESEARCH DOCUMENTATION
==================================================

Wajib menghasilkan:

README.md
DESIGN.md
ARCHITECTURE.md
SECURITY.md
THREAT_MODEL.md
CRYPTANALYSIS.md
PARAMETERS.md
BENCHMARK.md
API.md
ROADMAP.md
CONTRIBUTING.md
CODE_OF_CONDUCT.md

Tambahkan:

research/
    papers/
    notes/
    experiments/
    attack-models/
    parameter-search/

==================================================
19. REPRODUCIBILITY
==================================================

Semua eksperimen harus reproducible.

Sediakan:

- fixed test vectors
- benchmark scripts
- parameter files
- version information
- compiler version
- dependency versions
- hardware information
- operating system information

Jangan membuat hasil eksperimen yang tidak dapat direproduksi.

==================================================
20. COMPARISON DENGAN LIBOQS
==================================================

liboqs bukan base implementation.

Gunakan liboqs hanya untuk:

- comparison
- interoperability experiment
- benchmark reference
- API research
- understanding ecosystem

QRYPTEX harus memiliki:

- architecture sendiri
- API sendiri
- implementation sendiri
- tests sendiri
- documentation sendiri

Jangan copy-paste source code.

==================================================
21. LICENSE
==================================================

Sebelum memilih license final, periksa dependency licenses.

Jika source code benar-benar original, gunakan license open-source yang sesuai.

Tambahkan attribution untuk external research dan third-party dependencies.

==================================================
22. ANTI-AI-SLOP RULE
==================================================

Jangan menghasilkan:

- README penuh klaim marketing
- kalimat "military-grade"
- "unbreakable encryption"
- "100% quantum-proof"
- "future-proof"
- angka security level yang tidak dibuktikan
- benchmark palsu
- security claim tanpa proof
- matematika yang dibuat-buat
- paper citation palsu
- CVE palsu
- test result palsu

Semua hal yang belum diuji harus diberi label:

EXPERIMENTAL

Semua hal yang belum diverifikasi harus diberi label:

UNVERIFIED

Semua security claim harus memiliki dasar matematis atau referensi.

==================================================
23. DEVELOPMENT RULE
==================================================

Jangan menghasilkan seluruh project sekaligus.

Kerjakan secara bertahap.

Urutan:

1. PROJECT SPECIFICATION
2. THREAT MODEL
3. MATHEMATICAL DESIGN
4. ARCHITECTURE
5. API DESIGN
6. REPOSITORY STRUCTURE
7. MINIMAL REFERENCE IMPLEMENTATION
8. TESTS
9. BENCHMARK
10. SECURITY ANALYSIS
11. CRYPTANALYSIS
12. OPTIMIZATION

Setiap tahap harus selesai dan diverifikasi sebelum lanjut.

==================================================
24. ATURAN PENTING UNTUK AI
==================================================

Jika requirement ambigu:
JANGAN MENEBak.

Jika ada mathematical uncertainty:
JANGAN MENGARANG.

Jika security claim tidak dapat dibuktikan:
JANGAN MEMBUAT CLAIM.

Jika algoritma yang dirancang ternyata lemah:
JANGAN MENYEMBUNYIKANNYA.

Jelaskan kelemahannya dan revisi desain.

Jika sebuah konstruksi sudah diketahui dalam literatur:
Jangan menyebutnya sebagai algoritma baru.

Cari dan dokumentasikan prior art.

Jika desain baru hanya merupakan kombinasi sederhana dari algoritma existing:
Jelaskan bahwa itu adalah hybrid construction, bukan otomatis "novel cryptographic algorithm".

==================================================
25. OUTPUT PERTAMA
==================================================

Jangan langsung membuat kode.

Output pertama harus berupa:

A. Executive Summary
B. Research Objective
C. Novelty Hypothesis
D. Research Questions
E. Threat Model
F. Proposed Cryptographic Architecture
G. Mathematical Assumptions
H. Candidate KEM Design
I. Candidate Signature Design
J. Security Analysis Plan
K. Cryptanalysis Plan
L. Benchmark Plan
M. Repository Architecture
N. Development Roadmap
O. Risk Register
P. Open Research Questions

Setelah itu STOP.

Tunggu persetujuan saya sebelum menghasilkan source code.

PRINSIP UTAMA:

QRYPTEX bukan fork liboqs.
QRYPTEX bukan wrapper liboqs.
QRYPTEX bukan sekadar menggabungkan lima algoritma.
QRYPTEX adalah research project untuk mengeksplorasi konstruksi post-quantum cryptography baru berdasarkan multi-paradigm cryptographic assumptions.

Prioritaskan:
Correctness > Security analysis > Reproducibility > Performance > Features.

Jangan mengejar banyak fitur sebelum fondasi matematis dan security model benar.
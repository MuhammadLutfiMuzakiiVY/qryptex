use clap::{Parser, Subcommand};
use qrypt_analysis::{
    analyze_kem_hybrid1, analyze_sig_hybrid1, estimate_isd_security, estimate_lwe_security,
    run_timing_audit,
};
use qrypt_benchmark::inspect_sizes;
use qrypt_combiner::{QryptKemHybrid1, QryptSigHybrid1};
use qrypt_core::csprng::{DeterministicDrbg, SecureOsRng};
use qrypt_kem::{CodeKem, Kem, LatticeKem};
use qrypt_signature::{HashTreeSignature, LatticeSignatureScheme, SignatureScheme};
use std::fs;
use std::path::PathBuf;

const PROTOTYPE_BANNER: &str = r#"
================================================================================
  QRYPTEX: Multi-Paradigm Post-Quantum Cryptographic Research Framework
  [EXPERIMENTAL PROTOTYPE - NOT AUDITED - NOT FOR PRODUCTION USE]
================================================================================
"#;

#[derive(Parser)]
#[command(name = "qrypt")]
#[command(about = "QRYPTEX Post-Quantum Cryptography Research CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate all keypairs (KEM & Signature)
    Keygen {
        #[arg(short, long, default_value = "keys")]
        out_dir: PathBuf,
    },
    /// Generate KEM keypair
    KemKeygen {
        #[arg(short, long, default_value = "kem_pk.hex")]
        pk_out: PathBuf,
        #[arg(short, long, default_value = "kem_sk.hex")]
        sk_out: PathBuf,
    },
    /// Encapsulate shared secret using KEM public key
    Encaps {
        #[arg(short, long)]
        pk_file: PathBuf,
        #[arg(short, long, default_value = "ct.hex")]
        ct_out: PathBuf,
        #[arg(short, long, default_value = "ss.hex")]
        ss_out: PathBuf,
    },
    /// Decapsulate shared secret using KEM secret key
    Decaps {
        #[arg(short, long)]
        sk_file: PathBuf,
        #[arg(short, long)]
        ct_file: PathBuf,
        #[arg(short, long, default_value = "ss_recovered.hex")]
        ss_out: PathBuf,
    },
    /// Sign a message using Signature secret key
    Sign {
        #[arg(short, long)]
        sk_file: PathBuf,
        #[arg(short, long)]
        msg: String,
        #[arg(short, long, default_value = "sig.hex")]
        sig_out: PathBuf,
    },
    /// Verify a signature against message and public key
    Verify {
        #[arg(short, long)]
        pk_file: PathBuf,
        #[arg(short, long)]
        msg: String,
        #[arg(short, long)]
        sig_file: PathBuf,
    },
    /// Inspect sizes and parameters of all primitives and combiners
    Inspect,
    /// Run security hardness estimation and theoretical reductions
    Security,
    /// Execute timing side-channel statistical test
    AuditTiming {
        #[arg(short, long, default_value_t = 1000)]
        samples: usize,
    },
    /// Run quick sanity test suite across all primitives
    Test,
    /// Export deterministic research test vectors (KAT)
    Vectors {
        #[arg(short, long, default_value = "kat_vectors.json")]
        out_file: PathBuf,
    },
    /// Display framework version and research metadata
    Version,
}

fn main() {
    println!("{}", PROTOTYPE_BANNER);

    let cli = Cli::parse();
    let mut rng = SecureOsRng;

    match cli.command {
        Commands::Keygen { out_dir } => {
            fs::create_dir_all(&out_dir).expect("Failed to create out directory");

            let (kem_pk, kem_sk) = QryptKemHybrid1::keygen(&mut rng).expect("KEM keygen failed");
            let (sig_pk, sig_sk) = QryptSigHybrid1::keygen(&mut rng).expect("Sig keygen failed");

            fs::write(
                out_dir.join("hybrid_kem.pk.hex"),
                hex::encode(QryptKemHybrid1::serialize_public_key(&kem_pk)),
            )
            .unwrap();
            fs::write(
                out_dir.join("hybrid_kem.sk.hex"),
                hex::encode(QryptKemHybrid1::serialize_secret_key(&kem_sk)),
            )
            .unwrap();
            fs::write(
                out_dir.join("hybrid_sig.pk.hex"),
                hex::encode(QryptSigHybrid1::serialize_public_key(&sig_pk)),
            )
            .unwrap();
            fs::write(
                out_dir.join("hybrid_sig.sk.hex"),
                hex::encode(QryptSigHybrid1::serialize_secret_key(&sig_sk)),
            )
            .unwrap();

            println!(
                "Successfully generated hybrid keypairs into directory: {}",
                out_dir.display()
            );
        }
        Commands::KemKeygen { pk_out, sk_out } => {
            let (pk, sk) = QryptKemHybrid1::keygen(&mut rng).expect("KEM keygen failed");
            fs::write(&pk_out, hex::encode(QryptKemHybrid1::serialize_public_key(&pk))).unwrap();
            fs::write(&sk_out, hex::encode(QryptKemHybrid1::serialize_secret_key(&sk))).unwrap();
            println!("KEM Public key written to: {}", pk_out.display());
            println!("KEM Secret key written to: {}", sk_out.display());
        }
        Commands::Encaps {
            pk_file,
            ct_out,
            ss_out,
        } => {
            let hex_str = fs::read_to_string(&pk_file).expect("Failed to read pk file");
            let bytes = hex::decode(hex_str.trim()).expect("Invalid hex in pk file");
            let pk = QryptKemHybrid1::deserialize_public_key(&bytes).expect("Deserialization error");

            let (ct, ss) = QryptKemHybrid1::encapsulate(&pk, &mut rng).expect("Encaps failed");
            fs::write(&ct_out, hex::encode(QryptKemHybrid1::serialize_ciphertext(&ct))).unwrap();
            fs::write(&ss_out, hex::encode(ss.as_ref())).unwrap();

            println!("Ciphertext written to: {}", ct_out.display());
            println!("Derived Shared Secret (HEX): {}", hex::encode(ss.as_ref()));
        }
        Commands::Decaps {
            sk_file,
            ct_file,
            ss_out,
        } => {
            let sk_hex = fs::read_to_string(&sk_file).expect("Failed to read sk file");
            let sk_bytes = hex::decode(sk_hex.trim()).expect("Invalid hex in sk file");
            let sk = QryptKemHybrid1::deserialize_secret_key(&sk_bytes).expect("Deserialization error");

            let ct_hex = fs::read_to_string(&ct_file).expect("Failed to read ct file");
            let ct_bytes = hex::decode(ct_hex.trim()).expect("Invalid hex in ct file");
            let ct = QryptKemHybrid1::deserialize_ciphertext(&ct_bytes).expect("Deserialization error");

            let ss = QryptKemHybrid1::decapsulate(&sk, &ct).expect("Decaps failed");
            fs::write(&ss_out, hex::encode(ss.as_ref())).unwrap();

            println!("Decapsulated Shared Secret (HEX): {}", hex::encode(ss.as_ref()));
        }
        Commands::Sign {
            sk_file,
            msg,
            sig_out,
        } => {
            let sk_hex = fs::read_to_string(&sk_file).expect("Failed to read sk file");
            let sk_bytes = hex::decode(sk_hex.trim()).expect("Invalid hex in sk file");
            let sk = QryptSigHybrid1::deserialize_secret_key(&sk_bytes).expect("Deserialization error");

            let sig = QryptSigHybrid1::sign(&sk, msg.as_bytes(), &mut rng).expect("Sign failed");
            fs::write(&sig_out, hex::encode(QryptSigHybrid1::serialize_signature(&sig))).unwrap();

            println!("Signature successfully written to: {}", sig_out.display());
        }
        Commands::Verify {
            pk_file,
            msg,
            sig_file,
        } => {
            let pk_hex = fs::read_to_string(&pk_file).expect("Failed to read pk file");
            let pk_bytes = hex::decode(pk_hex.trim()).expect("Invalid hex in pk file");
            let pk = QryptSigHybrid1::deserialize_public_key(&pk_bytes).expect("Deserialization error");

            let sig_hex = fs::read_to_string(&sig_file).expect("Failed to read sig file");
            let sig_bytes = hex::decode(sig_hex.trim()).expect("Invalid hex in sig file");
            let sig = QryptSigHybrid1::deserialize_signature(&sig_bytes).expect("Deserialization error");

            let ok = QryptSigHybrid1::verify(&pk, msg.as_bytes(), &sig).expect("Verify error");
            if ok {
                println!("[+] VALID SIGNATURE: Verification succeeded.");
            } else {
                println!("[-] INVALID SIGNATURE: Verification FAILED.");
            }
        }
        Commands::Inspect => {
            let metrics = inspect_sizes();
            println!("{:<45} | {:<12} | {:<12} | {:<15}", "Algorithm", "PK Size (B)", "SK Size (B)", "CT/Sig Size (B)");
            println!("{:-<45}-+-{:-<12}-+-{:-<12}-+-{:-<15}", "", "", "", "");
            for m in metrics {
                println!("{:<45} | {:<12} | {:<12} | {:<15}", m.algorithm_name, m.pk_size_bytes, m.sk_size_bytes, m.ct_or_sig_size_bytes);
            }
        }
        Commands::Security => {
            println!("--- HARDNESS ESTIMATION ---");
            let lat_rep = estimate_lwe_security(256, 2, 3329, 3);
            println!("Lattice M-LWE (k=2, q=3329): Classical ~{:.1} bits, Quantum ~{:.1} bits (BKZ beta={})",
                lat_rep.classical_bit_security, lat_rep.quantum_bit_security, lat_rep.block_size_beta);

            let isd_rep = estimate_isd_security(12323, 142, 134);
            println!("Code QC-MDPC (r=12323, w=142, t=134): Lee-Brickell ISD ~{:.1} bits, Quantum ~{:.1} bits",
                isd_rep.lee_brickell_bits, isd_rep.quantum_isd_bits);

            println!("\n--- COMBINER THEORETICAL ANALYSIS ---");
            let kem_red = analyze_kem_hybrid1();
            println!("KEM Combiner: {}", kem_red.combiner_type);
            println!("  Fault Tolerance: {}", kem_red.fault_tolerance_level);
            println!("  Reduction: {}", kem_red.classical_reduction_loss);
            println!("  QROM Bound: {}", kem_red.qrom_reduction_loss);

            let sig_red = analyze_sig_hybrid1();
            println!("\nSignature Combiner: {}", sig_red.combiner_type);
            println!("  Fault Tolerance: {}", sig_red.fault_tolerance_level);
            println!("  Reduction: {}", sig_red.classical_reduction_loss);
        }
        Commands::AuditTiming { samples } => {
            println!("Running Welch's t-test timing audit ({} samples)...", samples);
            let (pk, sk) = LatticeKem::keygen(&mut rng).unwrap();
            let (valid_ct, _) = LatticeKem::encapsulate(&pk, &mut rng).unwrap();
            let mut tampered_ct = valid_ct.clone();
            tampered_ct.v.coeffs[0] ^= 1;

            let report = run_timing_audit(
                || {
                    let _ = LatticeKem::decapsulate(&sk, &valid_ct);
                },
                || {
                    let _ = LatticeKem::decapsulate(&sk, &tampered_ct);
                },
                samples,
            );

            println!("Timing Audit Results:");
            println!("  Samples: {}", report.num_samples);
            println!("  Welch t-statistic: {:.4}", report.t_statistic);
            println!("  Max |t|: {:.4} (Threshold: 4.5)", report.max_t_statistic);
            if report.is_leak_detected {
                println!("  [!] WARNING: Potential timing leak detected (|t| > 4.5)");
            } else {
                println!("  [+] PASS: No statistically significant timing leakage observed.");
            }
        }
        Commands::Test => {
            println!("Executing core cryptographic roundtrips...");
            let mut drbg = DeterministicDrbg::from_seed([1u8; 32]);

            let (lat_pk, lat_sk) = LatticeKem::keygen(&mut drbg).unwrap();
            let (lat_ct, lat_ss) = LatticeKem::encapsulate(&lat_pk, &mut drbg).unwrap();
            assert_eq!(lat_ss, LatticeKem::decapsulate(&lat_sk, &lat_ct).unwrap());
            println!("  [✓] LatticeKem roundtrip OK");

            let (code_pk, code_sk) = CodeKem::keygen(&mut drbg).unwrap();
            let (code_ct, code_ss) = CodeKem::encapsulate(&code_pk, &mut drbg).unwrap();
            assert_eq!(code_ss, CodeKem::decapsulate(&code_sk, &code_ct).unwrap());
            println!("  [✓] CodeKem roundtrip OK");

            let (hkem_pk, hkem_sk) = QryptKemHybrid1::keygen(&mut drbg).unwrap();
            let (hkem_ct, hkem_ss) = QryptKemHybrid1::encapsulate(&hkem_pk, &mut drbg).unwrap();
            assert_eq!(hkem_ss, QryptKemHybrid1::decapsulate(&hkem_sk, &hkem_ct).unwrap());
            println!("  [✓] QryptKemHybrid1 roundtrip OK");

            let (hsig_pk, hsig_sk) = HashTreeSignature::keygen(&mut drbg).unwrap();
            let hsig = HashTreeSignature::sign(&hsig_sk, b"test", &mut drbg).unwrap();
            assert!(HashTreeSignature::verify(&hsig_pk, b"test", &hsig).unwrap());
            println!("  [✓] HashTreeSignature roundtrip OK");

            let (lsig_pk, lsig_sk) = LatticeSignatureScheme::keygen(&mut drbg).unwrap();
            let lsig = LatticeSignatureScheme::sign(&lsig_sk, b"test", &mut drbg).unwrap();
            assert!(LatticeSignatureScheme::verify(&lsig_pk, b"test", &lsig).unwrap());
            println!("  [✓] LatticeSignatureScheme roundtrip OK");

            let (hyb_sig_pk, hyb_sig_sk) = QryptSigHybrid1::keygen(&mut drbg).unwrap();
            let hyb_sig = QryptSigHybrid1::sign(&hyb_sig_sk, b"test", &mut drbg).unwrap();
            assert!(QryptSigHybrid1::verify(&hyb_sig_pk, b"test", &hyb_sig).unwrap());
            println!("  [✓] QryptSigHybrid1 roundtrip OK");

            println!("\nAll self-test checks passed cleanly.");
        }
        Commands::Vectors { out_file } => {
            let mut drbg = DeterministicDrbg::from_seed([0x42u8; 32]);
            let (pk, sk) = QryptKemHybrid1::keygen(&mut drbg).unwrap();
            let (ct, ss) = QryptKemHybrid1::encapsulate(&pk, &mut drbg).unwrap();

            let json_content = format!(
                r#"{{
  "framework": "QRYPTEX",
  "version": "0.1.0",
  "seed": "4242424242424242424242424242424242424242424242424242424242424242",
  "hybrid_kem1": {{
    "pk_hex": "{}",
    "sk_hex": "{}",
    "ct_hex": "{}",
    "shared_secret_hex": "{}"
  }}
}}"#,
                hex::encode(QryptKemHybrid1::serialize_public_key(&pk)),
                hex::encode(QryptKemHybrid1::serialize_secret_key(&sk)),
                hex::encode(QryptKemHybrid1::serialize_ciphertext(&ct)),
                hex::encode(ss.as_ref())
            );

            fs::write(&out_file, json_content).expect("Failed to write test vectors");
            println!("Deterministic test vectors exported to: {}", out_file.display());
        }
        Commands::Version => {
            println!("QRYPTEX Version: 0.1.0 (Research Edition 2024 / Rust 2021)");
            println!("License: MIT OR Apache-2.0");
            println!("Architecture: Pure Rust Multi-Paradigm PQC Research Framework");
        }
    }
}

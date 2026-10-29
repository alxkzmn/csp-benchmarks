use barretenberg_bench::{Session, Target};

fn byte_fields(bytes: &[u8]) -> Vec<Vec<u8>> {
    bytes
        .iter()
        .map(|&byte| {
            let mut field = vec![0; 32];
            field[31] = byte;
            field
        })
        .collect()
}

/// Exercises our circuit preparation, witness/proof adapter and public-value
/// transport. Requires the pinned Nargo and BB executables plus their CRS cache.
#[test]
#[ignore = "requires Nargo and Barretenberg"]
fn all_workloads_preserve_public_values_and_reject_tampering() {
    let session = Session::new().unwrap();
    let mut workload_count = 0;
    for target in Target::ALL {
        for size in target.input_sizes() {
            eprintln!("Checking {}_{size}", target.name());
            let prepared = session.prepare(target, size).unwrap();
            let proof = session.prove(&prepared.prover).unwrap();
            assert!(prepared.num_gates > 0);
            assert!(prepared.preprocessing_size > 0);
            assert!(proof.proof.iter().all(|field| field.len() == 32));
            assert!(!proof.proof.is_empty());
            // With a supplied VK, the API returns no additional VK in the proof.
            assert!(proof.vk.bytes.is_empty());
            assert!(session.verify(&prepared.prover, &proof).unwrap());
            let expected = match target {
                Target::Sha256 => Some(byte_fields(&utils::generate_sha256_input(size).1)),
                Target::Blake3 => Some(byte_fields(&utils::generate_blake3_input(size).1)),
                Target::Keccak => Some(byte_fields(&utils::generate_keccak_input(size).1)),
                Target::Ecdsa => Some(byte_fields(&[1])),
                Target::Poseidon | Target::Poseidon2 => None,
            };
            if let Some(expected) = expected {
                assert_eq!(proof.public_inputs, expected);
            } else {
                assert_eq!(proof.public_inputs.len(), 1);
            }
            assert!(proof.public_inputs.iter().all(|field| field.len() == 32));
            let mut wrong_public = proof.clone();
            wrong_public.public_inputs[0][31] ^= 1;
            assert!(!session.verify(&prepared.prover, &wrong_public).unwrap());
            let mut wrong_proof = proof.clone();
            wrong_proof.proof[0][31] ^= 1;
            assert!(!session.verify(&prepared.prover, &wrong_proof).unwrap());
            workload_count += 1;
        }
    }
    eprintln!("Checked {workload_count} workloads with positive and negative verification");
}

#[test]
#[ignore = "requires Nargo and Barretenberg"]
fn rust_proof_bytes_match_the_cli_format() {
    let session = Session::new().unwrap();
    let prepared = session.prepare(Target::Blake3, 128).unwrap();
    let proof = session.prove(&prepared.prover).unwrap();
    let output =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/noir/blake3_128/target");
    let proof_path = output.join("interop-proof");
    let public_path = output.join("interop-public-inputs");
    std::fs::write(&proof_path, proof.proof.concat()).unwrap();
    std::fs::write(&public_path, proof.public_inputs.concat()).unwrap();
    let verified =
        std::process::Command::new(std::env::var_os("BB_BIN").unwrap_or_else(|| "bb".into()))
            .arg("verify")
            .arg("-p")
            .arg(&proof_path)
            .arg("-i")
            .arg(&public_path)
            .arg("-vk")
            .arg(output.join("vk"))
            .output()
            .unwrap();
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    assert_eq!(
        std::fs::metadata(proof_path).unwrap().len() as usize,
        proof.proof.iter().map(Vec::len).sum::<usize>()
    );
}

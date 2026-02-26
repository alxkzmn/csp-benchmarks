use utils::harness::ProvingSystem;

use hyperplonk::{
    hyperplonk_bench_properties, keccak::Binomial4Challenge, prepare_keccak_with_merkle_override,
    preprocessing_size, proof_size_with_merkle_override, prove_keccak, verify_keccak,
};

const SECURITY_BITS: usize = 100;
const FEATURE: &str = "binomial4_100";

utils::define_benchmark_harness!(
    BenchTarget::Keccak,
    ProvingSystem::HyperPlonk,
    Some(FEATURE),
    "keccak_mem_hyperplonk_4",
    hyperplonk_bench_properties(SECURITY_BITS as u64),
    |input_size| prepare_keccak_with_merkle_override::<Binomial4Challenge>(
        input_size,
        SECURITY_BITS,
        Some(80)
    )
    .expect("failed to prepare keccak sponge AIR"),
    hyperplonk::keccak::num_constraints,
    |prepared| prove_keccak(prepared).expect("failed to generate keccak proof"),
    |prepared, proof| verify_keccak(prepared, proof).expect("verification failed"),
    preprocessing_size,
    |proof| proof_size_with_merkle_override(proof, SECURITY_BITS, Some(80))
);

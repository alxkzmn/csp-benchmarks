use utils::harness::ProvingSystem;

use whirlaway::{
    num_constraints, prepare_keccak_with_merkle_override, preprocessing_size,
    proof_size_with_merkle_override, prove_keccak, verify_keccak, whirlaway_bench_properties,
};
use whirlaway_sys::circuits::keccak256::Binomial4Challenge;

const SECURITY_BITS: usize = 100;
const FEATURE: &str = "binomial4_100";

utils::define_benchmark_harness!(
    BenchTarget::Keccak,
    ProvingSystem::Whirlaway,
    Some(FEATURE),
    "keccak_mem_whirlaway_4",
    whirlaway_bench_properties(SECURITY_BITS as u64),
    |input_size| {
        prepare_keccak_with_merkle_override::<Binomial4Challenge>(
            input_size,
            SECURITY_BITS,
            Some(80),
        )
    },
    num_constraints,
    prove_keccak,
    |prepared, proof| verify_keccak(prepared, proof).expect("verification failed"),
    preprocessing_size,
    |proof| proof_size_with_merkle_override(proof, SECURITY_BITS, Some(80))
);

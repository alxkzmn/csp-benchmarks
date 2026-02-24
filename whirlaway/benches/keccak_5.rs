use utils::harness::ProvingSystem;

use whirlaway::{
    num_constraints, prepare_keccak, preprocessing_size, proof_size, prove_keccak, verify_keccak,
    whirlaway_bench_properties,
};
use whirlaway_sys::circuits::keccak256::QuinticChallenge;

const SECURITY_BITS: usize = 128;
const FEATURE: &str = "quintic_128";

utils::define_benchmark_harness!(
    BenchTarget::Keccak,
    ProvingSystem::Whirlaway,
    Some(FEATURE),
    "keccak_mem_whirlaway_5",
    whirlaway_bench_properties(SECURITY_BITS as u64),
    |input_size| { prepare_keccak::<QuinticChallenge>(input_size, SECURITY_BITS) },
    num_constraints,
    prove_keccak,
    |prepared, proof| verify_keccak(prepared, proof).expect("verification failed"),
    preprocessing_size,
    proof_size
);

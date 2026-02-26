use utils::harness::ProvingSystem;

use whirlaway::{
    num_constraints, prepare_keccak, preprocessing_size, proof_size_with_security_bits,
    prove_keccak, verify_keccak, whirlaway_bench_properties,
};
use whirlaway_sys::circuits::keccak256::Binomial8Challenge;

const SECURITY_BITS: usize = 128;
const FEATURE: &str = "binomial8_128";

utils::define_benchmark_harness!(
    BenchTarget::Keccak,
    ProvingSystem::Whirlaway,
    Some(FEATURE),
    "keccak_mem_whirlaway_8",
    whirlaway_bench_properties(SECURITY_BITS as u64),
    |input_size| { prepare_keccak::<Binomial8Challenge>(input_size, SECURITY_BITS) },
    num_constraints,
    prove_keccak,
    |prepared, proof| verify_keccak(prepared, proof).expect("verification failed"),
    preprocessing_size,
    |proof| proof_size_with_security_bits(proof, SECURITY_BITS)
);

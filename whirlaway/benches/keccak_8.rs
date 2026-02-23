use utils::harness::ProvingSystem;

use whirlaway::{
    WHIRLAWAY_BENCH_PROPERTIES, num_constraints, prepare_keccak, preprocessing_size, proof_size,
    prove_keccak, verify_keccak,
};
use whirlaway_sys::circuits::keccak256::Binomial8Challenge;

utils::define_benchmark_harness!(
    BenchTarget::Keccak,
    ProvingSystem::Whirlaway,
    Some("binomial8_128"),
    "keccak_mem_whirlaway_8",
    WHIRLAWAY_BENCH_PROPERTIES,
    |input_size| { prepare_keccak::<Binomial8Challenge>(input_size) },
    num_constraints,
    prove_keccak,
    |prepared, proof| verify_keccak(prepared, proof).expect("verification failed"),
    preprocessing_size,
    proof_size
);

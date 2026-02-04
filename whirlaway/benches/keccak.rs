use utils::harness::ProvingSystem;

use whirlaway::{
    WHIRLAWAY_BENCH_PROPERTIES, num_constraints, prepare_keccak, preprocessing_size, proof_size,
    prove_keccak, verify_keccak,
};

utils::define_benchmark_harness!(
    BenchTarget::Keccak,
    ProvingSystem::Whirlaway,
    None,
    "keccak_mem_whirlaway",
    WHIRLAWAY_BENCH_PROPERTIES,
    prepare_keccak,
    num_constraints,
    prove_keccak,
    |prepared, proof| verify_keccak(prepared, proof).expect("verification failed"),
    preprocessing_size,
    proof_size
);

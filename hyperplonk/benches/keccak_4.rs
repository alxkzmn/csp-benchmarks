use utils::harness::ProvingSystem;

use hyperplonk::{
    HYPERPLONK_BENCH_PROPERTIES, keccak::Binomial4Challenge, prepare_keccak, preprocessing_size,
    proof_size, prove_keccak, verify_keccak,
};

utils::define_benchmark_harness!(
    BenchTarget::Keccak,
    ProvingSystem::HyperPlonk,
    Some("binomial4_100"),
    "keccak_mem_hyperplonk_4",
    HYPERPLONK_BENCH_PROPERTIES,
    |input_size| prepare_keccak::<Binomial4Challenge>(input_size)
        .expect("failed to prepare keccak sponge AIR"),
    hyperplonk::keccak::num_constraints,
    |prepared| prove_keccak(prepared).expect("failed to generate keccak proof"),
    |prepared, proof| verify_keccak(prepared, proof).expect("verification failed"),
    preprocessing_size,
    proof_size
);

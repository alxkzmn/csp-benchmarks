use utils::harness::ProvingSystem;

use hyperplonk::{HYPERPLONK_BENCH_PROPERTIES, prepare_keccak, preprocessing_size, proof_size, prove_keccak, verify_keccak};

utils::define_benchmark_harness!(
    BenchTarget::Keccak,
    ProvingSystem::HyperPlonk,
    None,
    "keccak_mem_hyperplonk",
    HYPERPLONK_BENCH_PROPERTIES,
    |input_size| prepare_keccak(input_size).expect("failed to prepare keccak sponge AIR"),
    |prepared| hyperplonk::keccak::num_constraints(prepared),
    |prepared| prove_keccak(prepared),
    |prepared, proof| verify_keccak(prepared, proof).expect("verification failed"),
    |prepared| preprocessing_size(prepared),
    |proof| proof_size(proof)
);


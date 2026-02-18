use utils::harness::ProvingSystem;

use whir_p3::parameters::{errors::SecurityAssumption, FoldingFactor};
use whirlaway::{
    num_constraints, prepare_keccak_with_settings, preprocessing_size, proof_size, prove_keccak,
    verify_keccak, WHIRLAWAY_BENCH_PROPERTIES,
};
use whirlaway_sys::{AirSettings, UnivariateSkipMode};

utils::define_benchmark_harness!(
    BenchTarget::Keccak,
    ProvingSystem::Whirlaway,
    None,
    "keccak_mem_whirlaway",
    WHIRLAWAY_BENCH_PROPERTIES,
    |input_size| {
        let settings = AirSettings {
            security_bits: 128,
            whir_soudness_type: SecurityAssumption::CapacityBound,
            whir_folding_factor: FoldingFactor::ConstantFromSecondRound(7, 4),
            whir_log_inv_rate: 1,
            univariate_skip_mode: UnivariateSkipMode::default(),
            whir_initial_domain_reduction_factor: 5,
        };
        prepare_keccak_with_settings(input_size, settings)
    },
    num_constraints,
    prove_keccak,
    |prepared, proof| verify_keccak(prepared, proof).expect("verification failed"),
    preprocessing_size,
    proof_size
);

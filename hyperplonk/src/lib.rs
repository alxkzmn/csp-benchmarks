use std::borrow::Cow;

use anyhow::Result;
use p3_field::{BasedVectorSpace, ExtensionField, TwoAdicField};
use p3_hyperplonk::{HyperPlonkConfig, Proof};
use p3_koala_bear::KoalaBear;
use utils::harness::{AuditStatus, BenchProperties};

use crate::keccak::{
    Challenger, Dft, KeccakWhirBenchParams, Pcs, PreparedKeccak, make_config,
    make_config_with_merkle_override, prepare_with_params,
};

pub mod keccak;

/// Test-only re-exports so integration tests can access trace generation and column indices.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    pub use crate::keccak::KeccakMode;
    pub use crate::keccak::byte_sponge_air::{RATE_BYTES, RATE_U16S};
    pub use crate::keccak::byte_trace::generate_byte_traces_and_public_digest_limbs;
    pub use crate::keccak::prepare_with_mode;
    pub use crate::keccak::sponge_air::{
        BLOCK_BITS_START, DIGEST_LIMBS, OUT_BITS_START, RATE_BITS, STATE_BITS,
    };
    pub use crate::keccak::trace::generate_trace_and_public_digest_limbs;
    pub use crate::keccak::xor_lookup_air::{
        XOR_LOOKUP_COLS, XOR_LOOKUP_MULT_IDX, XOR_LOOKUP_Z_IDX,
    };
}

type Val = KoalaBear;

pub fn hyperplonk_bench_properties(security_bits: u64) -> BenchProperties {
    BenchProperties {
        security_bits,
        proving_system: Cow::Borrowed("HyperPlonk"),
        field_curve: Cow::Borrowed("KoalaBear"),
        iop: Cow::Borrowed("HyperPlonk"),
        pcs: Some(Cow::Borrowed("WHIR")),
        arithm: Cow::Borrowed("AIR"),
        is_zk: false,
        is_zkvm: false,
        is_pq: true,
        is_maintained: true,
        is_audited: AuditStatus::NotAudited,
        isa: None,
    }
}

pub fn prepare_keccak<E: ExtensionField<Val>>(
    input_size: usize,
    security_bits: usize,
) -> Result<keccak::PreparedKeccak<E>> {
    let config = make_config::<E>(security_bits);
    keccak::prepare(input_size, config)
}

pub fn prepare_keccak_with_params<E: ExtensionField<Val>>(
    input_size: usize,
    params: &KeccakWhirBenchParams,
) -> Result<keccak::PreparedKeccak<E>> {
    prepare_with_params(input_size, params)
}

pub fn prepare_keccak_with_merkle_override<E: ExtensionField<Val>>(
    input_size: usize,
    security_bits: usize,
    merkle_security_bits_override: Option<usize>,
) -> Result<keccak::PreparedKeccak<E>> {
    let config =
        make_config_with_merkle_override::<E>(security_bits, merkle_security_bits_override);
    keccak::prepare(input_size, config)
}

pub fn prove_keccak<E: ExtensionField<Val> + TwoAdicField>(
    prepared: &PreparedKeccak<E>,
) -> Result<(
    Vec<Val>,
    Proof<HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger>>,
)> {
    keccak::prove(prepared)
}

pub fn verify_keccak<E: ExtensionField<Val> + TwoAdicField>(
    prepared: &PreparedKeccak<E>,
    proof: &(
        Vec<Val>,
        Proof<HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger>>,
    ),
) -> Result<()> {
    keccak::verify(prepared, proof)
}

pub fn preprocessing_size<E: ExtensionField<Val>>(prepared: &PreparedKeccak<E>) -> usize {
    keccak::preprocessing_size(prepared)
}

pub fn proof_size<E: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy>(
    proof: &(
        Vec<Val>,
        Proof<HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger>>,
    ),
    security_bits: usize,
) -> usize {
    proof_size_with_merkle_override(proof, security_bits, None)
}

pub fn proof_size_with_merkle_override<
    E: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy,
>(
    proof: &(
        Vec<Val>,
        Proof<HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger>>,
    ),
    security_bits: usize,
    merkle_security_bits_override: Option<usize>,
) -> usize {
    keccak::proof_size_with_merkle_override(
        &proof.0,
        &proof.1,
        security_bits,
        merkle_security_bits_override,
    )
}

pub fn proof_size_with_params<
    E: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy,
>(
    proof: &(
        Vec<Val>,
        Proof<HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger>>,
    ),
    params: &KeccakWhirBenchParams,
) -> usize {
    keccak::proof_size_with_merkle_override(
        &proof.0,
        &proof.1,
        params.security_bits,
        params.merkle_security_bits_override,
    )
}

pub fn proof_size_v2<E: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy>(
    proof: &(
        Vec<Val>,
        Proof<HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger>>,
    ),
) -> usize {
    keccak::proof_size_v2(&proof.0, &proof.1)
}

pub fn proof_size_v1<E: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy>(
    proof: &(
        Vec<Val>,
        Proof<HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger>>,
    ),
) -> usize {
    keccak::proof_size_v1(&proof.0, &proof.1)
}

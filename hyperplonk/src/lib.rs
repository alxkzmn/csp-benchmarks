use std::borrow::Cow;

use anyhow::Result;
use p3_field::{BasedVectorSpace, ExtensionField, TwoAdicField};
use p3_hyperplonk::{HyperPlonkConfig, Proof};
use p3_koala_bear::KoalaBear;
use utils::harness::{AuditStatus, BenchProperties};

use crate::keccak::{Challenger, Dft, Pcs, PreparedKeccak, make_config};

pub mod keccak;

/// Test-only re-exports so integration tests can access trace generation and column indices.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    pub use crate::keccak::sponge_air::{
        BLOCK_BITS_START, DIGEST_LIMBS, OUT_BITS_START, RATE_BITS, STATE_BITS,
    };
    pub use crate::keccak::trace::generate_trace_and_public_digest_limbs;
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
) -> usize {
    keccak::proof_size(&proof.0, &proof.1)
}

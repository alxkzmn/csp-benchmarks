use std::borrow::Cow;

use anyhow::Result;
use utils::harness::{AuditStatus, BenchProperties};

pub mod keccak;

pub const HYPERPLONK_BENCH_PROPERTIES: BenchProperties = BenchProperties {
    proving_system: Cow::Borrowed("HyperPlonk"),
    field_curve: Cow::Borrowed("KoalaBear"),
    iop: Cow::Borrowed("HyperPlonk"),
    pcs: Some(Cow::Borrowed("WHIR")),
    arithm: Cow::Borrowed("AIR"),
    is_zk: false,
    is_zkvm: false,
    // p3-playground example uses security_level=100 as a placeholder.
    security_bits: 100,
    // WHIR is Keccak-based (hash-based PCS); treat as PQ for this benchmark suite.
    is_pq: true,
    is_maintained: true,
    is_audited: AuditStatus::NotAudited,
    isa: None,
};

pub type PreparedKeccak = keccak::PreparedKeccak;
pub type KeccakProof = keccak::KeccakProof;

pub fn prepare_keccak(input_size: usize) -> Result<PreparedKeccak> {
    keccak::prepare(input_size)
}

pub fn prove_keccak(prepared: &PreparedKeccak) -> KeccakProof {
    keccak::prove(prepared)
}

pub fn verify_keccak(prepared: &PreparedKeccak, proof: &KeccakProof) -> Result<()> {
    keccak::verify(prepared, proof)
}

pub fn preprocessing_size(prepared: &PreparedKeccak) -> usize {
    keccak::preprocessing_size(prepared)
}

pub fn proof_size(proof: &KeccakProof) -> usize {
    keccak::proof_size(proof)
}

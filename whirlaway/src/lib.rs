use std::borrow::Cow;

use anyhow::Result;
use utils::harness::{AuditStatus, BenchProperties};
use whirlaway_sys::AirSettings;
use whirlaway_sys::circuits::keccak256::Keccak256Circuit;
use whirlaway_sys::hashers::KECCAK_DIGEST_ELEMS;
use whirlaway_sys::proving_system::{self, KeccakProvingSystemConfig, Prepared};

pub const WHIRLAWAY_BENCH_PROPERTIES: BenchProperties = BenchProperties {
    proving_system: Cow::Borrowed("Whirlaway"),
    field_curve: Cow::Borrowed("KoalaBear"),
    iop: Cow::Borrowed("Whirlaway"),
    pcs: Some(Cow::Borrowed("WHIR")),
    arithm: Cow::Borrowed("AIR"),
    is_zk: false,
    is_zkvm: false,
    security_bits: 128,
    is_pq: true,
    is_maintained: false,
    is_audited: AuditStatus::NotAudited,
    isa: None,
};

type PreparedKeccak =
    Prepared<Keccak256Circuit, KeccakProvingSystemConfig, { KECCAK_DIGEST_ELEMS }>;
type KeccakProof = proving_system::Proof<Keccak256Circuit, { KECCAK_DIGEST_ELEMS }>;

pub fn prepare_keccak(input_size: usize) -> PreparedKeccak {
    let circuit = Keccak256Circuit { input_size };
    let settings = KeccakProvingSystemConfig {
        air_settings: AirSettings::default(),
    };
    proving_system::prepare::<Keccak256Circuit, KeccakProvingSystemConfig, { KECCAK_DIGEST_ELEMS }>(
        &settings, circuit,
    )
}

pub fn prepare_keccak_with_settings(input_size: usize, settings: AirSettings) -> PreparedKeccak {
    let circuit = Keccak256Circuit { input_size };
    let settings = KeccakProvingSystemConfig {
        air_settings: settings,
    };
    proving_system::prepare::<Keccak256Circuit, KeccakProvingSystemConfig, { KECCAK_DIGEST_ELEMS }>(
        &settings, circuit,
    )
}

pub fn prove_keccak(prepared: &PreparedKeccak) -> KeccakProof {
    let (message, _digest) = utils::generate_keccak_input(prepared.circuit.input_size);
    proving_system::prove(prepared, &message)
}

pub fn verify_keccak(prepared: &PreparedKeccak, proof: &KeccakProof) -> Result<()> {
    proving_system::verify(prepared, proof).map_err(anyhow::Error::msg)
}

pub fn preprocessing_size(prepared: &PreparedKeccak) -> usize {
    proving_system::preprocessing_size(prepared)
}

pub fn proof_size(proof: &KeccakProof) -> usize {
    proving_system::proof_size(proof)
}

pub fn num_constraints(prepared: &PreparedKeccak) -> usize {
    proving_system::num_constraints(prepared)
}

use std::borrow::Cow;

use anyhow::Result;
use utils::harness::{AuditStatus, BenchProperties};
use whirlaway_sys::circuits::keccak256::{Keccak256Circuit, Keccak256Input, F};
use whirlaway_sys::hashers::KECCAK_DIGEST_ELEMS;
use whirlaway_sys::proving_system::{self, Circuit, KeccakProvingSystemConfig, Prepared};
use whirlaway_sys::AirSettings;

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

pub fn prove_keccak(prepared: &PreparedKeccak) -> (KeccakProof, Vec<F>) {
    let (message, digest) = utils::generate_keccak_input(prepared.circuit.input_size);
    let message = Keccak256Input {
        message,
        expected_digest: digest.try_into().expect("Digest length mismatch"),
    };
    let public_values = Keccak256Circuit::public_values(&prepared.circuit, &message);
    let proof = proving_system::prove(prepared, &message);
    (proof, public_values)
}

pub fn verify_keccak(
    prepared: &PreparedKeccak,
    proof_with_digest: &(KeccakProof, Vec<F>),
) -> Result<()> {
    proving_system::verify(prepared, &proof_with_digest.0, &proof_with_digest.1)
        .map_err(anyhow::Error::msg)
}

pub fn preprocessing_size(prepared: &PreparedKeccak) -> usize {
    proving_system::preprocessing_size(prepared)
}

pub fn proof_size(proof_with_input: &(KeccakProof, Vec<F>)) -> usize {
    proving_system::proof_size(&proof_with_input.0)
}

pub fn num_constraints(prepared: &PreparedKeccak) -> usize {
    proving_system::num_constraints(prepared)
}

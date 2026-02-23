use std::borrow::Cow;

use anyhow::Result;
use p3_field::{BasedVectorSpace, ExtensionField, TwoAdicField};
use utils::harness::{AuditStatus, BenchProperties};
use whirlaway_sys::AirSettings;
use whirlaway_sys::circuits::keccak256::{
    Binomial8Challenge, F as KeccakBaseField, Keccak256Circuit, Keccak256Input,
};
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

pub type DefaultExtension = Binomial8Challenge;

pub type KeccakPrepared<EF> = Prepared<
    Keccak256Circuit<EF>,
    KeccakProvingSystemConfig<EF>,
    KeccakBaseField,
    EF,
    { KECCAK_DIGEST_ELEMS },
>;
pub type KeccakProof<EF> =
    proving_system::Proof<Keccak256Circuit<EF>, KeccakBaseField, EF, { KECCAK_DIGEST_ELEMS }>;

pub fn default_air_settings_for_extension<EF>() -> AirSettings
where
    EF: ExtensionField<KeccakBaseField> + TwoAdicField,
{
    let mut settings = AirSettings::default();
    settings.security_bits = if <EF as BasedVectorSpace<KeccakBaseField>>::DIMENSION == 4 {
        100
    } else {
        128
    };
    settings
}

pub fn prepare_keccak<EF>(input_size: usize) -> KeccakPrepared<EF>
where
    EF: ExtensionField<KeccakBaseField> + TwoAdicField,
{
    prepare_keccak_with_settings(input_size, default_air_settings_for_extension::<EF>())
}

pub fn prepare_keccak_with_settings<EF>(
    input_size: usize,
    settings: AirSettings,
) -> KeccakPrepared<EF>
where
    EF: ExtensionField<KeccakBaseField> + TwoAdicField,
{
    let circuit = Keccak256Circuit::<EF>::new(input_size);
    let proving_settings = KeccakProvingSystemConfig::<EF>::new(settings);
    proving_system::prepare(&proving_settings, circuit)
}

pub fn prove_keccak<EF>(prepared: &KeccakPrepared<EF>) -> (KeccakProof<EF>, Vec<KeccakBaseField>)
where
    EF: ExtensionField<KeccakBaseField> + TwoAdicField + Default,
{
    let (message, digest) = utils::generate_keccak_input(prepared.circuit.input_size);
    let message = Keccak256Input {
        message,
        expected_digest: digest.try_into().expect("Digest length mismatch"),
    };
    let public_values = Keccak256Circuit::<EF>::public_values(&prepared.circuit, &message);
    let proof = proving_system::prove(prepared, &message);
    (proof, public_values)
}

pub fn verify_keccak<EF>(
    prepared: &KeccakPrepared<EF>,
    proof_with_digest: &(KeccakProof<EF>, Vec<KeccakBaseField>),
) -> Result<()>
where
    EF: ExtensionField<KeccakBaseField> + TwoAdicField,
{
    proving_system::verify(prepared, &proof_with_digest.0, &proof_with_digest.1)
        .map_err(anyhow::Error::msg)
}

pub fn preprocessing_size<EF>(prepared: &KeccakPrepared<EF>) -> usize
where
    EF: ExtensionField<KeccakBaseField> + TwoAdicField,
{
    proving_system::preprocessing_size(prepared)
}

pub fn proof_size<EF>(proof_with_input: &(KeccakProof<EF>, Vec<KeccakBaseField>)) -> usize
where
    EF: ExtensionField<KeccakBaseField> + TwoAdicField,
{
    proving_system::proof_size(&proof_with_input.0)
}

pub fn num_constraints<EF>(prepared: &KeccakPrepared<EF>) -> usize
where
    EF: ExtensionField<KeccakBaseField> + TwoAdicField,
{
    proving_system::num_constraints(prepared)
}

#[cfg(test)]
mod tests {
    use super::default_air_settings_for_extension;
    use whirlaway_sys::circuits::keccak256::{
        Binomial4Challenge, Binomial8Challenge, QuinticChallenge,
    };

    #[test]
    fn default_security_bits_follow_extension_policy() {
        assert_eq!(
            default_air_settings_for_extension::<Binomial4Challenge>().security_bits,
            100
        );
        assert_eq!(
            default_air_settings_for_extension::<Binomial8Challenge>().security_bits,
            128
        );
        assert_eq!(
            default_air_settings_for_extension::<QuinticChallenge>().security_bits,
            128
        );
    }
}

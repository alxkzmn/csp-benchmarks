#[cfg(not(any(test, feature = "test-utils")))]
pub(crate) mod sponge_air;
#[cfg(any(test, feature = "test-utils"))]
pub mod sponge_air;

#[cfg(not(any(test, feature = "test-utils")))]
pub(crate) mod trace;
#[cfg(any(test, feature = "test-utils"))]
pub mod trace;

#[cfg(not(any(test, feature = "test-utils")))]
pub(crate) mod byte_sponge_air;
#[cfg(any(test, feature = "test-utils"))]
pub mod byte_sponge_air;

#[cfg(not(any(test, feature = "test-utils")))]
pub(crate) mod byte_trace;
#[cfg(any(test, feature = "test-utils"))]
pub mod byte_trace;

#[cfg(not(any(test, feature = "test-utils")))]
pub(crate) mod xor_lookup_air;
#[cfg(any(test, feature = "test-utils"))]
pub mod xor_lookup_air;

use anyhow::{Context, Result, anyhow, bail};
use p3_air::{Air, AirBuilderWithPublicValues, BaseAir, BaseAirWithPublicValues};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_dft::Radix2DitParallel;
use p3_field::extension::{BinomialExtensionField, QuinticTrinomialExtensionField};
use p3_field::{BasedVectorSpace, ExtensionField, TwoAdicField};
use p3_hyperplonk::{
    HyperPlonkConfig, InteractionBuilder, ProverInput, VerifierInput, evm_codec, keygen,
    prove as hyperprove, verify as hyperverify,
};
use p3_keccak::Keccak256Hash;
use p3_koala_bear::KoalaBear;
use p3_whir::{
    FoldingFactor, KeccakNodeCompress, KeccakU32BeLeafHasher, ProtocolParameters,
    SecurityAssumption, WhirPcs,
};

use crate::keccak::byte_sponge_air::{ByteSpongeAir, RATE_BYTES};
use crate::keccak::sponge_air::KeccakSpongeAir;
use crate::keccak::xor_lookup_air::XorLookupAir;

pub const XOR_BUS: usize = 0;

type Val = KoalaBear;
pub type Binomial4Challenge = BinomialExtensionField<Val, 4>;
pub type Binomial8Challenge = BinomialExtensionField<Val, 8>;
pub type QuinticChallenge = QuinticTrinomialExtensionField<Val>;
type FieldHash = KeccakU32BeLeafHasher;
type Compress = KeccakNodeCompress;
pub type Dft<Val> = Radix2DitParallel<Val>;
pub type Pcs<Val, Dft> = WhirPcs<Val, Dft, FieldHash, Compress, 4>;
pub type Challenger = SerializingChallenger32<Val, HashChallenger<u8, Keccak256Hash, 32>>;

pub type HyperConfig4 = HyperPlonkConfig<Pcs<Val, Dft<Val>>, Binomial4Challenge, Challenger>;
pub type HyperConfig8 = HyperPlonkConfig<Pcs<Val, Dft<Val>>, Binomial8Challenge, Challenger>;

pub type KeccakProof4 = p3_hyperplonk::Proof<HyperConfig4>;
pub type KeccakProof8 = p3_hyperplonk::Proof<HyperConfig8>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeccakMode {
    LegacyBitSponge,
    ByteSpongeWithXorLookup,
    SingleBlockNoLookup,
}

impl Default for KeccakMode {
    fn default() -> Self {
        Self::LegacyBitSponge
    }
}

pub const DEFAULT_KECCAK_MODE: KeccakMode = KeccakMode::LegacyBitSponge;

#[derive(Clone, Debug)]
pub enum KeccakAirVariant {
    LegacyBitSponge(KeccakSpongeAir),
    ByteSponge(ByteSpongeAir),
    XorLookup(XorLookupAir),
}

impl<F> BaseAir<F> for KeccakAirVariant {
    fn width(&self) -> usize {
        match self {
            Self::LegacyBitSponge(inner) => BaseAir::<F>::width(inner),
            Self::ByteSponge(inner) => BaseAir::<F>::width(inner),
            Self::XorLookup(inner) => BaseAir::<F>::width(inner),
        }
    }
}

impl<F> BaseAirWithPublicValues<F> for KeccakAirVariant {
    fn num_public_values(&self) -> usize {
        match self {
            Self::LegacyBitSponge(inner) => BaseAirWithPublicValues::<F>::num_public_values(inner),
            Self::ByteSponge(inner) => BaseAirWithPublicValues::<F>::num_public_values(inner),
            Self::XorLookup(inner) => BaseAirWithPublicValues::<F>::num_public_values(inner),
        }
    }
}

impl<AB: InteractionBuilder + AirBuilderWithPublicValues> Air<AB> for KeccakAirVariant {
    fn eval(&self, builder: &mut AB) {
        match self {
            Self::LegacyBitSponge(inner) => inner.eval(builder),
            Self::ByteSponge(inner) => inner.eval(builder),
            Self::XorLookup(inner) => inner.eval(builder),
        }
    }
}

pub struct PreparedKeccak<E: ExtensionField<Val>> {
    pub input_size: usize,
    pub mode: KeccakMode,
    pub config: HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger>,
    pub airs: Vec<KeccakAirVariant>,
    pub pk: p3_hyperplonk::ProvingKey,
    pub vk: p3_hyperplonk::VerifyingKey,
}

#[derive(Clone, Debug)]
pub struct KeccakWhirBenchParams {
    pub security_bits: usize,
    pub soundness_type: SecurityAssumption,
    pub starting_log_inv_rate: usize,
    pub pow_bits: usize,
    pub folding_factor: FoldingFactor,
    pub rs_domain_initial_reduction_factor: usize,
    pub univariate_skip_rounds: usize,
    pub merkle_security_bits_override: Option<usize>,
}

impl KeccakWhirBenchParams {
    pub const fn baseline(security_bits: usize) -> Self {
        Self {
            security_bits,
            soundness_type: SecurityAssumption::CapacityBound,
            starting_log_inv_rate: 1,
            pow_bits: 20,
            folding_factor: FoldingFactor::Constant(4),
            rs_domain_initial_reduction_factor: 3,
            univariate_skip_rounds: p3_hyperplonk::DEFAULT_UNIVARIATE_SKIP_ROUNDS,
            merkle_security_bits_override: None,
        }
    }

    pub fn effective_merkle_security_bits(&self) -> usize {
        p3_whir::resolve_effective_merkle_security_bits(
            self.security_bits,
            self.merkle_security_bits_override,
        )
    }
}

pub fn make_config_with_params<E: ExtensionField<Val>>(
    params: &KeccakWhirBenchParams,
) -> HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger> {
    let dft = Dft::<Val>::default();
    let effective_merkle_security_bits = params.effective_merkle_security_bits();
    let field_hash = FieldHash::for_security_bits(effective_merkle_security_bits);
    let compress = Compress::for_security_bits(effective_merkle_security_bits);
    let whir_params = ProtocolParameters {
        security_level: params.security_bits,
        pow_bits: params.pow_bits,
        folding_factor: params.folding_factor,
        merkle_hash: field_hash,
        merkle_compress: compress,
        soundness_type: params.soundness_type,
        starting_log_inv_rate: params.starting_log_inv_rate,
        rs_domain_initial_reduction_factor: params.rs_domain_initial_reduction_factor,
    };

    HyperPlonkConfig::<_, E, _>::new(
        Pcs::new(dft, whir_params),
        Challenger::from_hasher(Vec::new(), Keccak256Hash),
    )
    .with_univariate_skip_rounds(params.univariate_skip_rounds)
}

pub fn make_config<E: ExtensionField<Val>>(
    security_bits: usize,
) -> HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger> {
    let params = KeccakWhirBenchParams::baseline(security_bits);
    make_config_with_params::<E>(&params)
}

pub fn make_config_with_merkle_override<E: ExtensionField<Val>>(
    security_bits: usize,
    merkle_security_bits_override: Option<usize>,
) -> HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger> {
    let mut params = KeccakWhirBenchParams::baseline(security_bits);
    params.merkle_security_bits_override = merkle_security_bits_override;
    make_config_with_params::<E>(&params)
}

pub fn prepare_with_params<E: ExtensionField<Val>>(
    input_size: usize,
    params: &KeccakWhirBenchParams,
) -> Result<PreparedKeccak<E>> {
    let config = make_config_with_params::<E>(params);
    prepare(input_size, config)
}

fn build_airs(mode: KeccakMode) -> Vec<KeccakAirVariant> {
    match mode {
        KeccakMode::LegacyBitSponge => {
            vec![KeccakAirVariant::LegacyBitSponge(KeccakSpongeAir::new())]
        }
        KeccakMode::ByteSpongeWithXorLookup => vec![
            KeccakAirVariant::ByteSponge(ByteSpongeAir::new_lookup()),
            KeccakAirVariant::XorLookup(XorLookupAir::new()),
        ],
        KeccakMode::SingleBlockNoLookup => {
            vec![KeccakAirVariant::ByteSponge(
                ByteSpongeAir::new_single_block_no_lookup(),
            )]
        }
    }
}

const SINGLE_BLOCK_NO_LOOKUP_MAX_INPUT_SIZE: usize = RATE_BYTES - 1;

fn validate_mode_input_size(mode: KeccakMode, input_size: usize) -> Result<()> {
    if mode == KeccakMode::SingleBlockNoLookup && input_size > SINGLE_BLOCK_NO_LOOKUP_MAX_INPUT_SIZE
    {
        bail!(
            "SingleBlockNoLookup requires input_size <= {}; got {}",
            SINGLE_BLOCK_NO_LOOKUP_MAX_INPUT_SIZE,
            input_size
        );
    }
    Ok(())
}

fn per_air_public_inputs(public_values: &[Val], air_count: usize) -> Vec<Vec<Val>> {
    (0..air_count)
        .map(|idx| {
            if idx == 0 {
                public_values.to_vec()
            } else {
                Vec::new()
            }
        })
        .collect()
}

pub fn prepare_with_mode<E: ExtensionField<Val>>(
    input_size: usize,
    config: HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger>,
    mode: KeccakMode,
) -> Result<PreparedKeccak<E>> {
    validate_mode_input_size(mode, input_size)?;
    let airs = build_airs(mode);
    let air_refs: Vec<&KeccakAirVariant> = airs.iter().collect();
    let (vk, pk) = keygen::<Val, _>(air_refs);
    Ok(PreparedKeccak {
        input_size,
        mode,
        config,
        airs,
        pk,
        vk,
    })
}

pub fn prepare<E: ExtensionField<Val>>(
    input_size: usize,
    config: HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger>,
) -> Result<PreparedKeccak<E>> {
    prepare_with_mode(input_size, config, DEFAULT_KECCAK_MODE)
}

pub fn prove<E: ExtensionField<Val> + TwoAdicField>(
    prepared: &PreparedKeccak<E>,
) -> Result<(
    Vec<Val>,
    p3_hyperplonk::Proof<HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger>>,
)> {
    validate_mode_input_size(prepared.mode, prepared.input_size)?;
    if prepared.airs.is_empty() {
        bail!("prepared keccak has no AIRs");
    }

    let (public_values, prover_inputs) = match prepared.mode {
        KeccakMode::LegacyBitSponge => {
            let legacy_air = prepared
                .airs
                .first()
                .cloned()
                .ok_or_else(|| anyhow!("missing legacy AIR"))?;
            let (trace, digest_limbs) =
                trace::generate_trace_and_public_digest_limbs::<Val>(prepared.input_size)
                    .context("failed to build legacy keccak sponge trace")?;
            let public_values: Vec<Val> = digest_limbs
                .iter()
                .map(|&limb| Val::new(limb as u32))
                .collect();
            let prover_inputs = vec![ProverInput::new(legacy_air, public_values.clone(), trace)];
            (public_values, prover_inputs)
        }
        KeccakMode::ByteSpongeWithXorLookup => {
            if prepared.airs.len() != 2 {
                bail!(
                    "byte-sponge mode expects exactly 2 AIRs, got {}",
                    prepared.airs.len()
                );
            }
            let (sponge_trace, lookup_trace, digest_limbs) =
                byte_trace::generate_byte_traces_and_public_digest_limbs::<Val>(
                    prepared.input_size,
                )
                .context("failed to build byte sponge + xor lookup traces")?;
            let public_values: Vec<Val> = digest_limbs
                .iter()
                .map(|&limb| Val::new(limb as u32))
                .collect();
            let prover_inputs = vec![
                ProverInput::new(
                    prepared.airs[0].clone(),
                    public_values.clone(),
                    sponge_trace,
                ),
                ProverInput::new(prepared.airs[1].clone(), Vec::new(), lookup_trace),
            ];
            (public_values, prover_inputs)
        }
        KeccakMode::SingleBlockNoLookup => {
            if prepared.airs.len() != 1 {
                bail!(
                    "single-block no-lookup mode expects exactly 1 AIR, got {}",
                    prepared.airs.len()
                );
            }
            let byte_air = prepared
                .airs
                .first()
                .cloned()
                .ok_or_else(|| anyhow!("missing byte sponge AIR"))?;
            let (sponge_trace, _lookup_trace, digest_limbs) =
                byte_trace::generate_byte_traces_and_public_digest_limbs::<Val>(
                    prepared.input_size,
                )
                .context("failed to build byte sponge trace")?;
            let public_values: Vec<Val> = digest_limbs
                .iter()
                .map(|&limb| Val::new(limb as u32))
                .collect();
            let prover_inputs = vec![ProverInput::new(
                byte_air,
                public_values.clone(),
                sponge_trace,
            )];
            (public_values, prover_inputs)
        }
    };

    Ok((
        public_values,
        hyperprove(&prepared.config, &prepared.pk, prover_inputs),
    ))
}

pub fn verify<E: ExtensionField<Val> + TwoAdicField>(
    prepared: &PreparedKeccak<E>,
    proof: &(
        Vec<Val>,
        p3_hyperplonk::Proof<HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger>>,
    ),
) -> Result<()> {
    let public_inputs = per_air_public_inputs(&proof.0, prepared.airs.len());
    let verifier_inputs = prepared
        .airs
        .iter()
        .cloned()
        .zip(public_inputs)
        .map(|(air, public_values)| VerifierInput::new(air, public_values))
        .collect();

    hyperverify(&prepared.config, &prepared.vk, verifier_inputs, &proof.1)
        .map_err(|e| anyhow!("hyperplonk verification failed: {e:?}"))
}

pub fn preprocessing_size<E: ExtensionField<Val>>(prepared: &PreparedKeccak<E>) -> usize {
    bincode::serialize(&prepared.pk)
        .map(|v| v.len())
        .unwrap_or(0)
}

pub fn proof_size<E: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy>(
    public_values: &[Val],
    proof: &p3_hyperplonk::Proof<HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger>>,
    security_bits: usize,
) -> usize {
    proof_size_with_merkle_override(public_values, proof, security_bits, None)
}

pub fn proof_size_with_merkle_override<
    E: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy,
>(
    public_values: &[Val],
    proof: &p3_hyperplonk::Proof<HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger>>,
    security_bits: usize,
    merkle_security_bits_override: Option<usize>,
) -> usize {
    let public_inputs = per_air_public_inputs(public_values, proof.log_bs.len());
    let effective_merkle_security_bits = p3_whir::resolve_effective_merkle_security_bits(
        security_bits,
        merkle_security_bits_override,
    );
    let effective_digest_bytes =
        p3_whir::effective_digest_bytes_for_security_bits(effective_merkle_security_bits);
    let proof_blob =
        evm_codec::encode_proof_blob_v3_generic(&public_inputs, proof, effective_digest_bytes);
    evm_codec::encode_calldata_verify_bytes(&proof_blob).len()
}

pub fn proof_size_v2<E: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy>(
    public_values: &[Val],
    proof: &p3_hyperplonk::Proof<HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger>>,
) -> usize {
    let public_inputs = per_air_public_inputs(public_values, proof.log_bs.len());
    let proof_blob = evm_codec::encode_proof_blob_v2_generic(&public_inputs, proof);
    evm_codec::encode_calldata_verify_bytes(&proof_blob).len()
}

pub fn proof_size_v1<E: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy>(
    public_values: &[Val],
    proof: &p3_hyperplonk::Proof<HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger>>,
) -> usize {
    let public_inputs = per_air_public_inputs(public_values, proof.log_bs.len());
    let proof_blob = evm_codec::encode_proof_blob_v1_generic(&public_inputs, proof);
    evm_codec::encode_calldata_verify_bytes(&proof_blob).len()
}

pub fn num_constraints<E: ExtensionField<Val>>(prepared: &PreparedKeccak<E>) -> usize {
    prepared
        .vk
        .metas()
        .iter()
        .map(|meta| meta.constraint_count)
        .sum()
}

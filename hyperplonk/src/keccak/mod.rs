#[cfg(not(any(test, feature = "test-utils")))]
pub(crate) mod sponge_air;
#[cfg(any(test, feature = "test-utils"))]
pub mod sponge_air;

#[cfg(not(any(test, feature = "test-utils")))]
pub(crate) mod trace;
#[cfg(any(test, feature = "test-utils"))]
pub mod trace;

use anyhow::{Context, Result};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_dft::Radix2DitParallel;
use p3_field::extension::{BinomialExtensionField, QuinticTrinomialExtensionField};
use p3_field::{BasedVectorSpace, ExtensionField, TwoAdicField};
use p3_hyperplonk::{
    HyperPlonkConfig, ProverInput, VerifierInput, evm_codec, keygen, prove as hyperprove,
    verify as hyperverify,
};
use p3_keccak::Keccak256Hash;
use p3_koala_bear::KoalaBear;
use p3_whir::{
    FoldingFactor, KeccakNodeCompress, KeccakU32BeLeafHasher, ProtocolParameters,
    SecurityAssumption, WhirPcs,
};

use crate::keccak::sponge_air::KeccakSpongeAir;

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

pub struct PreparedKeccak<E: ExtensionField<Val>> {
    pub input_size: usize,
    pub config: HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger>,
    pub air: KeccakSpongeAir,
    pub pk: p3_hyperplonk::ProvingKey,
    pub vk: p3_hyperplonk::VerifyingKey,
}

pub fn make_config<E: ExtensionField<Val>>(
    security_bits: usize,
) -> HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger> {
    let dft = Dft::<Val>::default();
    let pow_bits = 20;
    let field_hash = FieldHash::for_security_bits(security_bits);
    let compress = Compress::for_security_bits(security_bits);
    let whir_params = ProtocolParameters {
        security_level: security_bits,
        pow_bits,
        folding_factor: FoldingFactor::Constant(4),
        merkle_hash: field_hash,
        merkle_compress: compress,
        soundness_type: SecurityAssumption::CapacityBound,
        starting_log_inv_rate: 1,
        rs_domain_initial_reduction_factor: 3,
    };

    HyperPlonkConfig::<_, E, _>::new(
        Pcs::new(dft, whir_params),
        Challenger::from_hasher(Vec::new(), Keccak256Hash),
    )
}

pub fn prepare<E: ExtensionField<Val>>(
    input_size: usize,
    config: HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger>,
) -> Result<PreparedKeccak<E>> {
    let air = KeccakSpongeAir::new();
    let (vk, pk) = keygen::<Val, _>([&air]);
    Ok(PreparedKeccak {
        input_size,
        config,
        air,
        pk,
        vk,
    })
}

pub fn prove<E: ExtensionField<Val> + TwoAdicField>(
    prepared: &PreparedKeccak<E>,
) -> Result<(
    Vec<Val>,
    p3_hyperplonk::Proof<HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger>>,
)> {
    // Build Keccak sponge trace from deterministic input and export digest limbs as public values.
    let (trace, digest_limbs) =
        trace::generate_trace_and_public_digest_limbs::<Val>(prepared.input_size)
            .context("failed to build keccak sponge trace")?;

    let public_values: Vec<Val> = digest_limbs
        .iter()
        .map(|&limb| Val::new(limb as u32))
        .collect();

    let prover_inputs = vec![ProverInput::new(
        prepared.air.clone(),
        public_values.clone(),
        trace,
    )];
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
    let verifier_inputs = vec![VerifierInput::new(prepared.air.clone(), proof.0.clone())];
    hyperverify(&prepared.config, &prepared.vk, verifier_inputs, &proof.1)
        .map_err(|e| anyhow::anyhow!("hyperplonk verification failed: {e:?}"))
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
    let public_inputs = [public_values.to_vec()];
    let proof_blob = evm_codec::encode_proof_blob_v3_generic(
        &public_inputs,
        proof,
        p3_whir::effective_digest_bytes_for_security_bits(security_bits),
    );
    evm_codec::encode_calldata_verify_bytes(&proof_blob).len()
}

pub fn proof_size_v2<E: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy>(
    public_values: &[Val],
    proof: &p3_hyperplonk::Proof<HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger>>,
) -> usize {
    let public_inputs = [public_values.to_vec()];
    let proof_blob = evm_codec::encode_proof_blob_v2_generic(&public_inputs, proof);
    evm_codec::encode_calldata_verify_bytes(&proof_blob).len()
}

pub fn proof_size_v1<E: ExtensionField<Val> + TwoAdicField + BasedVectorSpace<Val> + Copy>(
    public_values: &[Val],
    proof: &p3_hyperplonk::Proof<HyperPlonkConfig<Pcs<Val, Dft<Val>>, E, Challenger>>,
) -> usize {
    let public_inputs = [public_values.to_vec()];
    let proof_blob = evm_codec::encode_proof_blob_v1_generic(&public_inputs, proof);
    evm_codec::encode_calldata_verify_bytes(&proof_blob).len()
}

pub fn num_constraints<E: ExtensionField<Val>>(prepared: &PreparedKeccak<E>) -> usize {
    prepared
        .vk
        .metas()
        .first()
        .map(|m| m.constraint_count)
        .unwrap_or(0)
}

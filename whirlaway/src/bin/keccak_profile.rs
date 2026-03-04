use std::env;
use std::fmt::{self, Write as _};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tracing::{info, info_span};
use tracing_forest::{ForestLayer, PrettyPrinter};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::{Registry, layer::SubscriberExt, util::SubscriberInitExt};
use whir_p3::parameters::{FoldingFactor, errors::SecurityAssumption};
use whirlaway::KeccakProof;
use whirlaway_sys::circuits::keccak256::{
    Binomial4Challenge, F as KeccakBaseField, Keccak256Circuit, KeccakMode,
};
use whirlaway_sys::evm_codec::{
    count_merkle_digests_in_proof, encode_calldata_verify_bytes, encode_proof_blob_v3_generic,
    estimate_calldata_gas,
};
use whirlaway_sys::hashers::{
    KECCAK_DIGEST_ELEMS, effective_digest_bytes_for_security_bits,
    resolve_effective_merkle_security_bits,
};
use whirlaway_sys::proving_system::Circuit;

const SECURITY_BITS: usize = 100;
const INPUT_SIZE: usize = 128;
const RAM_RUNS: usize = 1;
const POW_BITS: usize = 16;
const MODE: KeccakMode = KeccakMode::ByteSpongeAlgebraic;

type Challenge = Binomial4Challenge;

#[derive(Clone, Copy)]
enum TreeIndent {
    Null,
    Line,
    Fork,
    Turn,
}

impl TreeIndent {
    fn repr(self) -> &'static str {
        match self {
            Self::Null => "   ",
            Self::Line => "│  ",
            Self::Fork => "┝━ ",
            Self::Turn => "┕━ ",
        }
    }
}

struct NoTimeTreeFormatter;

impl tracing_forest::Formatter for NoTimeTreeFormatter {
    type Error = fmt::Error;

    fn fmt(&self, tree: &tracing_forest::tree::Tree) -> Result<String, Self::Error> {
        let mut out = String::with_capacity(256);
        let mut indent = Vec::new();
        format_tree_no_time(tree, &mut indent, &mut out)?;
        Ok(out)
    }
}

fn format_tree_no_time(
    tree: &tracing_forest::tree::Tree,
    indent: &mut Vec<TreeIndent>,
    out: &mut String,
) -> fmt::Result {
    match tree {
        tracing_forest::tree::Tree::Event(event) => {
            write!(out, "{:<8} ", event.level())?;
            for edge in indent.iter() {
                out.write_str(edge.repr())?;
            }

            let tag = event
                .tag()
                .unwrap_or_else(|| tracing_forest::Tag::from(event.level()));
            write!(out, "{} [{}]:", tag.icon(), tag)?;

            if let Some(message) = event.message() {
                write!(out, " {}", message)?;
            }
            for field in event.fields() {
                write!(out, " | {}: {}", field.key(), field.value())?;
            }
            writeln!(out)
        }
        tracing_forest::tree::Tree::Span(span) => {
            write!(out, "{:<8} ", span.level())?;
            for edge in indent.iter() {
                out.write_str(edge.repr())?;
            }
            write!(out, "{}", span.name())?;
            for field in span.fields() {
                write!(out, " | {}: {}", field.key(), field.value())?;
            }
            writeln!(out)?;

            if let Some((last, remaining)) = span.nodes().split_last() {
                match indent.last_mut() {
                    Some(edge @ TreeIndent::Turn) => *edge = TreeIndent::Null,
                    Some(edge @ TreeIndent::Fork) => *edge = TreeIndent::Line,
                    _ => {}
                }

                indent.push(TreeIndent::Fork);

                for node in remaining {
                    if let Some(edge) = indent.last_mut() {
                        *edge = TreeIndent::Fork;
                    }
                    format_tree_no_time(node, indent, out)?;
                }

                if let Some(edge) = indent.last_mut() {
                    *edge = TreeIndent::Turn;
                }
                format_tree_no_time(last, indent, out)?;

                indent.pop();
            }

            Ok(())
        }
    }
}

fn bincode_size<T: Serialize>(value: &T) -> usize {
    bincode::serialized_size(value)
        .map(|v| v as usize)
        .unwrap_or(0)
}

fn pct(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        0.0
    } else {
        (part as f64) * 100.0 / (whole as f64)
    }
}

fn log_size(component: &str, bytes: usize, parent: usize, total: usize) {
    info!(
        component,
        bytes,
        pct_of_parent = pct(bytes, parent),
        pct_of_total = pct(bytes, total)
    );
}

fn emit_native_profile(proof: &KeccakProof<Challenge>) {
    let total = bincode_size(proof);
    let root = info_span!("native_profile", total_bytes = total);
    let _root_enter = root.enter();

    let proof_data = bincode_size(&proof.proof_data);
    let whir = bincode_size(&proof.whir_proof);

    log_size("proof.proof_data", proof_data, total, total);
    let whir_span = info_span!(
        "whir",
        bytes = whir,
        pct_of_parent = pct(whir, total),
        pct_of_total = pct(whir, total)
    );
    let _whir_enter = whir_span.enter();

    let initial_commitment = bincode_size(&proof.whir_proof.initial_commitment);
    let initial_ood = bincode_size(&proof.whir_proof.initial_ood_answers);
    let initial_sumcheck = bincode_size(&proof.whir_proof.initial_sumcheck);
    let rounds = bincode_size(&proof.whir_proof.rounds);
    let final_poly = bincode_size(&proof.whir_proof.final_poly);
    let final_pow = bincode_size(&proof.whir_proof.final_pow_witness);
    let final_query = bincode_size(&proof.whir_proof.final_query_batch);
    let final_sumcheck = bincode_size(&proof.whir_proof.final_sumcheck);

    log_size("whir.initial_commitment", initial_commitment, whir, total);
    log_size("whir.initial_ood_answers", initial_ood, whir, total);
    log_size("whir.initial_sumcheck", initial_sumcheck, whir, total);
    log_size("whir.rounds", rounds, whir, total);
    log_size("whir.final_poly", final_poly, whir, total);
    log_size("whir.final_pow_witness", final_pow, whir, total);
    log_size("whir.final_query_batch", final_query, whir, total);
    log_size("whir.final_sumcheck", final_sumcheck, whir, total);

    for (idx, round) in proof.whir_proof.rounds.iter().enumerate() {
        let round_total = bincode_size(round);
        let round_span = info_span!(
            "whir_round",
            round_index = idx,
            bytes = round_total,
            pct_of_parent = pct(round_total, rounds),
            pct_of_total = pct(round_total, total)
        );
        let _round_enter = round_span.enter();

        log_size(
            "whir.round.commitment",
            bincode_size(&round.commitment),
            round_total,
            total,
        );
        log_size(
            "whir.round.ood_answers",
            bincode_size(&round.ood_answers),
            round_total,
            total,
        );
        log_size(
            "whir.round.pow_witness",
            bincode_size(&round.pow_witness),
            round_total,
            total,
        );
        log_size(
            "whir.round.query_batch",
            bincode_size(&round.query_batch),
            round_total,
            total,
        );
        log_size(
            "whir.round.sumcheck",
            bincode_size(&round.sumcheck),
            round_total,
            total,
        );
    }
}

fn script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../measure_mem_avg.sh")
}

fn temp_json_path(prefix: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    env::temp_dir().join(format!("{prefix}_{}_{}.json", std::process::id(), ts))
}

fn measure_ram_with_script(runs: usize) -> Result<usize, String> {
    let exe = env::current_exe().map_err(|e| format!("current_exe failed: {e}"))?;
    let json_path = temp_json_path("whirlaway_keccak_profile_mem");

    let output = Command::new("sh")
        .arg(script_path())
        .arg("--json")
        .arg(&json_path)
        .arg("--runs")
        .arg(runs.to_string())
        .arg("--")
        .arg(exe)
        .arg("--mem-only")
        .output()
        .map_err(|e| format!("failed to execute memory script: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "memory script failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let raw = fs::read_to_string(&json_path)
        .map_err(|e| format!("failed reading mem json '{}': {e}", json_path.display()))?;
    let _ = fs::remove_file(&json_path);

    let value: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("invalid mem json: {e}"))?;
    value
        .get("peak_memory")
        .and_then(serde_json::Value::as_u64)
        .map(|v| v as usize)
        .ok_or_else(|| "missing 'peak_memory' in mem json".to_string())
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let processor = PrettyPrinter::new().formatter(NoTimeTreeFormatter);
    let _ = Registry::default()
        .with(env_filter)
        .with(ForestLayer::from(processor))
        .try_init();
}

fn build_settings() -> whirlaway_sys::AirSettings {
    let whir_pow_bits = Some(POW_BITS);
    let mut settings = whirlaway::default_air_settings_with_overrides(100, Some(80), whir_pow_bits);
    settings.whir_soudness_type = SecurityAssumption::CapacityBound;
    settings.whir_folding_factor = FoldingFactor::ConstantFromSecondRound(7, 4);
    settings.whir_log_inv_rate = 6;
    settings.whir_initial_domain_reduction_factor = 2;
    settings.univariate_skips = 0;
    settings
}

fn main() {
    let mem_only = env::args().any(|arg| arg == "--mem-only");
    init_tracing();

    let build_profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    if !mem_only {
        println!("build_profile: {build_profile}");
    }
    if cfg!(debug_assertions) && !mem_only {
        eprintln!(
            "warning: debug build detected; run `cargo run --release -p whirlaway-bench --bin keccak_profile` for realistic timings"
        );
    }

    let settings = build_settings();

    let prep_start = Instant::now();
    let prepared = whirlaway::prepare_keccak_with_settings_and_mode::<Challenge>(
        INPUT_SIZE,
        settings.clone(),
        MODE,
    );
    let prep_ms = prep_start.elapsed().as_millis();

    let prove_start = Instant::now();
    let proof = whirlaway::prove_keccak(&prepared);
    let prove_ms = prove_start.elapsed().as_millis();

    if mem_only {
        return;
    }

    let verify_start = Instant::now();
    whirlaway::verify_keccak(&prepared, &proof).expect("verify failed");
    let verify_ms = verify_start.elapsed().as_millis();

    let air_table = <Keccak256Circuit<Challenge> as Circuit<
        KeccakBaseField,
        Challenge,
        { KECCAK_DIGEST_ELEMS },
    >>::make_table(&prepared.circuit, &settings);
    let air_width = air_table.n_columns;
    let air_height = 1usize.checked_shl(air_table.log_length as u32).unwrap_or(0);
    let witness_columns = air_table.n_witness_columns();
    let preprocessed_columns = air_table.n_preprocessed_columns();
    let padded_witness_columns = witness_columns.checked_next_power_of_two().unwrap_or(0);
    let pcs_poly_num_variables = air_table.log_length + air_table.log_n_witness_columns();
    let pcs_raw_witness_evals = witness_columns.saturating_mul(air_height);
    let pcs_committed_poly_evals = 1usize
        .checked_shl(pcs_poly_num_variables as u32)
        .unwrap_or(0);
    let pcs_committed_poly_bytes_est =
        pcs_committed_poly_evals.saturating_mul(std::mem::size_of::<KeccakBaseField>());
    let pcs_committed_lde_evals = 1usize
        .checked_shl((pcs_poly_num_variables + settings.whir_log_inv_rate) as u32)
        .unwrap_or(0);
    let pcs_committed_lde_bytes_est =
        pcs_committed_lde_evals.saturating_mul(std::mem::size_of::<KeccakBaseField>());

    let preprocessing_bytes = whirlaway::preprocessing_size(&prepared);
    let native_proof_bytes = bincode_size(&proof.0);

    let effective_merkle_security_bits = resolve_effective_merkle_security_bits(
        SECURITY_BITS,
        settings.merkle_security_bits_override,
    );
    let masked_digest_bytes =
        effective_digest_bytes_for_security_bits(effective_merkle_security_bits);
    let proof_blob = encode_proof_blob_v3_generic(&proof.1, &proof.0, masked_digest_bytes);
    let calldata = encode_calldata_verify_bytes(&proof_blob);

    let merkle_digests = count_merkle_digests_in_proof(&proof.0);

    println!("Whirlaway Keccak Profile (V1)");
    println!("input_size: {INPUT_SIZE}");
    println!("mode: {:?}", MODE);
    println!("challenge_type: {}", std::any::type_name::<Challenge>());
    println!("security_bits: {SECURITY_BITS}");
    println!("soundness: {:?}", settings.whir_soudness_type);
    println!("starting_log_inv_rate: {0}", settings.whir_log_inv_rate);
    println!("pow_bits: {POW_BITS}");
    let folding_factor_repr = match settings.whir_folding_factor {
        FoldingFactor::Constant(factor) => format!("Constant({factor})"),
        FoldingFactor::ConstantFromSecondRound(first, second) => {
            format!("ConstantFromSecondRound({first}, {second})")
        }
    };
    println!("folding_factor: {folding_factor_repr}");
    println!(
        "whir_initial_domain_reduction_factor: {0}",
        settings.whir_initial_domain_reduction_factor
    );
    println!("univariate_skips: {0}", settings.univariate_skips);
    println!(
        "merkle_security_bits_override: {:?}",
        settings.merkle_security_bits_override
    );
    println!();

    println!("air_width: {air_width}");
    println!("air_height: {air_height}");
    println!("witness_columns: {witness_columns}");
    println!("preprocessed_columns: {preprocessed_columns}");
    println!("pcs_poly_num_variables: {pcs_poly_num_variables}");
    println!("pcs_padded_witness_columns: {padded_witness_columns}");
    println!("pcs_raw_witness_evals: {pcs_raw_witness_evals}");
    println!("pcs_committed_poly_evals: {pcs_committed_poly_evals}");
    println!("pcs_committed_poly_bytes_est: {pcs_committed_poly_bytes_est}");
    println!("pcs_committed_lde_evals: {pcs_committed_lde_evals}");
    println!("pcs_committed_lde_bytes_est: {pcs_committed_lde_bytes_est}");
    println!("preprocess_ms: {prep_ms}");
    println!("prove_ms: {prove_ms}");
    println!("verify_ms: {verify_ms}");
    println!("preprocessing_size_bytes: {preprocessing_bytes}");
    println!("native_proof_size_bytes: {native_proof_bytes}");
    println!("proof_blob_v3_size_bytes: {}", proof_blob.len());
    println!("calldata_size_bytes: {}", calldata.len());
    println!(
        "calldata_gas_estimate: {}",
        estimate_calldata_gas(&calldata)
    );
    println!("masked_digest_bytes: {masked_digest_bytes}");
    println!("merkle_digest_count: {merkle_digests}");

    match measure_ram_with_script(RAM_RUNS) {
        Ok(bytes) => println!("ram_peak_avg_bytes (runs={RAM_RUNS}): {bytes}"),
        Err(err) => eprintln!("ram measurement failed: {err}"),
    }

    emit_native_profile(&proof.0);

    let blob_span = info_span!(
        "blob_profile",
        total_bytes = proof_blob.len(),
        calldata_bytes = calldata.len(),
        pct_calldata_vs_blob = pct(calldata.len(), proof_blob.len())
    );
    let _blob_enter = blob_span.enter();
    log_size(
        "blob.calldata",
        calldata.len(),
        proof_blob.len(),
        proof_blob.len(),
    );
    info!(
        component = "blob.summary",
        merkle_digest_count = merkle_digests,
        masked_digest_bytes,
        calldata_gas = estimate_calldata_gas(&calldata)
    );
}

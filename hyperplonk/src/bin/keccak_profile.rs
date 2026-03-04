use std::env;
use std::fmt::{self, Write as _};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use hyperplonk::keccak::{
    Binomial4Challenge, Challenger, Dft, KeccakMode, KeccakWhirBenchParams, Pcs,
};
use p3_hyperplonk::evm_codec::{
    count_merkle_digests_in_proof, encode_calldata_verify_bytes, encode_proof_blob_v3_generic,
    estimate_calldata_gas,
};
use p3_hyperplonk::{HyperPlonkConfig, Proof};
use p3_koala_bear::KoalaBear;
use p3_whir::{FoldingFactor, SecurityAssumption, effective_digest_bytes_for_security_bits};
use serde::Serialize;
use tracing::{info, info_span};
use tracing_forest::{ForestLayer, PrettyPrinter};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::{Registry, layer::SubscriberExt, util::SubscriberInitExt};

#[cfg(target_family = "unix")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const INPUT_SIZE: usize = 128;
const RAM_RUNS: usize = 1;
const MODE: KeccakMode = KeccakMode::ByteSpongeWithXorLookup;

const PARAMS: KeccakWhirBenchParams = KeccakWhirBenchParams {
    security_bits: 100,
    soundness_type: SecurityAssumption::CapacityBound,
    starting_log_inv_rate: 6,
    pow_bits: 30,
    folding_factor: FoldingFactor::Constant(4),
    rs_domain_initial_reduction_factor: 3,
    univariate_skip_rounds: 0,
    merkle_security_bits_override: Some(80),
};

type Challenge = Binomial4Challenge;

type Val = KoalaBear;
type Config = HyperPlonkConfig<Pcs<Val, Dft<Val>>, Challenge, Challenger>;
type HyperProof = Proof<Config>;

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

fn emit_native_profile(proof: &HyperProof) {
    let total = bincode_size(proof);
    let root = info_span!("native_profile", total_bytes = total);
    let _root_enter = root.enter();

    let log_bs = bincode_size(&proof.log_bs);
    let commitment = bincode_size(&proof.commitment);
    let piop = bincode_size(&proof.piop);
    let pcs = bincode_size(&proof.pcs);

    log_size("proof.log_bs", log_bs, total, total);
    log_size("proof.commitment", commitment, total, total);

    {
        let span = info_span!(
            "piop",
            bytes = piop,
            pct_of_parent = pct(piop, total),
            pct_of_total = pct(piop, total)
        );
        let _enter = span.enter();

        let frac = bincode_size(&proof.piop.fractional_sum);
        let air = bincode_size(&proof.piop.air);

        {
            let frac_span = info_span!(
                "fractional_sum",
                bytes = frac,
                pct_of_parent = pct(frac, piop),
                pct_of_total = pct(frac, total)
            );
            let _frac_enter = frac_span.enter();
            let sums = bincode_size(&proof.piop.fractional_sum.sums);
            let layers = bincode_size(&proof.piop.fractional_sum.layers);
            log_size("fractional_sum.sums", sums, frac, total);
            log_size("fractional_sum.layers", layers, frac, total);

            for (idx, layer) in proof.piop.fractional_sum.layers.iter().enumerate() {
                let layer_size = bincode_size(layer);
                log_size(
                    &format!("fractional_sum.layers[{idx}]"),
                    layer_size,
                    layers,
                    total,
                );
            }
        }

        {
            let air_span = info_span!(
                "air",
                bytes = air,
                pct_of_parent = pct(air, piop),
                pct_of_total = pct(air, total)
            );
            let _air_enter = air_span.enter();
            let skips = bincode_size(&proof.piop.air.univariate_skips);
            let regular = bincode_size(&proof.piop.air.regular);
            let uni_eval = bincode_size(&proof.piop.air.univariate_eval_check);
            log_size("air.univariate_skips", skips, air, total);
            log_size("air.regular", regular, air, total);
            log_size("air.univariate_eval_check", uni_eval, air, total);

            for (idx, skip) in proof.piop.air.univariate_skips.iter().enumerate() {
                let skip_size = bincode_size(skip);
                log_size(
                    &format!("air.univariate_skips[{idx}]"),
                    skip_size,
                    skips,
                    total,
                );
            }
        }
    }

    {
        let span = info_span!(
            "pcs",
            bytes = pcs,
            pct_of_parent = pct(pcs, total),
            pct_of_total = pct(pcs, total)
        );
        let _enter = span.enter();

        for (pcs_idx, whir) in proof.pcs.iter().enumerate() {
            let whir_total = bincode_size(whir);
            let whir_span = info_span!(
                "whir",
                index = pcs_idx,
                bytes = whir_total,
                pct_of_parent = pct(whir_total, pcs),
                pct_of_total = pct(whir_total, total)
            );
            let _whir_enter = whir_span.enter();

            let initial_commitment = bincode_size(&whir.initial_commitment);
            let initial_ood = bincode_size(&whir.initial_ood_answers);
            let initial_sumcheck = bincode_size(&whir.initial_sumcheck);
            let rounds = bincode_size(&whir.rounds);
            let final_poly = bincode_size(&whir.final_poly);
            let final_pow = bincode_size(&whir.final_pow_witness);
            let final_query = bincode_size(&whir.final_query_batch);
            let final_sumcheck = bincode_size(&whir.final_sumcheck);

            log_size(
                "whir.initial_commitment",
                initial_commitment,
                whir_total,
                total,
            );
            log_size("whir.initial_ood_answers", initial_ood, whir_total, total);
            log_size("whir.initial_sumcheck", initial_sumcheck, whir_total, total);
            log_size("whir.rounds", rounds, whir_total, total);
            log_size("whir.final_poly", final_poly, whir_total, total);
            log_size("whir.final_pow_witness", final_pow, whir_total, total);
            log_size("whir.final_query_batch", final_query, whir_total, total);
            log_size("whir.final_sumcheck", final_sumcheck, whir_total, total);

            for (round_idx, round) in whir.rounds.iter().enumerate() {
                let round_total = bincode_size(round);
                let round_span = info_span!(
                    "whir_round",
                    pcs_index = pcs_idx,
                    round_index = round_idx,
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
    let json_path = temp_json_path("hyperplonk_keccak_profile_mem");

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
            "warning: debug build detected; run `cargo run --release -p hyperplonk --bin keccak_profile` for realistic timings"
        );
    }

    let prep_start = Instant::now();
    let config = hyperplonk::keccak::make_config_with_params::<Challenge>(&PARAMS);
    let prepared =
        hyperplonk::keccak::prepare_with_mode(INPUT_SIZE, config, MODE).expect("prepare failed");
    let prep_ms = prep_start.elapsed().as_millis();

    let prove_start = Instant::now();
    let proof = hyperplonk::prove_keccak(&prepared).expect("prove failed");
    let prove_ms = prove_start.elapsed().as_millis();

    if mem_only {
        return;
    }

    let verify_start = Instant::now();
    hyperplonk::verify_keccak(&prepared, &proof).expect("verify failed");
    let verify_ms = verify_start.elapsed().as_millis();

    let air_width = prepared
        .vk
        .metas()
        .first()
        .map(|meta| meta.width)
        .unwrap_or(0);
    let air_height = proof
        .1
        .log_bs
        .first()
        .and_then(|&log_h| 1usize.checked_shl(log_h as u32))
        .unwrap_or(0);
    let air_width_padded = air_width.checked_next_power_of_two().unwrap_or(0);
    let pcs_poly_num_variables = proof
        .1
        .log_bs
        .first()
        .copied()
        .unwrap_or(0)
        .saturating_add(air_width_padded.checked_ilog2().unwrap_or(0) as usize);
    let pcs_raw_trace_evals = air_width.saturating_mul(air_height);
    let pcs_committed_poly_evals = air_width_padded.saturating_mul(air_height);
    let pcs_committed_poly_bytes_est =
        pcs_committed_poly_evals.saturating_mul(std::mem::size_of::<Val>());
    let pcs_committed_lde_evals = 1usize
        .checked_shl((pcs_poly_num_variables + PARAMS.starting_log_inv_rate) as u32)
        .unwrap_or(0);
    let pcs_committed_lde_bytes_est =
        pcs_committed_lde_evals.saturating_mul(std::mem::size_of::<Val>());

    let preprocessing_bytes = hyperplonk::preprocessing_size(&prepared);
    let native_proof_bytes = bincode_size(&proof.1);

    let effective_merkle_security_bits = PARAMS.effective_merkle_security_bits();
    let masked_digest_bytes =
        effective_digest_bytes_for_security_bits(effective_merkle_security_bits);
    let public_inputs: Vec<Vec<Val>> = (0..proof.1.log_bs.len())
        .map(|idx| {
            if idx == 0 {
                proof.0.clone()
            } else {
                Vec::new()
            }
        })
        .collect();
    let proof_blob = encode_proof_blob_v3_generic(&public_inputs, &proof.1, masked_digest_bytes);
    let calldata = encode_calldata_verify_bytes(&proof_blob);

    let merkle_digests = count_merkle_digests_in_proof(&proof.1);

    println!("HyperPlonk Keccak Profile (V1)");
    println!("input_size: {INPUT_SIZE}");
    println!("mode: {:?}", MODE);
    println!("challenge_type: {}", std::any::type_name::<Challenge>());
    println!("security_bits: {}", PARAMS.security_bits);
    println!("soundness: {:?}", PARAMS.soundness_type);
    println!("starting_log_inv_rate: {}", PARAMS.starting_log_inv_rate);
    println!("pow_bits: {}", PARAMS.pow_bits);
    println!("folding_factor: {:?}", PARAMS.folding_factor);
    println!(
        "rs_domain_initial_reduction_factor: {}",
        PARAMS.rs_domain_initial_reduction_factor
    );
    println!("univariate_skip_rounds: {}", PARAMS.univariate_skip_rounds);
    println!(
        "merkle_security_bits_override: {:?}",
        PARAMS.merkle_security_bits_override
    );
    println!();

    println!("air_width: {air_width}");
    println!("air_height: {air_height}");
    println!("pcs_poly_num_variables: {pcs_poly_num_variables}");
    println!("pcs_raw_trace_evals: {pcs_raw_trace_evals}");
    println!("pcs_padded_width: {air_width_padded}");
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
    println!(
        "fractional_sum_size_bytes: {}",
        bincode_size(&proof.1.piop.fractional_sum)
    );

    println!();
    for (idx, meta) in prepared.vk.metas().iter().enumerate() {
        let log_h = proof.1.log_bs.get(idx).copied().unwrap_or(0);
        let height = 1usize.checked_shl(log_h as u32).unwrap_or(0);
        println!("air[{idx}].width: {}", meta.width);
        println!("air[{idx}].height: {height}");
        println!("air[{idx}].constraint_count: {}", meta.constraint_count);
        println!("air[{idx}].interaction_count: {}", meta.interaction_count);
        println!(
            "air[{idx}].eval_check_uv_degree: {}",
            meta.eval_check_uv_degree
        );
        println!(
            "air[{idx}].eval_check_mv_degree: {}",
            meta.eval_check_mv_degree
        );
    }

    match measure_ram_with_script(RAM_RUNS) {
        Ok(bytes) => println!("ram_peak_avg_bytes (runs={RAM_RUNS}): {bytes}"),
        Err(err) => eprintln!("ram measurement failed: {err}"),
    }

    emit_native_profile(&proof.1);

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

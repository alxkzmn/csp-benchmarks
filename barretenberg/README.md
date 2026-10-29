# Noir + Barretenberg benchmarks

These benchmarks use the shared Rust Criterion harness and the official
[`barretenberg-rs` 5.2.1](https://crates.io/crates/barretenberg-rs/5.2.1) crate.
Its `PipeBackend` communicates with a persistent `bb msgpack run` child process.
Nargo compiles the Noir circuits and generates witnesses.

## Prerequisites

Use the repository's Rust toolchain, Bash, `jq`, and `/usr/bin/time` for the shared
RAM measurement script. Install the same versions as
[Rust benchmark CI](../.github/workflows/rust_benchmarks_parallel.yml):

```bash
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
export PATH="$HOME/.nargo/bin:$PATH"
noirup --version 1.0.0-beta.25

curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/next/barretenberg/bbup/install | bash
export PATH="$HOME/.bb:$PATH"
bbup -v 5.2.1
```

Cargo pins `barretenberg-rs` to `=5.2.1` with only its `native` feature, so it
uses the installed binary rather than downloading and linking static libraries.
The Noir dependencies remain SHA-256 `v0.3.0`, Keccak `v0.1.3`, and Poseidon
`v0.3.0` (also used for Poseidon2).

## Run

From the repository root:

```bash
cd barretenberg
BENCH_INPUT_PROFILE=reduced cargo bench
```

Run one target with `cargo bench --bench sha256_bench`. The other bench names
are `blake3_bench`, `keccak_bench`, `ecdsa_bench`, `poseidon_bench`, and
`poseidon2_bench`.

Use `BENCH_INPUT_PROFILE=full` for the complete input range:

| Target | Reduced | Full |
| --- | --- | --- |
| SHA-256 / Keccak (bytes) | 128, 256 | 128, 256, 512, 1024, 2048 |
| BLAKE3 (bytes) | 128, 256 | 128, 256, 512, 1024 |
| ECDSA secp256r1 (digest bytes) | 32 | 32 |
| Poseidon / Poseidon2 (field elements) | 2, 8 | 2, 4, 8, 12, 16 |

BLAKE3 retains its existing 1024-byte limit.

Run the circuit integration tests with the installed tools:

```bash
BENCH_INPUT_PROFILE=full cargo test --release -p barretenberg-bench \
  --test integration -- --ignored --test-threads=1
```

## Measurement boundaries

- Circuit compilation and verification-key preparation happen outside timed
  proving and verification.
- Proving includes Nargo witness generation and the `circuit_prove` API call,
  including Barretenberg's construction of its prover instance.
- Verification uses the prepared key, proof, and public inputs. The returned
  verification result must be true.
- The persistent backend excludes per-call `bb` startup and teardown and can
  reuse its SRS cache. These timings therefore differ from the former shell
  harness, which launched a fresh process for each call.
- Proof size counts the proof's field bytes, excluding public inputs, the
  verification key, and transport framing. Preprocessing size remains the
  compiled circuit JSON's file size. Gate counts come from `circuit_stats`.
- The shared RAM script averages ten runs of a dedicated memory binary. Each
  run performs setup, witness generation, and proving, and reaps the backend
  child before exiting; it does not verify.

The shared harness writes Criterion reports under `../target/criterion` and
standard metrics and memory reports in this directory. ECDSA retains the
`secp256r1` feature tag, and the existing acceleration metadata is preserved.

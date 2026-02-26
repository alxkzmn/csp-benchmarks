use clap::Parser;
use hyperplonk::keccak::{Binomial4Challenge, PreparedKeccak};

#[cfg(target_family = "unix")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

const SECURITY_BITS: usize = 100;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long = "input-size")]
    input_size: usize,
}

fn main() {
    let args = Args::parse();
    let prepared: PreparedKeccak<Binomial4Challenge> =
        hyperplonk::prepare_keccak_with_merkle_override(args.input_size, SECURITY_BITS, Some(80))
            .expect("prepare failed");
    let _ = hyperplonk::prove_keccak(&prepared);
}

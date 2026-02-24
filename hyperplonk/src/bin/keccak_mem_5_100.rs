use clap::Parser;
use hyperplonk::keccak::{PreparedKeccak, QuinticChallenge};

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
    let prepared: PreparedKeccak<QuinticChallenge> =
        hyperplonk::prepare_keccak(args.input_size, SECURITY_BITS).expect("prepare failed");
    let _ = hyperplonk::prove_keccak(&prepared);
}

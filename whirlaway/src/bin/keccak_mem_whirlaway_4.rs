use clap::Parser;
use whirlaway_sys::circuits::keccak256::Binomial4Challenge;

const SECURITY_BITS: usize = 100;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long = "input-size")]
    input_size: usize,
}

fn main() {
    let args = Args::parse();
    let prepared = whirlaway::prepare_keccak_with_merkle_override::<Binomial4Challenge>(
        args.input_size,
        SECURITY_BITS,
        Some(80),
    );
    let _ = whirlaway::prove_keccak(&prepared);
}

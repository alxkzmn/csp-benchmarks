use clap::Parser;
use whirlaway_sys::circuits::keccak256::Binomial8Challenge;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long = "input-size")]
    input_size: usize,
}

fn main() {
    let args = Args::parse();
    let prepared = whirlaway::prepare_keccak::<Binomial8Challenge>(args.input_size);
    let _ = whirlaway::prove_keccak(&prepared);
}

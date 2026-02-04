use clap::Parser;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long = "input-size")]
    input_size: usize,
}

fn main() {
    let args = Args::parse();
    let prepared = whirlaway::prepare_keccak(args.input_size);
    let _ = whirlaway::prove_keccak(&prepared);
}

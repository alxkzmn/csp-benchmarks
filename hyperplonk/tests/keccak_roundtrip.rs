use hyperplonk::keccak::Binomial4Challenge;

#[test]
fn keccak_roundtrip_128() {
    let prepared = hyperplonk::prepare_keccak::<Binomial4Challenge>(128).expect("prepare failed");
    let proof = hyperplonk::prove_keccak(&prepared).expect("failed to prove keccak");
    hyperplonk::verify_keccak(&prepared, &proof).expect("verify failed");
}

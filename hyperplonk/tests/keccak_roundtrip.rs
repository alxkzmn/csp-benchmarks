#[test]
fn keccak_roundtrip_128() {
    let prepared = hyperplonk::prepare_keccak(128).expect("prepare failed");
    let proof = hyperplonk::prove_keccak(&prepared);
    hyperplonk::verify_keccak(&prepared, &proof).expect("verify failed");
}

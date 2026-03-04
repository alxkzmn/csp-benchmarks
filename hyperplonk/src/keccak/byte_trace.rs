use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail};
use p3_field::PrimeField64;
use p3_keccak::KeccakF;
use p3_keccak_air::{NUM_KECCAK_COLS, NUM_ROUNDS};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_symmetric::Permutation;

use crate::keccak::byte_sponge_air::{
    ACTIVE_IDX, BLOCK_BYTES_START, BYTE_EXTRA_COLS, DIGEST_LIMBS, HASH_END_IDX, IS_NEW_START_IDX,
    IS_PADDING_START, RATE_BYTES, RATE_U16S, SEEN_END_IDX,
};
use crate::keccak::xor_lookup_air::{
    XOR_LOOKUP_COLS, XOR_LOOKUP_MULT_IDX, XOR_LOOKUP_X_BITS, XOR_LOOKUP_Y_BITS, XOR_LOOKUP_Z_IDX,
};

type XorTuple = (u16, u16, u16);

fn keccak_pad10star1(mut msg: Vec<u8>) -> Vec<u8> {
    msg.push(0x01);
    if msg.len().is_multiple_of(RATE_BYTES) {
        let last = msg.len() - 1;
        msg[last] ^= 0x80;
        return msg;
    }

    while (msg.len() % RATE_BYTES) != (RATE_BYTES - 1) {
        msg.push(0x00);
    }
    msg.push(0x80);
    msg
}

fn state_to_rate_bytes(state: &[u64; 25]) -> [u8; RATE_BYTES] {
    let mut out = [0u8; RATE_BYTES];
    for lane in 0..(RATE_BYTES / 8) {
        out[lane * 8..(lane + 1) * 8].copy_from_slice(&state[lane].to_le_bytes());
    }
    out
}

fn rate_bytes_to_u16s(rate_bytes: &[u8; RATE_BYTES]) -> [u16; RATE_U16S] {
    let mut out = [0u16; RATE_U16S];
    for i in 0..RATE_U16S {
        out[i] = u16::from_le_bytes([rate_bytes[2 * i], rate_bytes[2 * i + 1]]);
    }
    out
}

fn digest_to_u16_limbs_le(digest: &[u8; 32]) -> [u16; DIGEST_LIMBS] {
    let mut out = [0u16; DIGEST_LIMBS];
    for i in 0..DIGEST_LIMBS {
        out[i] = u16::from_le_bytes([digest[2 * i], digest[2 * i + 1]]);
    }
    out
}

fn digest_from_state(state: &[u64; 25]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

fn inc_tuple(map: &mut BTreeMap<XorTuple, u64>, tuple: XorTuple) {
    map.entry(tuple)
        .and_modify(|count| *count += 1)
        .or_insert(1);
}

fn build_lookup_trace<F: PrimeField64>(xor_counts: &BTreeMap<XorTuple, u64>) -> RowMajorMatrix<F> {
    let mut entries: Vec<(XorTuple, u64)> = xor_counts.iter().map(|(k, v)| (*k, *v)).collect();
    if entries.is_empty() {
        entries.push(((0, 0, 0), 0));
    }

    let height = entries.len().next_power_of_two();
    let mut values = vec![F::ZERO; height * XOR_LOOKUP_COLS];

    let mut set = |row: usize, col: usize, v: F| {
        values[row * XOR_LOOKUP_COLS + col] = v;
    };

    for (row, ((x, y, z), mult)) in entries.into_iter().enumerate() {
        for i in 0..XOR_LOOKUP_X_BITS {
            let bit = ((x >> i) & 1) as u8;
            set(row, i, F::from_u8(bit));
        }
        for i in 0..XOR_LOOKUP_Y_BITS {
            let bit = ((y >> i) & 1) as u8;
            set(row, XOR_LOOKUP_X_BITS + i, F::from_u8(bit));
        }
        set(row, XOR_LOOKUP_Z_IDX, F::from_u16(z));
        set(row, XOR_LOOKUP_MULT_IDX, F::from_u64(mult));
    }

    RowMajorMatrix::new(values, XOR_LOOKUP_COLS)
}

pub fn generate_byte_traces_and_public_digest_limbs<F: PrimeField64>(
    input_size: usize,
) -> Result<(RowMajorMatrix<F>, RowMajorMatrix<F>, [u16; DIGEST_LIMBS])> {
    let (msg, digest) = utils::generate_keccak_input(input_size);
    let digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| anyhow!("expected 32-byte keccak digest"))?;

    let padded = keccak_pad10star1(msg);
    if !padded.len().is_multiple_of(RATE_BYTES) {
        bail!("padding produced non-multiple of rate");
    }

    let num_blocks = padded.len() / RATE_BYTES;
    if num_blocks == 0 {
        bail!("keccak padded message has zero blocks");
    }

    let mut perm_inputs = Vec::with_capacity(num_blocks);
    let mut perm_outputs = Vec::with_capacity(num_blocks);
    let mut block_bytes = Vec::with_capacity(num_blocks);
    let mut block_padding_flags = Vec::with_capacity(num_blocks);

    let mut state = [0u64; 25];
    for block_idx in 0..num_blocks {
        let block: &[u8; RATE_BYTES] = padded[block_idx * RATE_BYTES..(block_idx + 1) * RATE_BYTES]
            .try_into()
            .expect("slice has RATE_BYTES bytes");

        for lane in 0..(RATE_BYTES / 8) {
            let chunk: [u8; 8] = block[lane * 8..(lane + 1) * 8]
                .try_into()
                .expect("lane chunk has 8 bytes");
            state[lane] ^= u64::from_le_bytes(chunk);
        }

        perm_inputs.push(state);
        block_bytes.push(*block);

        let mut padding_flags = [0u8; RATE_BYTES];
        for (i, bit) in padding_flags.iter_mut().enumerate().take(RATE_BYTES) {
            *bit = u8::from(block_idx * RATE_BYTES + i >= input_size);
        }
        block_padding_flags.push(padding_flags);

        KeccakF.permute_mut(&mut state);
        perm_outputs.push(state);
    }

    let computed_digest = digest_from_state(perm_outputs.last().expect("at least one block"));
    if computed_digest != digest {
        bail!("keccak sponge simulation digest mismatch");
    }

    let keccak_trace = p3_keccak_air::generate_trace_rows::<F>(perm_inputs.clone(), 0);
    let height = keccak_trace.height();
    let width = NUM_KECCAK_COLS + BYTE_EXTRA_COLS;

    let mut values = vec![F::ZERO; height * width];
    for row in 0..height {
        let src = keccak_trace
            .row_slice(row)
            .ok_or_else(|| anyhow!("missing trace row"))?;
        values[row * width..row * width + NUM_KECCAK_COLS].copy_from_slice(&src);
    }

    let mut set = |row: usize, col: usize, v: F| {
        values[row * width + col] = v;
    };

    let hash_end_row = (num_blocks * NUM_ROUNDS) - 1;
    if hash_end_row >= height {
        bail!("keccak trace too short for expected hash_end row");
    }

    for row in 0..height {
        let active = if row <= hash_end_row { F::ONE } else { F::ZERO };
        let seen_end = if row <= hash_end_row { F::ZERO } else { F::ONE };
        set(row, ACTIVE_IDX, active);
        set(row, SEEN_END_IDX, seen_end);
        set(
            row,
            HASH_END_IDX,
            if row == hash_end_row { F::ONE } else { F::ZERO },
        );
    }

    for block_idx in 0..num_blocks {
        let block_start = block_idx * NUM_ROUNDS;
        let block_end = ((block_idx + 1) * NUM_ROUNDS).min(height);

        for row in block_start..block_end {
            for i in 0..RATE_BYTES {
                set(
                    row,
                    BLOCK_BYTES_START + i,
                    F::from_u8(block_bytes[block_idx][i]),
                );
                set(
                    row,
                    IS_PADDING_START + i,
                    F::from_u8(block_padding_flags[block_idx][i]),
                );
            }
        }

        if block_start < height {
            set(
                block_start,
                IS_NEW_START_IDX,
                if block_idx == 0 { F::ONE } else { F::ZERO },
            );
        }
    }

    let mut xor_counts: BTreeMap<XorTuple, u64> = BTreeMap::new();

    // Non-final block transitions only.
    for block_idx in 0..num_blocks {
        let is_final_block = block_padding_flags[block_idx][RATE_BYTES - 1] == 1;
        if is_final_block {
            continue;
        }

        let prev_post = rate_bytes_to_u16s(&state_to_rate_bytes(&perm_outputs[block_idx]));
        let next_block = block_bytes
            .get(block_idx + 1)
            .ok_or_else(|| anyhow!("missing next block bytes for non-final block"))?;
        let next_block = rate_bytes_to_u16s(next_block);
        let next_preimage = perm_inputs
            .get(block_idx + 1)
            .ok_or_else(|| anyhow!("missing next preimage for non-final block"))?;
        let next_preimage = rate_bytes_to_u16s(&state_to_rate_bytes(next_preimage));

        for i in 0..RATE_U16S {
            inc_tuple(
                &mut xor_counts,
                (next_block[i], prev_post[i], next_preimage[i]),
            );
        }
    }

    let lookup_trace = build_lookup_trace::<F>(&xor_counts);
    let digest_limbs = digest_to_u16_limbs_le(&digest);

    Ok((
        RowMajorMatrix::new(values, width),
        lookup_trace,
        digest_limbs,
    ))
}

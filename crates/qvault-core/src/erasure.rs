use std::sync::OnceLock;

use crate::error::{err, Result};

fn tables() -> &'static ([u8; 512], [u8; 256]) {
    static TABLES: OnceLock<([u8; 512], [u8; 256])> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];
        exp[0] = 1;
        let mut x = 1u16;
        for (i, slot) in exp.iter_mut().enumerate().take(255).skip(1) {
            x <<= 1;
            if (x & 256) != 0 {
                x ^= 256 | 0x1d;
            }
            *slot = x as u8;
            log[x as usize] = i as u8;
        }
        for i in 255..512 {
            exp[i] = exp[i - 255];
        }
        (exp, log)
    })
}

fn gf_mul(x: u8, y: u8) -> u8 {
    if x == 0 || y == 0 {
        return 0;
    }
    let (exp, log) = tables();
    exp[usize::from(log[x as usize]) + usize::from(log[y as usize])]
}

fn gf_div(x: u8, y: u8) -> Result<u8> {
    if y == 0 {
        return Err(err("Divided by zero! Blackhole created.. "));
    }
    if x == 0 {
        return Ok(0);
    }
    let (exp, log) = tables();
    Ok(exp[usize::from(log[x as usize]) + 255 - usize::from(log[y as usize])])
}

#[derive(Debug, Clone)]
struct Polynomial {
    coefficients: Vec<u8>,
}

impl Polynomial {
    fn new(coefficients: Vec<u8>) -> Result<Self> {
        if coefficients.is_empty() {
            return Err(err("Polynomial must contain at least one coefficient"));
        }
        if coefficients.len() > 256 {
            return Err(err(
                "Polynomial order must be less than or equal to the degree of the Galois field.",
            ));
        }
        Ok(Self { coefficients })
    }

    fn order(&self) -> usize {
        self.coefficients.len()
    }

    fn eval(&self, x: u8) -> u8 {
        let mut y = self.coefficients[0];
        for coefficient in self.coefficients.iter().skip(1) {
            y = gf_mul(y, x) ^ coefficient;
        }
        y
    }

    fn scale(&self, x: u8) -> Result<Self> {
        let mut out = vec![0u8; self.coefficients.len()];
        for (i, coefficient) in self.coefficients.iter().copied().enumerate() {
            out[i] = gf_mul(x, coefficient);
        }
        Self::new(out)
    }

    fn add(&self, other: &Self) -> Result<Self> {
        let mut out = vec![0u8; self.order().max(other.order())];
        let self_offset = out.len() - self.order();
        let other_offset = out.len() - other.order();
        for (i, coefficient) in self.coefficients.iter().copied().enumerate() {
            out[self_offset + i] = coefficient;
        }
        for (i, coefficient) in other.coefficients.iter().copied().enumerate() {
            out[other_offset + i] ^= coefficient;
        }
        Self::new(out)
    }

    fn mul(&self, other: &Self) -> Result<Self> {
        let mut out = vec![0u8; self.order() + other.order() - 1];
        for (i, left) in self.coefficients.iter().copied().enumerate() {
            for (j, right) in other.coefficients.iter().copied().enumerate() {
                out[i + j] ^= gf_mul(left, right);
            }
        }
        Self::new(out)
    }

    fn append(&self, x: u8) -> Result<Self> {
        let mut out = self.coefficients.clone();
        out.push(x);
        Self::new(out)
    }
}

fn generator(n_ec_symbols: usize) -> Result<Polynomial> {
    let mut g = Polynomial::new(vec![1])?;
    let (exp, _) = tables();
    for item in exp.iter().take(n_ec_symbols) {
        g = g.mul(&Polynomial::new(vec![1, *item])?)?;
    }
    Ok(g)
}

fn encode(input: &[u8], n_ec: usize) -> Result<Vec<u8>> {
    let gen = generator(n_ec)?;
    let mut out = vec![0u8; input.len() + n_ec];
    out[..input.len()].copy_from_slice(input);
    for i in 0..input.len() {
        let c = out[i];
        if c != 0 {
            for j in 0..gen.order() {
                out[i + j] ^= gf_mul(gen.coefficients[j], c);
            }
        }
    }
    out[..input.len()].copy_from_slice(input);
    Ok(out)
}

fn syndromes(input: &[u8], n_ec: usize) -> Vec<u8> {
    let (exp, _) = tables();
    let poly = Polynomial {
        coefficients: input.to_vec(),
    };
    let mut out = vec![0u8; n_ec];
    for i in 0..n_ec {
        out[i] = poly.eval(exp[i]);
    }
    out
}

fn correct_errata(input: &mut [u8], synd: &[u8], pos: &[usize]) -> Result<()> {
    if pos.is_empty() {
        return Ok(());
    }
    let mut q = Polynomial::new(vec![1])?;
    let (exp, _) = tables();
    for i in pos {
        let x = exp[input.len() - 1 - *i];
        q = q.mul(&Polynomial::new(vec![x, 1])?)?;
    }
    let mut t = vec![0u8; pos.len()];
    for i in 0..t.len() {
        t[i] = synd[t.len() - 1 - i];
    }
    let p = Polynomial::new(t)?.mul(&q)?;
    let p_tail = p.coefficients[p.order() - pos.len()..].to_vec();
    let p = Polynomial::new(p_tail)?;

    let start = q.order() & 1;
    let mut qprime_coeffs = vec![0u8; (q.order() - start) / 2];
    let mut qprime_idx = 0usize;
    let mut i = start;
    while i < q.order() {
        qprime_coeffs[qprime_idx] = q.coefficients[i];
        qprime_idx += 1;
        i += 2;
    }
    let qprime = Polynomial::new(qprime_coeffs)?;

    for pos_i in pos {
        let x = exp[pos_i + 256 - input.len()];
        let y = p.eval(x);
        let z = qprime.eval(gf_mul(x, x));
        input[*pos_i] ^= gf_div(y, gf_mul(x, z))?;
    }
    Ok(())
}

fn find_errors(synd: &[u8], n_mess: usize) -> Result<Vec<usize>> {
    let (exp, _) = tables();
    let mut err_poly = Polynomial::new(vec![1])?;
    let mut old_poly = Polynomial::new(vec![1])?;

    for i in 0..synd.len() {
        old_poly = old_poly.append(0)?;
        let mut delta = synd[i];
        for j in 1..err_poly.order() {
            delta ^= gf_mul(err_poly.coefficients[err_poly.order() - 1 - j], synd[i - j]);
        }
        if delta != 0 {
            if old_poly.order() > err_poly.order() {
                let new_poly = old_poly.scale(delta)?;
                old_poly = err_poly.scale(gf_div(1, delta)?)?;
                err_poly = new_poly;
            }
            err_poly = err_poly.add(&old_poly.scale(delta)?)?;
        }
    }

    let errs = err_poly.order() - 1;
    if 2 * errs > synd.len() {
        return Err(err(format!("Too many errors to correct! ({errs})")));
    }

    let mut error_pos = Vec::new();
    for i in 0..n_mess {
        if err_poly.eval(exp[255 - i]) == 0 {
            error_pos.push(n_mess - 1 - i);
        }
    }
    if error_pos.len() != errs {
        return Err(err(format!(
            "couldn't find error positions! ({}!={errs}) ( missing fragments)",
            error_pos.len()
        )));
    }
    Ok(error_pos)
}

fn decode(message: &[u8], n_ec: usize) -> Result<Vec<u8>> {
    let mut out = message.to_vec();
    let synd = syndromes(&out, n_ec);
    if synd.iter().all(|value| *value == 0) {
        return Ok(out);
    }
    let err_pos = find_errors(&synd, out.len())?;
    correct_errata(&mut out, &synd, &err_pos)?;
    if syndromes(&out, n_ec).iter().any(|value| *value != 0) {
        return Err(err("Reed-Solomon correction left nonzero syndromes"));
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy)]
struct ErasureLayout {
    n: usize,
    encode_size: usize,
    input_size: usize,
    n_ec: usize,
    symbol_size: usize,
}

fn checked_layout(
    original_blobs: usize,
    allowed_failures: usize,
    max_codeword: usize,
) -> Result<ErasureLayout> {
    if original_blobs == 0 {
        return Err(err("Reed-Solomon original blob count must be positive"));
    }
    if max_codeword == 0 {
        return Err(err("Reed-Solomon max codeword must be positive"));
    }

    let parity = allowed_failures
        .checked_mul(2)
        .ok_or_else(|| err("Reed-Solomon parameter overflow"))?;
    let n = original_blobs
        .checked_add(parity)
        .ok_or_else(|| err("Reed-Solomon parameter overflow"))?;
    let max = max_codeword.min(256);
    if n > max {
        return Err(err(format!(
            "Reed-Solomon shard count {n} exceeds codeword bound {max}"
        )));
    }

    let encode_size = (max / n)
        .checked_mul(n)
        .ok_or_else(|| err("Reed-Solomon layout overflow"))?;
    let input_size = encode_size
        .checked_mul(original_blobs)
        .ok_or_else(|| err("Reed-Solomon layout overflow"))?
        / n;
    if input_size == 0 {
        return Err(err("Reed-Solomon input block size must be positive"));
    }
    let symbol_size = input_size / original_blobs;
    if symbol_size == 0 || symbol_size * original_blobs != input_size {
        return Err(err(format!(
            "Bad alignment of bytes in chunking. {input_size} != {symbol_size} * {original_blobs}"
        )));
    }
    let n_ec = encode_size
        .checked_sub(input_size)
        .ok_or_else(|| err("Reed-Solomon layout underflow"))?;

    Ok(ErasureLayout {
        n,
        encode_size,
        input_size,
        n_ec,
        symbol_size,
    })
}

pub fn split(
    ints: &[u8],
    original_blobs: usize,
    allowed_failures: usize,
    max_codeword: usize,
) -> Result<Vec<Vec<u8>>> {
    let layout = checked_layout(original_blobs, allowed_failures, max_codeword)?;

    let blocks = ints.len().div_ceil(layout.input_size);
    let output_capacity = blocks
        .checked_mul(layout.symbol_size)
        .ok_or_else(|| err("Reed-Solomon output size overflow"))?;
    let mut outputs = Vec::with_capacity(layout.n);
    for _ in 0..layout.n {
        let mut output = Vec::new();
        output
            .try_reserve_exact(output_capacity)
            .map_err(|_| err("Unable to allocate Reed-Solomon output fragments"))?;
        outputs.push(output);
    }
    let mut offset = 0usize;
    while offset < ints.len() {
        let end = offset.saturating_add(layout.input_size).min(ints.len());
        let input = &ints[offset..end];
        let encoded = encode(input, layout.n_ec)?;
        if encoded.len() != input.len() + layout.n_ec {
            return Err(err("Reed-Solomon encoder returned an invalid block size"));
        }
        for (j, output) in outputs.iter_mut().enumerate().take(layout.n) {
            let start = j * layout.symbol_size;
            let frag_end = start + layout.symbol_size;
            // The vendored JS writer reads fixed-width shard symbols even when
            // the final encoded Uint8Array is short. Out-of-range reads become
            // zero when assigned to its Uint8Array output buffer.
            output.extend(
                (start..frag_end).map(|position| encoded.get(position).copied().unwrap_or(0)),
            );
        }
        offset = end;
    }
    Ok(outputs)
}

pub fn recombine(
    encoded: &[Vec<u8>],
    truncate_to: usize,
    original_blobs: usize,
    allowed_failures: usize,
    max_codeword: usize,
) -> Result<Vec<u8>> {
    let layout = checked_layout(original_blobs, allowed_failures, max_codeword)?;
    if encoded.len() != layout.n {
        return Err(err("Encoded fragment count does not match RS n"));
    }
    let total_fragment_size = encoded[0].len();

    for fragment in encoded.iter().skip(1) {
        if fragment.len() != total_fragment_size {
            return Err(err("Encoded fragments must all have the same length"));
        }
    }
    if !total_fragment_size.is_multiple_of(layout.symbol_size) {
        return Err(err(
            "Encoded fragment length is not aligned to the Reed-Solomon symbol size",
        ));
    }
    let decoded_capacity = (total_fragment_size / layout.symbol_size)
        .checked_mul(layout.input_size)
        .ok_or_else(|| err("Reed-Solomon decoded size overflow"))?;
    if truncate_to > decoded_capacity {
        return Err(err(
            "Requested Reed-Solomon output length exceeds reconstructed data",
        ));
    }

    let mut out = Vec::new();
    out.try_reserve_exact(decoded_capacity)
        .map_err(|_| err("Unable to allocate Reed-Solomon decoded output"))?;
    let mut offset = 0usize;
    while offset < total_fragment_size {
        let mut block = Vec::with_capacity(layout.encode_size);
        for fragment in encoded {
            let end = offset
                .checked_add(layout.symbol_size)
                .ok_or_else(|| err("Reed-Solomon fragment offset overflow"))?;
            block.extend_from_slice(&fragment[offset..end]);
        }
        let decoded = decode(&block, layout.n_ec)?;
        out.extend_from_slice(&decoded[..layout.input_size]);
        offset += layout.symbol_size;
    }

    out.truncate(truncate_to);
    Ok(out)
}

use std::sync::OnceLock;

use crate::error::{err, Result};

const GENERATOR: u8 = 0xe5;
const REDUCTION_POLY: u8 = 0x1b;

#[derive(Debug, Clone)]
struct RandomSource<'a> {
    preloaded: Option<&'a [u8]>,
    offset: usize,
}

impl<'a> RandomSource<'a> {
    fn new(preloaded: Option<&'a [u8]>) -> Self {
        Self {
            preloaded,
            offset: 0,
        }
    }

    fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        if let Some(preloaded) = self.preloaded {
            let end = self.offset + out.len();
            if end > preloaded.len() {
                return Err(err("Insufficient deterministic SSS random bytes"));
            }
            out.copy_from_slice(&preloaded[self.offset..end]);
            self.offset = end;
            return Ok(());
        }

        getrandom::getrandom(out)
            .map_err(|error| err(format!("OS randomness is unavailable: {error}")))
    }
}

fn tables() -> &'static ([u8; 255], [u8; 256]) {
    static TABLES: OnceLock<([u8; 255], [u8; 256])> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut exp = [0u8; 255];
        let mut log = [0u8; 256];
        let mut value = 1u8;
        for i in 0..255 {
            exp[i] = value;
            log[value as usize] = i as u8;
            value = mult_no_lut(value, GENERATOR);
        }
        (exp, log)
    })
}

fn mult_no_lut(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    while b != 0 {
        if (b & 1) != 0 {
            product ^= a;
        }
        let carry = (a & 0x80) != 0;
        a <<= 1;
        if carry {
            a ^= REDUCTION_POLY;
        }
        b >>= 1;
    }
    product
}

fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

fn mult(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let (exp, log) = tables();
    let sum = (usize::from(log[a as usize]) + usize::from(log[b as usize])) % 255;
    exp[sum]
}

fn div(a: u8, b: u8) -> Result<u8> {
    if b == 0 {
        return Err(err("cannot divide by zero"));
    }
    if a == 0 {
        return Ok(0);
    }
    let (exp, log) = tables();
    let diff = (i16::from(log[a as usize]) - i16::from(log[b as usize]) + 255) % 255;
    Ok(exp[diff as usize])
}

fn interpolate_polynomial(x_samples: &[u8], y_samples: &[u8], x: u8) -> Result<u8> {
    if x_samples.len() != y_samples.len() {
        return Err(err("sample length mistmatch"));
    }

    let mut result = 0u8;
    for i in 0..x_samples.len() {
        let mut basis = 1u8;
        for j in 0..x_samples.len() {
            if i == j {
                continue;
            }
            let num = add(x, x_samples[j]);
            let denom = add(x_samples[i], x_samples[j]);
            let term = div(num, denom)?;
            basis = mult(basis, term);
        }
        result = add(result, mult(y_samples[i], basis));
    }
    Ok(result)
}

fn evaluate(coefficients: &[u8], x: u8, degree: usize) -> Result<u8> {
    if x == 0 {
        return Err(err("cannot evaluate secret polynomial at zero"));
    }

    let mut result = coefficients[degree];
    for coefficient in coefficients[..degree].iter().rev() {
        result = add(mult(result, x), *coefficient);
    }
    Ok(result)
}

fn new_coefficients(
    intercept: u8,
    degree: usize,
    random: &mut RandomSource<'_>,
) -> Result<Vec<u8>> {
    let mut coefficients = vec![0u8; degree + 1];
    coefficients[0] = intercept;
    random.fill(&mut coefficients[1..])?;
    Ok(coefficients)
}

fn new_coordinates(random: &mut RandomSource<'_>) -> Result<[u8; 255]> {
    let mut coordinates = std::array::from_fn(|i| (i + 1) as u8);
    let mut random_indices = [0u8; 255];
    random.fill(&mut random_indices)?;
    for i in 0..255 {
        let j = usize::from(random_indices[i] % 255);
        coordinates.swap(i, j);
    }
    Ok(coordinates)
}

pub fn split_secret(
    secret: &[u8],
    shares: usize,
    threshold: usize,
    deterministic_random: Option<&[u8]>,
) -> Result<Vec<Vec<u8>>> {
    if secret.is_empty() {
        return Err(err("Secret cannot be empty"));
    }
    if !(2..256).contains(&shares) {
        return Err(err("shares must be at least 2 and at most 255"));
    }
    if !(2..256).contains(&threshold) {
        return Err(err("threshold must be at least 2 and at most 255"));
    }
    if shares < threshold {
        return Err(err("shares cannot be less than threshold"));
    }

    let mut random = RandomSource::new(deterministic_random);
    let x_coordinates = new_coordinates(&mut random)?;
    let mut result = Vec::with_capacity(shares);
    for i in 0..shares {
        let mut share = vec![0u8; secret.len() + 1];
        share[secret.len()] = x_coordinates[i];
        result.push(share);
    }

    let degree = threshold - 1;
    for (i, byte) in secret.iter().copied().enumerate() {
        let coefficients = new_coefficients(byte, degree, &mut random)?;
        for j in 0..shares {
            let x = x_coordinates[j];
            let y = evaluate(&coefficients, x, degree)?;
            result[j][i] = y;
        }
    }

    Ok(result)
}

pub fn combine_shares<S: AsRef<[u8]>>(shares: &[S]) -> Result<Vec<u8>> {
    if !(2..256).contains(&shares.len()) {
        return Err(err("shares must have at least 2 and at most 255 elements"));
    }

    let first_share = shares[0].as_ref();
    if first_share.len() < 2 {
        return Err(err("each share must be at least 2 bytes"));
    }

    let share_length = first_share.len();
    for share in shares {
        let share = share.as_ref();
        if share.len() < 2 {
            return Err(err("each share must be at least 2 bytes"));
        }
        if share.len() != share_length {
            return Err(err("all shares must have the same byte length"));
        }
    }

    let secret_length = share_length - 1;
    let mut secret = vec![0u8; secret_length];
    let mut x_samples = vec![0u8; shares.len()];
    let mut y_samples = vec![0u8; shares.len()];
    let mut seen = [false; 256];

    for (i, share) in shares.iter().enumerate() {
        let share = share.as_ref();
        let sample = share[share_length - 1];
        if seen[sample as usize] {
            return Err(err(
                "shares must contain unique values but a duplicate was found",
            ));
        }
        seen[sample as usize] = true;
        x_samples[i] = sample;
    }

    for i in 0..secret_length {
        for (j, share) in shares.iter().enumerate() {
            y_samples[j] = share.as_ref()[i];
        }
        secret[i] = interpolate_polynomial(&x_samples, &y_samples, 0)?;
    }

    Ok(secret)
}

pub fn calculate_threshold_from_rs(n: usize, k: usize) -> Result<usize> {
    if k < 2 || n <= k {
        return Err(err("Invalid Reed-Solomon parameters"));
    }
    if (n - k) % 2 != 0 {
        return Err(err("Invalid Reed-Solomon parameters"));
    }
    if n < 5 {
        return Err(err("Invalid Reed-Solomon parameters"));
    }
    Ok(k + ((n - k) / 2))
}

use core::num::NonZeroU32;

use fips203::{CryptoRng, RngCore, RngError};
use zeroize::Zeroizing;

use crate::error::{coded, QvCode, Result};

#[derive(Debug, Default)]
pub(crate) struct SystemRng;

impl RngCore for SystemRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest)
            .expect("OS randomness must be available for SystemRng");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), RngError> {
        fill_random(dest).map_err(|_| {
            NonZeroU32::new(RngError::CUSTOM_START)
                .unwrap_or(NonZeroU32::MIN)
                .into()
        })
    }
}

impl CryptoRng for SystemRng {}

pub(crate) fn fill_random(dest: &mut [u8]) -> Result<()> {
    getrandom::fill(dest).map_err(|error| {
        coded(
            QvCode::EntropyFailed,
            format!("OS randomness is unavailable: {error}"),
        )
    })
}

pub(crate) fn secret_random_array<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut bytes = Zeroizing::new([0u8; N]);
    fill_random(bytes.as_mut())?;
    Ok(bytes)
}

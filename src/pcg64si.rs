// https://github.com/imneme/pcg-c
use rand::{Error, RngCore, SeedableRng};
use rand_core::impls;

#[derive(Debug, Copy, Clone)]
pub struct Pcg64Si {
    state: u64,
}

impl RngCore for Pcg64Si {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        let old_state = self.state;
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);

        let word =
            ((old_state >> ((old_state >> 59) + 5)) ^ old_state).wrapping_mul(12605985483714917081);
        (word >> 43) ^ word
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        impls::fill_bytes_via_next(self, dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl SeedableRng for Pcg64Si {
    type Seed = [u8; 8];

    fn from_seed(seed: Self::Seed) -> Pcg64Si {
        Pcg64Si {
            state: u64::from_le_bytes(seed),
        }
    }
}

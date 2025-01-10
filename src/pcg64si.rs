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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // For a given seed the RNG is deterministic
    // thus we can perform some basic tests consistently
    #[test]
    fn test_rng_next() {
        let mut rng = Pcg64Si::from_seed([1, 2, 3, 4, 5, 6, 7, 8]);
        let mut values_set: HashSet<u32> = HashSet::new();
        // Generate 1000 values modulus 100 (so each value is between 0 and 99)
        for _ in 0..1000 {
            values_set.insert(rng.next_u32() % 100);
        }
        // Expect to generate every number between 0 and 99 (the generated values are somewhat evenly distributed)
        assert_eq!(values_set.len(), 100);
    }

    #[test]
    fn test_rng_from_seed() {
        // Different seeds should result in a different RNG state
        let rng1 = Pcg64Si::from_seed([1, 2, 3, 4, 5, 6, 7, 8]);
        let rng2 = Pcg64Si::from_seed([1, 2, 3, 4, 5, 6, 7, 7]);
        assert_ne!(rng1.state, rng2.state);
    }

    #[test]
    fn test_rng_fill_bytes() {
        // This uses the next_u64/u32 functions underneath, so don't need to test the pseudo randomness again
        let mut array: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
        let mut rng = Pcg64Si::from_seed([1, 2, 3, 4, 5, 6, 7, 8]);
        let result = rng.try_fill_bytes(&mut array);
        assert!(result.is_ok());
        assert_ne!(array, [0, 0, 0, 0, 0, 0, 0, 0]);
    }
}

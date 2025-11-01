use std::{num::NonZeroU64, ops::Sub};

#[static_init::dynamic]
static START_INSTANT: std::time::Instant = std::time::Instant::now();

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SmallInstant {
    pub nanos: NonZeroU64,
}

impl SmallInstant {
    pub fn now() -> Self {
        let now = std::time::Instant::now();
        let nanos = now.duration_since(*START_INSTANT).as_nanos() as u64;

        SmallInstant {
            nanos: NonZeroU64::new(nanos).unwrap(),
        }
    }

    pub fn elapsed(&self) -> std::time::Duration {
        let now = Self::now();

        now - *self
    }
}

impl Into<std::time::Instant> for SmallInstant {
    fn into(self) -> std::time::Instant {
        *START_INSTANT + std::time::Duration::from_nanos(self.nanos.get())
    }
}

impl Sub<SmallInstant> for SmallInstant {
    type Output = std::time::Duration;

    fn sub(self, rhs: SmallInstant) -> Self::Output {
        let duration_nanos = self.nanos.get() - rhs.nanos.get();

        std::time::Duration::from_nanos(duration_nanos)
    }
}

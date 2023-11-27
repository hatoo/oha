use std::{fmt, time::Duration};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimeScale {
    Second,
    TenSeconds,
    Minute,
    TenMinutes,
    Hour,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TimeLabel {
    pub x: usize,
    pub timescale: TimeScale,
}

impl fmt::Display for TimeScale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeScale::Second => write!(f, "second"),
            TimeScale::TenSeconds => write!(f, "10 seconds"),
            TimeScale::Minute => write!(f, "minute"),
            TimeScale::TenMinutes => write!(f, "10 minutes"),
            TimeScale::Hour => write!(f, "hour"),
        }
    }
}

impl fmt::Display for TimeLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeLabel {
                x,
                timescale: TimeScale::Second,
            } => write!(f, "{x}s"),
            TimeLabel {
                x,
                timescale: TimeScale::TenSeconds,
            } => write!(f, "{}s", 10 * x),
            TimeLabel {
                x,
                timescale: TimeScale::Minute,
            } => write!(f, "{x}m"),
            TimeLabel {
                x,
                timescale: TimeScale::TenMinutes,
            } => write!(f, "{}m", 10 * x),
            TimeLabel {
                x,
                timescale: TimeScale::Hour,
            } => write!(f, "{x}h"),
        }
    }
}

impl TimeScale {
    pub fn as_secs_f64(&self) -> f64 {
        match self {
            TimeScale::Second => 1.0,
            TimeScale::TenSeconds => 10.0,
            TimeScale::Minute => 60.0,
            TimeScale::TenMinutes => 10.0 * 60.0,
            TimeScale::Hour => 60.0 * 60.0,
        }
    }

    pub fn from_elapsed(duration: Duration) -> Self {
        for ts in &[
            TimeScale::Hour,
            TimeScale::TenMinutes,
            TimeScale::Minute,
            TimeScale::TenSeconds,
            TimeScale::Second,
        ] {
            if duration.as_secs_f64() > ts.as_secs_f64() {
                return *ts;
            }
        }

        TimeScale::Second
    }

    pub fn inc(&self) -> Self {
        match self {
            TimeScale::Second => TimeScale::TenSeconds,
            TimeScale::TenSeconds => TimeScale::Minute,
            TimeScale::Minute => TimeScale::TenMinutes,
            TimeScale::TenMinutes => TimeScale::Hour,
            TimeScale::Hour => TimeScale::Hour,
        }
    }

    pub fn dec(&self) -> Self {
        match self {
            TimeScale::Second => TimeScale::Second,
            TimeScale::TenSeconds => TimeScale::Second,
            TimeScale::Minute => TimeScale::TenSeconds,
            TimeScale::TenMinutes => TimeScale::Minute,
            TimeScale::Hour => TimeScale::TenMinutes,
        }
    }
}

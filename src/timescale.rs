use std::{fmt, time::Duration};

#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum TimeScale {
    Nanosecond,  // 1e-9
    Microsecond, // 1e-6
    Millisecond, // 1e-3
    Second,      // 1
    TenSeconds,  // 10
    Minute,      // 60
    TenMinutes,  // 600
    Hour,        // 3600
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TimeLabel {
    pub x: usize,
    pub timescale: TimeScale,
}

impl fmt::Display for TimeScale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeScale::Nanosecond => write!(f, "ns"),
            TimeScale::Microsecond => write!(f, "us"),
            TimeScale::Millisecond => write!(f, "ms"),
            TimeScale::Second => write!(f, "sec"),
            TimeScale::TenSeconds => write!(f, "10 sec"),
            TimeScale::Minute => write!(f, "min"),
            TimeScale::TenMinutes => write!(f, "10 min"),
            TimeScale::Hour => write!(f, "hr"),
        }
    }
}

impl fmt::Display for TimeLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeLabel {
                x,
                timescale: TimeScale::Nanosecond,
            } => write!(f, "{x}ns"),
            TimeLabel {
                x,
                timescale: TimeScale::Microsecond,
            } => write!(f, "{x}us"),
            TimeLabel {
                x,
                timescale: TimeScale::Millisecond,
            } => write!(f, "{x}ms"),
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

impl clap::ValueEnum for TimeScale {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Self::Nanosecond,
            Self::Microsecond,
            Self::Millisecond,
            Self::Second,
            Self::Minute,
            Self::Hour,
        ]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        match self {
            TimeScale::Nanosecond => Some(clap::builder::PossibleValue::new("ns")),
            TimeScale::Microsecond => Some(clap::builder::PossibleValue::new("us")),
            TimeScale::Millisecond => Some(clap::builder::PossibleValue::new("ms")),
            TimeScale::Second => Some(clap::builder::PossibleValue::new("s")),
            TimeScale::Minute => Some(clap::builder::PossibleValue::new("m")),
            TimeScale::Hour => Some(clap::builder::PossibleValue::new("h")),
            TimeScale::TenSeconds | TimeScale::TenMinutes => None,
        }
    }
}

impl TimeScale {
    pub fn as_secs_f64(&self) -> f64 {
        match self {
            TimeScale::Nanosecond => 1e-9,
            TimeScale::Microsecond => 1e-6,
            TimeScale::Millisecond => 1e-3,
            TimeScale::Second => 1.0,
            TimeScale::TenSeconds => 10.0,
            TimeScale::Minute => 60.0,
            TimeScale::TenMinutes => 10.0 * 60.0,
            TimeScale::Hour => 60.0 * 60.0,
        }
    }

    /// From seconds as f64
    pub fn from_f64(seconds: f64) -> Self {
        for ts in &[
            TimeScale::Hour,
            TimeScale::TenMinutes,
            TimeScale::Minute,
            TimeScale::TenSeconds,
            TimeScale::Second,
            TimeScale::Millisecond,
            TimeScale::Microsecond,
            TimeScale::Nanosecond,
        ] {
            if seconds > ts.as_secs_f64() {
                return *ts;
            }
        }
        TimeScale::Nanosecond
    }

    pub fn from_elapsed(duration: Duration) -> Self {
        Self::from_f64(duration.as_secs_f64())
    }

    pub fn inc(&self) -> Self {
        match self {
            TimeScale::Nanosecond => TimeScale::Microsecond,
            TimeScale::Microsecond => TimeScale::Millisecond,
            TimeScale::Millisecond => TimeScale::Second,
            TimeScale::Second => TimeScale::TenSeconds,
            TimeScale::TenSeconds => TimeScale::Minute,
            TimeScale::Minute => TimeScale::TenMinutes,
            TimeScale::TenMinutes => TimeScale::Hour,
            TimeScale::Hour => TimeScale::Hour,
        }
    }

    pub fn dec(&self) -> Self {
        match self {
            TimeScale::Nanosecond => TimeScale::Nanosecond,
            TimeScale::Microsecond => TimeScale::Nanosecond,
            TimeScale::Millisecond => TimeScale::Microsecond,
            TimeScale::Second => TimeScale::Millisecond,
            TimeScale::TenSeconds => TimeScale::Second,
            TimeScale::Minute => TimeScale::TenSeconds,
            TimeScale::TenMinutes => TimeScale::Minute,
            TimeScale::Hour => TimeScale::TenMinutes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_timescale_correct_for_seconds_range(
        range: [f64; 2],
        expected_timescale: TimeScale,
        expected_timescale_str: &str,
        expected_timescale_as_secs: f64,
    ) {
        for durations in range {
            let timescale = TimeScale::from_elapsed(Duration::from_secs_f64(durations));
            assert_eq!(timescale, expected_timescale);
            assert_eq!(format!("{timescale}"), expected_timescale_str);
            assert_eq!(timescale.as_secs_f64(), expected_timescale_as_secs);
        }
    }

    #[test]
    fn test_timescale_ranges() {
        assert_timescale_correct_for_seconds_range(
            [f64::MIN_POSITIVE, 1e-6],
            TimeScale::Nanosecond,
            "ns",
            1e-9,
        );
        assert_timescale_correct_for_seconds_range(
            [0.000_001_1, 1e-3],
            TimeScale::Microsecond,
            "us",
            1e-6,
        );
        assert_timescale_correct_for_seconds_range(
            [0.001_1, 1.0],
            TimeScale::Millisecond,
            "ms",
            1e-3,
        );
        assert_timescale_correct_for_seconds_range([1.1, 10.0], TimeScale::Second, "sec", 1.0);
        assert_timescale_correct_for_seconds_range(
            [10.1, 60.0],
            TimeScale::TenSeconds,
            "10 sec",
            10.0,
        );
        assert_timescale_correct_for_seconds_range([60.1, 600.0], TimeScale::Minute, "min", 60.0);
        assert_timescale_correct_for_seconds_range(
            [600.1, 3600.0],
            TimeScale::TenMinutes,
            "10 min",
            600.0,
        );
        assert_timescale_correct_for_seconds_range(
            [3600.1, 31536000.0],
            TimeScale::Hour,
            "hr",
            3600.0,
        );
    }

    #[test]
    fn test_timescale_inc() {
        let timescale = TimeScale::from_elapsed(Duration::from_secs_f64(1e-10));
        let timescale_microsecond = timescale.inc();
        assert_eq!(timescale_microsecond, TimeScale::Microsecond);
        let timescale_millisecond = timescale_microsecond.inc();
        assert_eq!(timescale_millisecond, TimeScale::Millisecond);
        let timescale_second = timescale_millisecond.inc();
        assert_eq!(timescale_second, TimeScale::Second);
        let timescale_ten_seconds = timescale_second.inc();
        assert_eq!(timescale_ten_seconds, TimeScale::TenSeconds);
        let timescale_minute = timescale_ten_seconds.inc();
        assert_eq!(timescale_minute, TimeScale::Minute);
        let timescale_ten_minutes = timescale_minute.inc();
        assert_eq!(timescale_ten_minutes, TimeScale::TenMinutes);
        let timescale_hour = timescale_ten_minutes.inc();
        assert_eq!(timescale_hour, TimeScale::Hour);
    }

    #[test]
    fn test_timescale_dec() {
        let timescale = TimeScale::from_elapsed(Duration::from_secs_f64(31536000.0));
        let timescale_ten_minutes = timescale.dec();
        assert_eq!(timescale_ten_minutes, TimeScale::TenMinutes);
        let timescale_minute = timescale_ten_minutes.dec();
        assert_eq!(timescale_minute, TimeScale::Minute);
        let timescale_ten_seconds = timescale_minute.dec();
        assert_eq!(timescale_ten_seconds, TimeScale::TenSeconds);
        let timescale_second = timescale_ten_seconds.dec();
        assert_eq!(timescale_second, TimeScale::Second);
        let timescale_millisecond = timescale_second.dec();
        assert_eq!(timescale_millisecond, TimeScale::Millisecond);
        let timescale_microsecond = timescale_millisecond.dec();
        assert_eq!(timescale_microsecond, TimeScale::Microsecond);
        let timescale_nanosecond = timescale_microsecond.dec();
        assert_eq!(timescale_nanosecond, TimeScale::Nanosecond);
    }
}

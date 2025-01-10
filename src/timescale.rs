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
            assert_eq!(format!("{}", timescale), expected_timescale_str);
            assert_eq!(timescale.as_secs_f64(), expected_timescale_as_secs);
        }
    }

    #[test]
    fn test_timescale_ranges() {
        assert_timescale_correct_for_seconds_range(
            [f64::MIN_POSITIVE, 10.0],
            TimeScale::Second,
            "second",
            1.0,
        );
        assert_timescale_correct_for_seconds_range(
            [10.1, 60.0],
            TimeScale::TenSeconds,
            "10 seconds",
            10.0,
        );
        assert_timescale_correct_for_seconds_range(
            [60.1, 600.0],
            TimeScale::Minute,
            "minute",
            60.0,
        );
        assert_timescale_correct_for_seconds_range(
            [600.1, 3600.0],
            TimeScale::TenMinutes,
            "10 minutes",
            600.0,
        );
        assert_timescale_correct_for_seconds_range(
            [3600.1, 31536000.0],
            TimeScale::Hour,
            "hour",
            3600.0,
        );
    }

    #[test]
    fn test_timescale_inc() {
        let timescale = TimeScale::from_elapsed(Duration::from_secs_f64(0.1));
        let timescale_ten_seconds = timescale.inc();
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
    }
}

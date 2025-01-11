use ratatui::crossterm::style::Color;

// Background: Deep Space, dark but with subtle stardust
pub const BACKGROUND: Color = Color::AnsiValue(235);

// Success: Cool, calming, like a nebula
pub const SUCCESS: Color = Color::AnsiValue(85);
pub const FASTEST: Color = Color::AnsiValue(85);
pub const REQUEST_HISTOGRAM: Color = Color::AnsiValue(85);

// Warning: Neutral, like a distant star
pub const WARNING: Color = Color::AnsiValue(229);
pub const AVERAGE: Color = Color::AnsiValue(229);
pub const RESPONSE_HISTOGRAM: Color = Color::AnsiValue(229);

// Error: Alert, like a pulsar
pub const ERROR: Color = Color::AnsiValue(199);
pub const SLOWEST: Color = Color::AnsiValue(199);

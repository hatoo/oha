use ratatui::crossterm::style::Color;

pub const BACKGROUND: Color = Color::Rgb { r: 30, g: 33, b: 36 };         // Deep Charcoal
pub const SLOWEST: Color = Color::Rgb { r: 247, g: 157, b: 132 };          // Muted Coral
pub const FASTEST: Color = Color::Rgb { r: 196, g: 240, b: 224 };          // Light Soft Mint
pub const AVERAGE: Color = Color::Rgb { r: 209, g: 196, b: 233 };          // Muted Lavender

// State based colors
pub const SUCCESS: Color = Color::Rgb { r: 127, g: 182, b: 133 };          // Sage Green
pub const WARNING: Color = Color::Rgb { r: 255, g: 193, b: 7 };            // Amber
pub const ERROR: Color = Color::Rgb { r: 220, g: 53, b: 69 };              // Bold Red

// Histograms
pub const REQUEST_HISTOGRAM: Color = Color::Rgb { r: 168, g: 230, b: 207 };   // Soft Mint
pub const RESPONSE_HISTOGRAM: Color = Color::Rgb { r: 127, g: 182, b: 133 };   // Sage Green
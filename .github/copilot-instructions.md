# GitHub Copilot Instructions for oha

## Project Overview

`oha` (おはよう) is an HTTP load testing tool written in Rust, inspired by `rakyll/hey`. It provides real-time TUI (Terminal User Interface) visualization of load testing results using `ratatui`.

## Key Technologies & Dependencies

- **Language**: Rust (edition 2024, MSRV 1.85)
- **Async Runtime**: `tokio` with full features
- **HTTP Client**: `hyper` (v1.4) with HTTP/1, HTTP/2 support
- **TUI**: `ratatui` with `crossterm` backend
- **CLI**: `clap` with derive features
- **Memory Allocator**: `tikv-jemallocator` (non-MSVC targets)
- **Error Handling**: `anyhow` and `thiserror`
- **JSON**: `serde` and `serde_json`
- **Database**: `rusqlite` with bundled SQLite
- **Networking**: `hickory-resolver` for DNS resolution

## Project Structure

```
src/
├── lib.rs           # Main library with CLI definitions and core logic
├── main.rs          # Binary entry point
├── client.rs        # HTTP client implementations (HTTP/1, HTTP/2)
├── client_h3.rs     # HTTP/3 client (feature-gated)
├── aws_auth.rs      # AWS signature authentication
├── db.rs           # Database operations for storing results
├── histogram.rs     # Statistical histogram implementation
├── monitor.rs       # Real-time monitoring and TUI
├── printer.rs       # Output formatting and display
├── result_data.rs   # Data structures for test results
├── timescale.rs     # Time-based scaling utilities
├── tls_config.rs    # TLS configuration
├── url_generator.rs # URL generation with patterns
└── pcg64si.rs      # Random number generation
```

## Features & Build Configurations

### Default Features
- `rustls` - Uses rustls for TLS (default)

### Optional Features
- `native-tls` - Use native TLS instead of rustls
- `vsock` - Enable VSOCK support for VM communication
- `http3` - Experimental HTTP/3 support via `h3` library

### Build Examples
```bash
# Default build with rustls
cargo build

# With native TLS
cargo build --no-default-features --features native-tls

# With HTTP/3 support
cargo build --features http3

# With VSOCK support
cargo build --features vsock
```

## Code Style & Conventions

### Error Handling
- Use `anyhow::Result<T>` for functions that can fail
- Use `anyhow::bail!()` for early returns with error messages
- Use `anyhow::ensure!()` for validation with custom error messages
- Use `thiserror` for custom error types (when needed)

### Async Code
- All async code uses `tokio`
- Use `tokio::spawn` for concurrent tasks
- Prefer `async/await` over manual future polling

### CLI Structure
- Use `clap` derive macros for argument parsing
- Main configuration struct is typically in `lib.rs`
- Support both short and long argument forms

### TUI Guidelines
- Use `ratatui` for all terminal UI components
- Handle terminal resize events
- Implement proper cleanup on exit
- Use `crossterm` for terminal control

### HTTP Client Patterns
- Support HTTP/1.1, HTTP/2, and optionally HTTP/3
- Handle connection pooling and reuse
- Implement proper timeout handling
- Support custom headers and authentication

### Performance Considerations
- Use `jemalloc` allocator for better memory performance
- Leverage `tokio`'s async runtime efficiently
- Minimize allocations in hot paths
- Use streaming where appropriate for large responses
- Use PCG64SI PRNG (`pcg64si.rs`) for high-performance random number generation

## Testing

### Test Structure
- Integration tests in `tests/` directory
- Use `assert_cmd` for CLI testing
- Test server setup with `axum` and `axum-server`
- SSL/TLS testing with provided certificates

### Test Data
- Test certificates: `tests/common/server.cert` and `tests/common/server.key`
- Common test utilities in `tests/common/mod.rs`

## Development Guidelines

1. **Cross-platform**: Ensure code works on Linux, macOS, and Windows
2. **Feature gates**: Use appropriate feature gates for optional dependencies
3. **Documentation**: Document public APIs with rustdoc comments
4. **Performance**: Profile and optimize hot paths
5. **Error messages**: Provide helpful, actionable error messages
6. **CLI UX**: Follow Unix conventions for command-line tools

## Dependencies to Prefer

- **HTTP**: `hyper` and `hyper-util` for HTTP client functionality
- **TLS**: `rustls` by default, `native-tls` as fallback
- **Async**: `tokio` ecosystem (`tokio-util`, `tokio-rustls`, etc.)
- **CLI**: `clap` for argument parsing
- **Serialization**: `serde` ecosystem
- **Random**: `rand` and `rand_core` for randomization needs
- **Time**: `chrono` for time handling

## Platform-specific Code

- Use `#[cfg(unix)]` for Unix-specific features (like `rlimit`)
- Use `#[cfg(not(target_env = "msvc"))]` for non-MSVC Windows builds
- Handle platform differences in TLS and networking code appropriately

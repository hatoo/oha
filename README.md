```bash
kon on  master is 📦 v0.1.0 via 🦀 v1.43.0-nightly took 4s
❯ cargo run --release -- http://localhost:8080
    Finished release [optimized] target(s) in 0.09s
     Running `target/release/kon 'http://localhost:8080'`
Summary:
  Success rate: 1.0000
  Total:        0.0310 secs
  Slowest:      0.0184 secs
  Fastest:      0.0014 secs
  Average:      0.0060 secs
  Requests/sec: 6454.6320 secs

  Total data:   122400 bytes
  Size/request: 612 bytes

Latency distribution:
  10% in 0.0017 secs
  25% in 0.0019 secs
  50% in 0.0022 secs
  75% in 0.0119 secs
  90% in 0.0179 secs
  95% in 0.0182 secs
  99% in 0.0184 secs

Status code distribution:
  [200] 200 responses
```

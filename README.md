```bash
oha on  master is 📦 v0.1.0 via 🦀 v1.43.0-nightly
❯ cargo run --release -- http://localhost:8080
    Finished release [optimized] target(s) in 0.12s
     Running `target/release/oha 'http://localhost:8080'`
Summary:
  Success rate:	1.0000
  Total:	0.0614 secs
  Slowest:	0.0387 secs
  Fastest:	0.0046 secs
  Average:	0.0140 secs
  Requests/sec:	3255.0904

  Total data:	119.53 KiB
  Size/request:	612.00 B
  Size/sec:	1.90 MiB

Latency distribution:
  10% in 0.0070 secs
  25% in 0.0086 secs
  50% in 0.0096 secs
  75% in 0.0249 secs
  90% in 0.0296 secs
  95% in 0.0321 secs
  99% in 0.0382 secs

Status code distribution:
  [200] 200 responses

```

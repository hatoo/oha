```bash
kon on  master is 📦 v0.1.0 via 🦀 v1.43.0-nightly took 3s
❯ hey -c 50 -n 200 http://127.0.0.1:8080

Summary:
  Total:        0.0264 secs
  Slowest:      0.0177 secs
  Fastest:      0.0002 secs
  Average:      0.0046 secs
  Requests/sec: 7574.0936

  Total data:   122400 bytes
  Size/request: 612 bytes

Response time histogram:
  0.000 [1]     |
  0.002 [145]   |■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  0.004 [1]     |
  0.005 [1]     |
  0.007 [2]     |■
  0.009 [1]     |
  0.011 [2]     |■
  0.012 [0]     |
  0.014 [8]     |■■
  0.016 [26]    |■■■■■■■
  0.018 [13]    |■■■■


Latency distribution:
  10% in 0.0006 secs
  25% in 0.0009 secs
  50% in 0.0014 secs
  75% in 0.0088 secs
  90% in 0.0157 secs
  95% in 0.0160 secs
  99% in 0.0166 secs

Details (average, fastest, slowest):
  DNS+dialup:   0.0003 secs, 0.0002 secs, 0.0177 secs
  DNS-lookup:   0.0000 secs, 0.0000 secs, 0.0000 secs
  req write:    0.0000 secs, 0.0000 secs, 0.0002 secs
  resp wait:    0.0040 secs, 0.0002 secs, 0.0147 secs
  resp read:    0.0002 secs, 0.0000 secs, 0.0067 secs

Status code distribution:
  [200] 200 responses




kon on  master is 📦 v0.1.0 via 🦀 v1.43.0-nightly
❯ cargo run --release -- http://127.0.0.1:8080
    Finished release [optimized] target(s) in 0.07s
     Running `target/release/kon 'http://127.0.0.1:8080'`
[src/main.rs:51] duration = 23.2952ms
[src/main.rs:52] n as f64 / duration.as_secs_f64() = 8585.459665510492
```

Looks good. Note: it's just one time try.
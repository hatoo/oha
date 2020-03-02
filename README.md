```bash
kon on  master is 📦 v0.1.0 via 🦀 v1.43.0-nightly took 4s
❯ hey -c 50 -n 200 http://127.0.0.1:8080

Summary:
  Total:        0.0183 secs
  Slowest:      0.0074 secs
  Fastest:      0.0004 secs
  Average:      0.0027 secs
  Requests/sec: 10913.3967

  Total data:   122400 bytes
  Size/request: 612 bytes

Response time histogram:
  0.000 [1]     |■
  0.001 [40]    |■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  0.002 [37]    |■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  0.003 [38]    |■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  0.003 [22]    |■■■■■■■■■■■■■■■■■■■■■■
  0.004 [15]    |■■■■■■■■■■■■■■■
  0.005 [14]    |■■■■■■■■■■■■■■
  0.005 [14]    |■■■■■■■■■■■■■■
  0.006 [12]    |■■■■■■■■■■■■
  0.007 [6]     |■■■■■■
  0.007 [1]     |■


Latency distribution:
  10% in 0.0009 secs
  25% in 0.0013 secs
  50% in 0.0023 secs
  75% in 0.0038 secs
  90% in 0.0053 secs
  95% in 0.0060 secs
  99% in 0.0066 secs

Details (average, fastest, slowest):
  DNS+dialup:   0.0001 secs, 0.0004 secs, 0.0074 secs
  DNS-lookup:   0.0000 secs, 0.0000 secs, 0.0000 secs
  req write:    0.0000 secs, 0.0000 secs, 0.0005 secs
  resp wait:    0.0024 secs, 0.0004 secs, 0.0058 secs
  resp read:    0.0000 secs, 0.0000 secs, 0.0015 secs

Status code distribution:
  [200] 200 responses




kon on  master is 📦 v0.1.0 via 🦀 v1.43.0-nightly
❯ cargo run --release -- http://127.0.0.1:8080
    Finished release [optimized] target(s) in 0.05s
     Running `target/release/kon 'http://127.0.0.1:8080'`
[src/main.rs:56] duration = 913.7767ms
[src/main.rs:57] n as f64 / duration.as_secs_f64() = 218.8718534845548


**WHY????**
```
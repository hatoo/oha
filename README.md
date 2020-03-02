```bash
kon on  master [⇡] is 📦 v0.1.0 via 🦀 v1.43.0-nightly
❯ hey -c 50 -n 200 http://127.0.0.1:8080

Summary:
  Total:        0.0200 secs
  Slowest:      0.0128 secs
  Fastest:      0.0004 secs
  Average:      0.0035 secs
  Requests/sec: 10022.9023

  Total data:   122400 bytes
  Size/request: 612 bytes

Response time histogram:
  0.000 [1]     |
  0.002 [81]    |■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
  0.003 [39]    |■■■■■■■■■■■■■■■■■■■
  0.004 [20]    |■■■■■■■■■■
  0.005 [17]    |■■■■■■■■
  0.007 [14]    |■■■■■■■
  0.008 [0]     |
  0.009 [7]     |■■■
  0.010 [4]     |■■
  0.012 [15]    |■■■■■■■
  0.013 [2]     |■


Latency distribution:
  10% in 0.0011 secs
  25% in 0.0014 secs
  50% in 0.0024 secs
  75% in 0.0050 secs
  90% in 0.0097 secs
  95% in 0.0108 secs
  99% in 0.0123 secs

Details (average, fastest, slowest):
  DNS+dialup:   0.0002 secs, 0.0004 secs, 0.0128 secs
  DNS-lookup:   0.0000 secs, 0.0000 secs, 0.0000 secs
  req write:    0.0000 secs, 0.0000 secs, 0.0012 secs
  resp wait:    0.0032 secs, 0.0004 secs, 0.0107 secs
  resp read:    0.0000 secs, 0.0000 secs, 0.0028 secs

Status code distribution:
  [200] 200 responses




kon on  master [⇡] is 📦 v0.1.0 via 🦀 v1.43.0-nightly
❯ cargo run --release -- http://127.0.0.1:8080
    Finished release [optimized] target(s) in 0.06s
     Running `target/release/kon 'http://127.0.0.1:8080'`
[src/main.rs:60] duration = 31.3913ms
[src/main.rs:61] n as f64 / duration.as_secs_f64() = 6371.19201817064
```
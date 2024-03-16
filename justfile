pgo:
    #!/bin/bash
    trap "kill 0" EXIT
    cargo run --release --manifest-path pgo/server/Cargo.toml &
    # Should be more than 1m
    cargo pgo run -- --profile pgo -- -z 3m -c 900 --no-tui http://localhost:8888
    cargo pgo optimize build -- --profile pgo

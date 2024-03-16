[unix]
pgo addtional-args="":
    #!/bin/bash
    # Disable trap in CI
    # `just` returns weired exit code if we use trap
    if [ -z $CI]; then trap "kill 0" EXIT; fi
    cargo run --release --manifest-path pgo/server/Cargo.toml &
    # Should be more than 1m
    cargo pgo run -- --profile pgo {{addtional-args}} -- -z 3m -c 900 --no-tui http://localhost:8888
    cargo pgo optimize build -- --profile pgo {{addtional-args}}

set windows-powershell := true

[windows]
pgo addtional-args="":
    try { \
        $proc = Start-Process -NoNewWindow -PassThru cargo -ArgumentList 'run','--release','--manifest-path','pgo/server/Cargo.toml'; \
        cargo pgo run -- --profile pgo {{addtional-args}} -- -z 3m -c 900 --no-tui http://localhost:8888; \
        cargo pgo optimize build -- --profile pgo {{addtional-args}}; \
    } finally { Stop-Process -Id $proc.Id }

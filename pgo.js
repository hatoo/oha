import { $ } from "bun";

let additional = [];

if (Bun.argv.length >= 3) {
    additional = Bun.argv.slice(2);
}

let server = null;

try {
    server = Bun.spawn(['cargo', 'run', '--release', '--manifest-path', 'pgo/server/Cargo.toml']);
    await $`cargo pgo run -- --profile pgo ${additional} -- -z 2m -c 900 --no-tui http://localhost:8888`;
    await $`cargo pgo run -- --profile pgo ${additional} -- -n 10000000 -c 900 --no-tui http://localhost:8888`;
    await $`cargo pgo optimize build -- --profile pgo ${additional}`
} finally {
    if (server !== null) {
        server.kill();
    }
}

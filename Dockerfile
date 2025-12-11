ARG RUST_VERSION=slim
FROM docker.io/library/rust:${RUST_VERSION} AS chef

RUN cargo install cargo-chef --locked
RUN apt-get update && apt-get install -y \
    cmake \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json

RUN cargo chef cook --release --no-default-features --features rustls --recipe-path recipe.json

COPY . .
RUN cargo build --release --no-default-features --features rustls --bin oha
RUN strip /app/target/release/oha

FROM registry.fedoraproject.org/fedora-minimal AS runtime
USER 65535
COPY --chown=65535:65535 --from=builder /app/target/release/oha /bin/
ENTRYPOINT ["/bin/oha"]

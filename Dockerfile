ARG RUST_VERSION=1.74
FROM docker.io/library/rust:${RUST_VERSION} AS build
WORKDIR /app
COPY . /app

RUN cargo install --path .

# Target image
FROM registry.fedoraproject.org/fedora-minimal
USER 65535

COPY --chown=65535:65535 --from=build /usr/local/cargo/bin/oha /bin/oha

ENTRYPOINT ["/bin/oha"]

ARG RUST_VERSION=1.79
FROM docker.io/library/rust:${RUST_VERSION} AS build
WORKDIR /app
COPY . /app

RUN apt-get update && apt-get install -y \
    cmake \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN cargo install --path .
RUN strip /usr/local/cargo/bin/oha

# Target image
FROM registry.fedoraproject.org/fedora-minimal
USER 65535

COPY --chown=65535:65535 --from=build /usr/local/cargo/bin/oha /bin/oha

ENTRYPOINT ["/bin/oha"]

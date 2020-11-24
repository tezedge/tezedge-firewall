FROM ubuntu:20.04

# deps
ENV DEBIAN_FRONTEND='noninteractive'
RUN apt-get update && apt install -y git wget gcc libsodium-dev

# rust
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN set -eux; \
    url="https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init"; \
    wget "$url"; \
    chmod +x rustup-init; \
    ./rustup-init -y --no-modify-path --default-toolchain nightly-2020-07-12; \
    rm rustup-init; \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME;

WORKDIR /root

COPY . bpf-firewall/

# packet-generator
ENV SODIUM_USE_PKG_CONFIG=1
RUN apt install -y pkg-config && \
    cd bpf-firewall && cargo build -p packet-generator

from ubuntu:20.04

# deps
RUN apt-get update && \
    DEBIAN_FRONTEND='noninteractive' apt install -y git wget gcc libsodium-dev make zlib1g-dev;

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

# llvm 11
RUN wget https://apt.llvm.org/llvm.sh; \
    chmod +x llvm.sh; \
    DEBIAN_FRONTEND='noninteractive' apt install -y lsb-release software-properties-common; \
    ./llvm.sh 11; \
    rm llvm.sh;

WORKDIR /root

# firewall
# RUN LLVM_SYS_110_PREFIX=/usr/lib/llvm-11 cargo install --git https://github.com/simplestaking/bpf-firewall.git firewall

# CMD firewall --device eth0

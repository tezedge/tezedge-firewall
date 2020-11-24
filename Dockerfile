FROM ubuntu:20.04

# deps
ENV DEBIAN_FRONTEND='noninteractive'
RUN apt-get update && apt install -y git wget gcc kmod libsodium-dev make zlib1g-dev

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
    apt install -y lsb-release software-properties-common; \
    ./llvm.sh 11; \
    rm llvm.sh;

# prepare kernel
ARG kernel_version
RUN apt install -y libarchive-tools flex bison libssl-dev bc libelf-dev && \
    cd /usr/src && \
    wget -c https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-${kernel_version}.tar.xz && \
    bsdtar xJf linux-${kernel_version}.tar.xz && \
    cd linux-${kernel_version} && \
    make defconfig && \
    make modules_prepare

WORKDIR /root

# tezedge
ENV LLVM_CONFIG_PATH="/usr/lib/llvm-11/bin/llvm-config" \
    SODIUM_USE_PKG_CONFIG=1
RUN apt install -y curl g++ libev-dev pkg-config gawk && \
    git clone "https://github.com/simplestaking/tezedge.git" && \
    cd tezedge && git checkout tags/v0.6.0 -b v0.6.0 && \
    cp docker/identities/identity_tezedge.json light_node/etc/tezedge/identity.json && \
    cargo build --release

RUN LD_LIBRARY_PATH="${BASH_SOURCE%/*}/tezos/interop/lib_tezos/artifacts:${BASH_SOURCE%/*}/target/release" \
    cd tezedge && cargo build --release

# firewall
COPY . bpf-firewall/
RUN cd bpf-firewall && \
    KERNEL_VERSION=${kernel_version} \
    KERNEL_SOURCE=/usr/src/linux-${kernel_version} \
    LLVM_SYS_110_PREFIX=/usr/lib/llvm-11 \
    cargo build -p firewall
    # cargo install --git https://github.com/simplestaking/bpf-firewall.git firewall

from ubuntu:20.04

# deps
RUN apt-get update && \
    DEBIAN_FRONTEND='noninteractive' apt install -y git wget gcc kmod libsodium-dev make zlib1g-dev;

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

# prepare kernel
ARG kernel_version
RUN DEBIAN_FRONTEND='noninteractive' apt install -y libarchive-tools flex bison libssl-dev bc libelf-dev && \
    cd /usr/src && \
    wget -c https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-${kernel_version}.tar.xz && \
    bsdtar xJf linux-${kernel_version}.tar.xz && \
    cd linux-${kernel_version} && \
    make defconfig && \
    make modules_prepare

WORKDIR /root

COPY . bpf-firewall/

# firewall
RUN cd bpf-firewall && \
    KERNEL_VERSION=${kernel_version} \
    KERNEL_SOURCE=/usr/src/linux-${kernel_version} \
    LLVM_SYS_110_PREFIX=/usr/lib/llvm-11 \
    cargo build
    # cargo install --git https://github.com/simplestaking/bpf-firewall.git firewall

RUN DEBIAN_FRONTEND='noninteractive' apt install -y netcat && \
    git clone "https://github.com/simplestaking/tezedge.git" && \
    cd tezedge && git checkout tags/v0.6.0 -b v0.6.0 && cargo build --release

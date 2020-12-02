FROM ubuntu:20.04

# deps
ENV DEBIAN_FRONTEND='noninteractive'
RUN apt-get update && apt install -y \
    # common
    git wget gcc kmod libsodium-dev make zlib1g-dev \
    # llvm
    lsb-release software-properties-common \
    # kernel
    libarchive-tools flex bison libssl-dev bc libelf-dev

# rust
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
RUN set -eux && \
    url="https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init" && \
    wget "$url" && \
    chmod +x rustup-init && \
    ./rustup-init -y --no-modify-path --default-toolchain nightly-2020-07-12 && \
    rm rustup-init && \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME

# llvm 11
RUN wget https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh 11 && \
    rm llvm.sh
ENV LLVM_SYS_110_PREFIX=/usr/lib/llvm-11

# firewall
COPY . /root/tezedge-firewall
WORKDIR /root/tezedge-firewall

RUN ./scripts/build.sh 5.8.18

ARG COMPLEXITY=26.0
ENV COMPLEXITY=${COMPLEXITY}
CMD ./scripts/run.sh -d eth0 --target=${COMPLEXITY}

FROM ubuntu:20.04 as builder

# deps
ENV DEBIAN_FRONTEND='noninteractive'
RUN apt-get update && apt install -y \
    # common
    git wget curl gcc libsodium-dev make zlib1g-dev \
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

RUN cargo install cargo-script
RUN ./scripts/build_.rs 5.8.18

FROM ubuntu:20.04

WORKDIR /root/tezedge-firewall
COPY --from=builder /root/tezedge-firewall/scripts/run.sh /root/tezedge-firewall/scripts/
COPY --from=builder /root/tezedge-firewall/scripts/test_pow_reuse.sh /root/tezedge-firewall/scripts/
COPY --from=builder /root/tezedge-firewall/bin /root/tezedge-firewall/bin
COPY --from=builder /root/tezedge-firewall/tests /root/tezedge-firewall/tests

ARG COMPLEXITY=26.0
ENV COMPLEXITY=${COMPLEXITY}
CMD ./scripts/run.sh -d eth0 --target=${COMPLEXITY}

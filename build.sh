#!/usr/bin/env bash

wget -cq https://cdn.kernel.org/pub/linux/kernel/v$2.x/linux-$1.tar.xz
tar -xf linux-$1.tar.xz
pushd linux-$1
make defconfig
make modules_prepare
popd
KERNEL_VERSION=$1 KERNEL_SOURCE=$(pwd)/linux-$1 \
LLVM_SYS_110_PREFIX=/usr/lib/llvm-11 cargo build -p firewall --bin firewall
rm -R linux-$1{,.tar.xz}
mkdir -p target/bpf
mv target/debug/firewall ../firewall-$1
cargo clean

#!/usr/bin/env bash

set -e

export K=${1%-*-*}
if [ ${K#*.*.} == "0" ]
then export K=${K%.*}; export M=${K%.*}
else export M=${K%.*.*}
fi

wget -cq https://cdn.kernel.org/pub/linux/kernel/v$M.x/linux-$K.tar.xz
tar -xf linux-$K.tar.xz
pushd linux-$K
make defconfig
make modules_prepare
popd
export KERNEL_VERSION=$K
export KERNEL_SOURCE=$(pwd)/linux-$K
cargo build -p tezedge-firewall --release && cargo build -p tezedge-firewall --bin fw --bin packet-generator --release
rm -R linux-$K{,.tar.xz}
mkdir -p bin
mv target/release/tezedge-firewall ./bin/firewall-$1
mv target/release/fw ./bin/fw
mv target/release/packet-generator ./bin/packet-generator
cargo clean

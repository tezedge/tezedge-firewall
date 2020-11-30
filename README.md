# Tezos Firewall

## Install

### Dependencies

```
sudo apt-get update
sudo apt install -y git wget gcc make libsodium-dev zlib1g-dev lsb-release software-properties-common linux-headers-$(uname -r)
```

### Rust

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup install nightly-2020-07-12 && rustup default nightly-2020-07-12
source ~/.cargo/env
```

### LLVM 11

```
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 11
rm llvm.sh
```

### The Firewall

```
export LLVM_SYS_110_PREFIX=/usr/lib/llvm-11
cargo install -f --git https://github.com/simplestaking/tezedge-firewall tezedge-firewall
```

## Run

Run the firewall `sudo ~/.cargo/bin/firewall --device <interface name> -b <ip to block> -b <another ip to block>`.

For example `sudo ~/.cargo/bin/firewall --device enp4s0 -b 51.15.220.7 -b 95.217.203.43`.

## Docker

Run in docker, should be privileged.
```
docker run --privileged -d simplestakingcom/tezedge-firewall:0.1
```

The file `/tmp/tezedge_firewall.sock` in the docker container is a unix domain socket.
This socket is communication channel with the TezEdge node.
The TezEdge node should have access to this file. 

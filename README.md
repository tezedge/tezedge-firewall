# Tezos Firewall

We have created a firewall for the TezEdge node that recognizes inbound traffic and filters it out before it enters the node itself. For this purpose, we’re utilizing an eXpress Data Path / Extended Berkeley Packet Filters (XDP/eBPF) module that acts as a layer outside of the node itself. This module allows us to run an application in the kernel that acts as a firewall, filtering incoming messages.

The firewall acts as the TezEdge node’s first line of defense. When a peer first connects to a node, it begins the bootstrapping process, with the first message being the connection message.

The connection message contains the peer’s public key and their proof of work. The proof of work is a small piece of code that is generated based on the associated public key. It is very hard to replicate the proof of work, but it is easy to check its validity. The firewall ensures that each connection starts with a _valid and unique_ (per connection) proof of work. If an adversary wants to start many connections, they must generate many unique proof of works, which makes a DDoS attack very expensive.

The connection message is first subjected to these checks from the firewall. If it passes these checks, the message is allowed to pass into the node. If it does not, the message is rejected without any of its packets ever entering the kernel. This minimizes the node’s attack surface and considerably speeds up traffic filtering.

For a more detailed description of the firewall, please read our [article](https://medium.com/simplestaking/integrating-an-ebpf-based-firewall-into-the-tezedge-node-with-multipass-validations-769d4c6ccd93?source=collection_home---6------1-----------------------).

## Docker compose

### Get the source code

```
git clone https://github.com/simplestaking/tezedge-firewall.git
cd tezedge-firewall
```

### Run example

Tested with: Docker engine version 19.03.12 and Docker compose version 1.26.2.

For the first run it requires internet connection and some time to download docker images.

```
docker-compose -f docker-compose.firewall.ocaml.yml up --build
```

Run the example with multiple attackers, firewall will stop them all.

```
docker-compose -f docker-compose.firewall.ocaml.yml up --build --scale test_proof_of_work=10
```

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

Run it in docker, it should be privileged.
```
docker run --privileged -d simplestakingcom/tezedge-firewall:0.1
```

The file `/tmp/tezedge_firewall.sock` in the docker container is a unix domain socket.
This socket is communication channel with the TezEdge node.
The TezEdge node should have access to this file. 

# Tezos Firewall

We have created a firewall for the TezEdge node that recognizes inbound traffic and filters it out before it enters the node itself. For this purpose, we’re utilizing an eXpress Data Path / Extended Berkeley Packet Filters (XDP/eBPF) module that acts as a layer outside of the node itself. This module allows us to run an application in the kernel that acts as a firewall, filtering incoming messages.

For a more detailed description of the firewall, please read our [article](https://medium.com/simplestaking/integrating-an-ebpf-based-firewall-into-the-tezedge-node-with-multipass-validations-769d4c6ccd93?source=collection_home---6------1-----------------------).

## What does it launch?

The `tezedge-firewall` binary runs the TezEdge firewall, which consists of an XDP module which is loaded in the kernel space memory and the main application itself, which is loaded in the user’s space memory. The main application communicates with the XDP module and also with the TezEdge node. TezEdge node sends a command to the firewall to tell on which port it should filter the traffic along with additional commands. The firewall can also work with the Tezos OCaml node, but this node does not interact directly with the firewall. In this case, the `fw` binary is needed to manually send the commands to the firewall.

The `tezedge-firewall` binary contains eBPF code along with ordinary code in the same file. There are two applications inside: an ordinary Linux application which will run in user space and an XDP program written in eBPF which will run in the kernel space at the very beginning of the path of the network packet.

When it is launched, it inserts the eBPF code into the kernel. This step requires root permission. It creates a kernel object, so-called perfbuf it is a FIFO event queue between kernel space and user space parts of the firewall. Reading this queue also requires root permission. That is how two parts can communicate. When the firewall stops, it will remove the XDP program from the kernel and closes the perfbuf.

## How does the firewall communicate with the node?

The Firewall creates a Unix domain socket at `/tmp/tezedge_firewall.sock` to communicate with Tezos OCaml node or the TezEdge node. The node does not have to use this socket, it is optional. However, if the firewall works on any TCP connection, it will block the user’s traffic, because traffic that does not belong to Tezos will obviously fail the proof of work test. 

We want to prevent this from happening. The firewall will not block anything until it receives a command through the socket. The TezEdge node sends this command automatically when it starts to listen to the P2P layer on a port. When using the firewall with the Tezos OCaml node, the user needs to send the command manually `fw node <port-where-node-listening>`, for example `fw node 9732`.

## How can I set the firewall up?

### Get the source code

```
git clone https://github.com/simplestaking/tezedge-firewall.git
cd tezedge-firewall
```

### Install

The following instructions have been tested to work well on Ubuntu 20.04.

#### Dependencies

```
sudo apt-get update
sudo apt install -y git wget gcc make libsodium-dev zlib1g-dev lsb-release software-properties-common linux-headers-$(uname -r)
```

#### Rust

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup install nightly-2020-10-24 && rustup default nightly-2020-10-24
```

#### LLVM 11

```
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 11
rm llvm.sh
```

#### The Firewall

```
export LLVM_SYS_110_PREFIX=/usr/lib/llvm-11
cargo install -f --git https://github.com/simplestaking/tezedge-firewall tezedge-firewall
```

### Run

Run the firewall `sudo ~/.cargo/bin/tezedge-firewall --device <interface name> -b <ip to block> -b <another ip to block>`.

For example `sudo ~/.cargo/bin/tezedge-firewall --device enp4s0 -b 51.15.220.7 -b 95.217.203.43`.

### Docker

Run it in docker. It should be privileged.
```
docker run --privileged -d simplestakingcom/tezedge-firewall:v0.1.3
```

The file `/tmp/tezedge_firewall.sock` in the Docker container is a Unix domain socket.
This socket is the communication channel with the TezEdge node.
The TezEdge node must have access to this file.

## How can I know whether the firewall is working?

The `ip` Linux util can be used to list all the XDP programs running it. In Ubuntu, this is provided by the `iproute2` package. Install it if necessary. 

```
sudo apt install -y iproute2
```

And then use `ip link`. For example, in the docker container, the output will look like this:

```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
474: eth0@if475: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 xdp qdisc noqueue state UP mode DEFAULT group default
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    prog/xdp id 3878
```

You can see `prog/xdp id 3878`, on the network interface `eth0`. Of course, 3878 is an arbitrary id, you will likely have a different id.

## How can I launch the test?

```
docker-compose -f docker-compose.test.yml pull
docker-compose -f docker-compose.test.yml up
```

## How can I configure the firewall?

There are no configuration files. Instead, configuration is done using command line parameters and sending commands by using the `fw` tool.


For the `tezedge-firewall` the following command line parameters are available:

`-b, --blacklist <blacklist>...` 


The IP that you want to blacklist. It can be used multiple times, for example 

```
tezedge-firewall -b 8.8.8.8 -b 192.168.0.100 -b 172.20.0.14
```

The firewall will block those IPs from accessing the node.

`-d, --device <device>`

The interface name to attach to the firewall. The default is `enp4s0`. In docker, use `eth0`.

`-s, --socket <socket>`

The path where it should create a socket. The default is `/tmp/tezedge_firewall.sock`.

`-t, --target <target>`

The required complexity of the proof of work. The default is 26.0.

The `fw` util can execute these commands: 

`fw node <port>` - firewall will filter incoming traffic on the specified port.

`fw block <ip>` - blocks the IP.

`fw unblock <ip>` - unblocks the IP.

Also, the socket path can be specified with the `-s` parameter:

```
fw -s /path/to/socket block <ip>
```

Running `tezedge-firewall -h` or `fw -h` will print a brief help message.

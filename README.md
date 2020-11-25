# Tezos Firewall

Run `./prepare_dependencies.sh` after clone to clone and patch foreign repositories.

Build `cargo build`.

Run the firewall `sudo ./target/debug/firewall --device <interface name> -b <ip to block> -b <another ip to block>`.

For example `sudo ./target/debug/firewall --device enp4s0 -b 51.15.220.7 -b 95.217.203.43`.

Listening external command from socket. For now each 4 bytes read from the socket interpreted as ipv4 to block.
Default socket path is `/tmp/tezedge_firewall.sock`, can be redefined by `--socket=new/path.sock`.

## Whitelist

The whitelist is supported. It disable proof of work checking. Option `-w <socket address>` adds the address in the whitelist.
Also, wildcard supported, `-w 0.0.0.0:80` whitelist port 80 at any IP, and `-w x.x.x.x:0` whitelist any port on given ip.

# Docker

Build docker image for specified kernel.

```
docker build -t bpf-firewall-$(uname -r) --build-arg kernel_version=$(uname -r) .
```

Run docker container, it should be privileged.
```
docker run --privileged -d bpf-firewall-$(uname -r)
```

## Docker-compose

Docker-compose used for testing the whole flow.

Build, should set `KERNEL_VERSION` variable.
```
KERNEL_VERSION=$(uname -r) docker-compose build
```

Run is simple
```
docker-compose up
```

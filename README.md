# Tezos Firewall

Run `./prepare_dependencies.sh` after clone to clone and patch foreign repositories.

Build `cargo build`.

Run the firewall `sudo ./target/debug/firewall --device <interface name> -b <ip to block> -b <another ip to block>`.

For example `sudo ./target/debug/firewall --device enp4s0 -b 51.15.220.7 -b 95.217.203.43`.

Listening external command from socket. For now each 4 bytes read from the socket interpreted as ipv4 to block.
Default socket path is `/tmp/tezedge_firewall.sock`, can be redefined by `--socket=new/path.sock`

# Docker

Build docker image for specified kernel.

```
docker build -t bpf-firewall-$(uname -r) --build-arg kernel_version=$(uname -r) .
```

Run docker container, it should be privileged.
```
docker run --privileged -d bpf-firewall-$(uname -r)
```


Build docker-compose, should set `KERNEL_VERSION` variable.
```
KERNEL_VERSION=$(uname -r) docker-compose build
```

Run docker-compose is simple
```
docker-compose up
```

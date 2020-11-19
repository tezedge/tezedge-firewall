#!/usr/bin/env bash

interface=tft
bridge=br0

function cleanup {
    sudo ip tuntap del mode tap $interface
    sudo ip link del $bridge type bridge
}

sudo ip link add $bridge type bridge
sudo ip tuntap add mode tap $interface
sudo ip link set $interface master $bridge
sudo ip link set enp4s0 master $bridge

sudo ip addr add "192.168.1.1/24" dev $interface
sudo ip link set $interface up

sleep .1
cargo run -p packet-generator -- --address="192.168.1.1:9732" &
pid=$!
exit_code=$?
if [[ $exit_code -ne 0 ]]; then
    cleanup
    exit $exit_code
fi
trap "kill $pid" INT TERM

wait $pid
cleanup

#!/usr/bin/env bash

interface=tft

sudo ip tuntap add mode tap $interface
sudo ip addr add "192.168.1.1/24" dev $interface
sleep .1
cargo run -p packet-generator -- --address="192.168.1.1:9732" &
pid=$!
exit_code=$?
if [[ $exit_code -ne 0 ]]; then
    sudo ip tuntap del mode tap $interface
    exit $exit_code
fi
trap "kill $pid; sudo ip tuntap del mode tap $interface" INT TERM


sudo ip link set $interface up

wait $pid
sudo ip tuntap del mode tap $interface

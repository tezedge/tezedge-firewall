#!/usr/bin/env bash

if [ ! -f firewall-$(uname -r) ]; then
    ./bin/firewall-5.8.18 $@ &
else
    ./bin/firewall-$(uname -r) $@ &
fi
sleep 1
./bin/fw node 9732
sleep inf

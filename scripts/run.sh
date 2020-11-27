#!/usr/bin/env bash

if [ ! -f firewall-$(uname -r) ]; then
    ./firewall-5.8.18 $@ &
else
    ./firewall-$(uname -r) $@ &
fi
sleep 1
./fw node 9732
sleep inf

#!/usr/bin/env bash

echo "should fail, because of bad proof of work"
./bin/packet-generator --address=firewall:9732 --identity=tezedge-firewall/identity_bad.json

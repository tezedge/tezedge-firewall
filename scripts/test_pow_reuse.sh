#!/usr/bin/env bash

echo "should be ok"
./target/debug/packet-generator --address=firewall:9732 --identity=identity_good.json
echo "should fail, because of proof of work reuse"
./target/debug/packet-generator --address=firewall:9732 --identity=identity_good.json

#!/usr/bin/env bash

echo "should be ok"
./bin/packet-generator --address=firewall:9732 --identity=tests/identity_good.json
echo "should fail, because of proof of work reuse"
./bin/packet-generator --address=firewall:9732 --identity=tests/identity_good.json

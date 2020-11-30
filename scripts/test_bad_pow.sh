#!/usr/bin/env bash

echo "should fail, because of bad proof of work"
./target/debug/packet-generator --address=firewall:9732 --identity=identity_bad.json

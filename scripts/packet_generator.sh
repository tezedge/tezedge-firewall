#!/usr/bin/env bash

while ! nc -z $1 $2; do sleep 0.5; done

./target/debug/packet-generator --address "$1:$2" --identity "identity_good.json"

while ./target/debug/packet-generator --address "$1:$2" --identity "identity_bad.json"
do sleep 0.5
done

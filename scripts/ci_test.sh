#!/usr/bin/env bash

OUTPUT=$($BINARIES/packet-generator --address=$1 --identity=$IDENTITIES/identity_bad.json | tail -n1)
echo "$OUTPUT"
[ "$OUTPUT" == "The client cannot connect to the remote node" ]

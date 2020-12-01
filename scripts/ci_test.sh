#!/usr/bin/env bash

[ "./packet-generator --address=$1 --identity=$IDENTITIES/identity_bad.json | tail -n1" != "The client cannot connect to the remote node" ]

#!/usr/bin/env bash

sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' target/debug/firewall

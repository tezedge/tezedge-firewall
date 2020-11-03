#!/usr/bin/env bash

git clone https://github.com/redsift/redbpf
pushd redbpf
git reset --hard 5512c476d0e52f0bcb42761a18caad42af1b4d66
git apply ../redbpf.patch
git submodule sync
git submodule update --init
popd

git clone https://github.com/RustCrypto/hashes
pushd hashes
git reset --hard bb71874240a8e9f381aa84116168795cedd33357
git apply ../hashes.patch
popd

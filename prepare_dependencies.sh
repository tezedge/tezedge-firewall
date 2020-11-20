#!/usr/bin/env bash

git clone https://github.com/redsift/redbpf
pushd redbpf
git reset --hard 5512c476d0e52f0bcb42761a18caad42af1b4d66
git apply ../redbpf.patch
git submodule sync
git submodule update --init
popd
git apply self.patch

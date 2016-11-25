#!/bin/bash
set -x
set -e

sudo docker build -t alban/ebpf-kernel-builder -f Dockerfile.kernel-fedora-builder .

mkdir -p ebpf/

sudo docker run -v $PWD:/host/ alban/ebpf-kernel-builder /bin/sh -c 'cp -r /src/ebpf/* /host/ebpf/'
sudo chown -R $UID:$UID ebpf



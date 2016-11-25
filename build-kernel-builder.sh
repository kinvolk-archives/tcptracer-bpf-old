#!/bin/bash
set -x
set -e

sudo docker build -t kinvolk/ebpf-kernel-builder -f Dockerfile.kernel-fedora-builder .

mkdir -p ebpf/

sudo docker run -v $PWD:/host/ kinvolk/ebpf-kernel-builder /bin/sh -c 'cp -r /src/ebpf/* /host/ebpf/'
sudo chown -R $UID:$UID ebpf



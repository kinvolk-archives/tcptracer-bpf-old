#!/bin/bash
set -x
set -e

mkdir -p ebpf/

for DISTRO in fedora arch ; do
  sudo docker build -t kinvolk/ebpf-kernel-${DISTRO}-builder -f Dockerfile.kernel-${DISTRO}-builder .
  sudo docker run -v $PWD:/host/ kinvolk/ebpf-kernel-${DISTRO}-builder /bin/sh -c 'cp -r /src/ebpf/* /host/ebpf/'
done

sudo chown -R $UID:$UID ebpf



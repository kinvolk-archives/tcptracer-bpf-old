#!/bin/bash
set -x
set -e

mkdir -p ebpf/

#for DISTRO in fedora ; do
#  sudo docker build -t kinvolk/ebpf-kernel-${DISTRO}-builder -f Dockerfile.kernel-${DISTRO}-builder .
#  sudo docker run -v $PWD:/host/ kinvolk/ebpf-kernel-${DISTRO}-builder /bin/sh -c 'cp -r /src/ebpf/* /host/ebpf/'
#done

df -h

# CoreOS
GROUP=alpha
COREOS_RELEASE_BOARD=amd64-usr
COREOS_RELEASE_VERSION=1248.0.0
url="http://${GROUP:-stable}.release.core-os.net/$COREOS_RELEASE_BOARD/$COREOS_RELEASE_VERSION/coreos_developer_container.bin.bz2"
#gpg2 --recv-keys 48F9B96A2E16137F
curl -L "$url" | bzip2 -d > coreos_developer_container.bin

# "fdisk -l coreos_developer_container.bin" says the partition starts at sector 4096
sudo mount -o ro,loop,offset=$((4096*512)) coreos_developer_container.bin /mnt/
# Files now available on /mnt/lib/modules/4.8.11-coreos-r1/

# in /home/alban/tmp/lib-modules/4.8.11-coreos-r1
# sudo cp -rl source/* kernel/
# sudo cp -rl build/* kernel/

# KERNEL_HEADERS=/home/alban/tmp/lib-modules/4.8.11-coreos-r1/kernel/ KERNEL_VERSION=4.8.11-coreos-r1 ./build-ebpf.sh ./trace_output_kern.c dist/


sudo chown -R $UID:$UID ebpf

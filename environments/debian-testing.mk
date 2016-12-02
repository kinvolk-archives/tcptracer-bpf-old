include build.mk

DISTRO=debian-testing

KERNEL_VERSION=4.8.0-1-amd64
KERNEL_HEADERS=/usr/src/linux-headers-$(KERNEL_VERSION)

build: build-docker-image build-ebpf-object

include build.mk

DISTRO=arch

KERNEL_VERSION=4.8.11-1-ARCH
KERNEL_HEADERS=/usr/lib/modules/$(KERNEL_VERSION)

build: build-docker-image build-ebpf-object

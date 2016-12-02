include build.mk

DISTRO=fedora-24

build: build-docker-image build-ebpf-object

linux-version:
	@dnf list kernel-devel | awk '/^kernel-devel\..*/{print $$2}'

linux-headers:
	@dnf list kernel-devel | awk '/^kernel-devel\..*/{print "/usr/src/kernels/"$$2".x86_64"}'

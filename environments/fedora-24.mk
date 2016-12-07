include build.mk

DISTRO=fedora-24

build: build-docker-image build-ebpf-object delete-docker-image

linux-version:
	@dnf list kernel-devel | awk '/^kernel-devel\..*/{print $$2".x86_64"}'

linux-headers:
	@dnf list kernel-devel | awk '/^kernel-devel\..*/{print "/usr/src/kernels/"$$2".x86_64"}'

distro-id:
	@grep ^ID= /etc/os-release  | awk -F= '{print $$2}'

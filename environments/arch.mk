include build.mk

DISTRO=arch

build: build-docker-image build-ebpf-object

linux-version:
	@pacman -Q linux-headers | awk '{print $$2"-ARCH"}'

linux-headers:
	@pacman -Q linux-headers | awk '{print "/usr/lib/modules/"$$2"-ARCH/build"}'

distro-id:
	@grep ^ID= /usr/lib/os-release  | awk -F= '{print $$2}'

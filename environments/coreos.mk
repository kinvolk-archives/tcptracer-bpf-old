include build.mk

DISTRO=coreos

DOCKER_FILE=Dockerfile.kernel-debian-testing-builder

DIR:=$(shell mktemp -d /tmp/tcptracer-bpf-coreos-XXXXXXXX)

RELEASE?=current
RELEASE_CHANNEL?=alpha

build: fetch-image mount-image extract-header umount-image build-docker-image build-ebpf-object cleanup

fetch-image:
	@echo $(DIR)
	@curl -L https://$(RELEASE_CHANNEL).release.core-os.net/amd64-usr/$(RELEASE)/coreos_developer_container.bin.bz2 | bzip2 -d > $(DIR)/coreos_developer_container.bin

# "fdisk -l coreos_developer_container.bin" says the partition starts at sector 4096
mount-image:
	@mkdir -p $(DIR)/mnt
	@sudo mount -o ro,loop,offset=$$((4096*512)) $(DIR)/coreos_developer_container.bin $(DIR)/mnt

extract-header: HEADER_DIRS=$(wildcard $(DIR)/mnt/lib/modules/*/build/*)
extract-header: HEADER_DIRS+=$(wildcard $(DIR)/mnt/lib/modules/*/source/*)
extract-header:
	@mkdir -p kernel/
	@cp -nr $(HEADER_DIRS) kernel/
	@echo $(shell basename $(DIR)/mnt/lib/modules/*) > kernel/version

umount-image:
	@sudo umount $(DIR)/mnt

linux-version:
	@cat /src/kernel/version

linux-headers:
	@echo /src/kernel

distro-id:
	@echo coreos

cleanup:
	@rm -rf kernel/
	@rm -rf "$(DIR)"

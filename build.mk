UID=$(shell id -u)
PWD=$(shell pwd)

build-docker-image:
	sudo docker build -t kinvolk/ebpf-kernel-$(DISTRO)-builder -f Dockerfile.kernel-$(DISTRO)-builder .

build-ebpf-object:
	sudo docker run --rm -e DEBUG=$(DEBUG) \
		-e DISTRO=$(DISTRO) \
		-v $(PWD):/src:ro \
		-v $(PWD)/ebpf/$(DISTRO):/dist/ kinvolk/ebpf-kernel-$(DISTRO)-builder \
		make -f ebpf.mk build
	sudo chown -R $(UID):$(UID) ebpf

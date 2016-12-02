UID=$(shell id -u)
PWD=$(shell pwd)

build-docker-image:
	sudo docker build -t kinvolk/ebpf-kernel-$(DISTRO)-builder -f Dockerfile.kernel-$(DISTRO)-builder .

build-ebpf-object:
	sudo docker run --rm -e DEBUG=$(DEBUG) \
		-e KERNEL_VERSION=$(KERNEL_VERSION) \
		-e KERNEL_HEADERS=$(KERNEL_HEADERS) \
		-v $(PWD):/src:ro \
		-v $(PWD)/ebpf/$(DISTRO):/dist/ kinvolk/ebpf-kernel-$(DISTRO)-builder \
		./build-ebpf.sh trace_output_kern.c /dist "$(KERNEL_VERSION)"
	sudo chown -R $(UID):$(UID) ebpf

DEBUG=1
UID=$(shell id -u)
PWD=$(shell pwd)

DOCKER_FILE?=Dockerfile
DOCKER_IMAGE?=kinvolk/tcptracer-bpf-builder

all: build-docker-image build-ebpf-object

build-docker-image:
	sudo docker build -t $(DOCKER_IMAGE) -f $(DOCKER_FILE) .

build-ebpf-object:
	sudo docker run --rm -e DEBUG=$(DEBUG) \
		-v $(PWD):/src:ro \
		-v $(PWD)/ebpf:/dist/ $(DOCKER_IMAGE) \
		make -f ebpf.mk build
	sudo chown -R $(UID):$(UID) ebpf

delete-docker-image:
	sudo docker rmi -f $(DOCKER_IMAGE)

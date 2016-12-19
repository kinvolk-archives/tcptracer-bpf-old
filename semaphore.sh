#!/bin/bash
set -xe

make fedora-24

RKT_IMAGE=quay.io/alban/rkt:ebpf
docker pull ${RKT_IMAGE}
CONTAINER_ID=$(docker run -d ${RKT_IMAGE} /bin/false 2>/dev/null || true)
docker export -o rkt.tgz ${CONTAINER_ID}
mkdir -p rkt
tar xvf rkt.tgz -C rkt/

sudo ./rkt/rkt \
	run --interactive \
	--insecure-options=image,all-run \
	--dns=8.8.8.8 \
	--stage1-path=./rkt/stage1-kvm.aci \
	--volume=ebpf,kind=host,source=$PWD \
	docker://debian \
	--mount=volume=ebpf,target=/ebpf \
	--exec=/bin/sh -- -c \
	'cd /ebpf ; \
		mount -t tmpfs tmpfs /tmp ; \
		mount -t debugfs debugfs /sys/kernel/debug/ ; \
		ls -l ; find'

exit 0


./tools/export-elfs-into-container

# Semaphore variables:
# https://semaphoreci.com/docs/available-environment-variables.html

if [ "$CI" != "true" ] ; then
  exit 0
fi
if [ "$SEMAPHORE" != "true" ] ; then
  exit 0
fi

if [ "$BRANCH_NAME" == "master" ] ; then
  test -z "${DOCKER_USER}" || (
    docker tag kinvolk/tcptracer-bpf:latest ${DOCKER_ORGANIZATION:-$DOCKER_USER}/tcptracer-bpf:semaphore-latest &&
    docker tag kinvolk/tcptracer-bpf:latest ${DOCKER_ORGANIZATION:-$DOCKER_USER}/tcptracer-bpf:semaphore-$(./tools/image-tag) &&
    docker push ${DOCKER_ORGANIZATION:-$DOCKER_USER}/tcptracer-bpf:semaphore-latest &&
    docker push ${DOCKER_ORGANIZATION:-$DOCKER_USER}/tcptracer-bpf:semaphore-$(./tools/image-tag)
  )
else
  test -z "${DEPLOY_BRANCH}" || test -z "${DOCKER_USER}" || (
    docker tag kinvolk/tcptracer-bpf:latest ${DOCKER_ORGANIZATION:-$DOCKER_USER}/tcptracer-bpf:semaphore-${BRANCH_NAME//\//-} &&
    docker push ${DOCKER_ORGANIZATION:-$DOCKER_USER}/tcptracer-bpf:semaphore-${BRANCH_NAME//\//-}
  )
fi


#!/bin/bash
set -xe

make fedora-24
make arch
make debian-testing

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
    docker login -e $DOCKER_EMAIL -u $DOCKER_USER -p $DOCKER_PASS &&
    docker tag kinvolk/tcptracer-bpf:latest ${DOCKER_ORGANIZATION:-$DOCKER_USER}/tcptracer-bpf:semaphore-latest &&
    docker tag kinvolk/tcptracer-bpf:$(./tools/image-tag) ${DOCKER_ORGANIZATION:-$DOCKER_USER}/tcptracer-bpf:semaphore-$(./tools/image-tag) &&
    docker push ${DOCKER_ORGANIZATION:-$DOCKER_USER}/tcptracer-bpf:semaphore-latest &&
    docker push ${DOCKER_ORGANIZATION:-$DOCKER_USER}/tcptracer-bpf:semaphore-$(./tools/image-tag)
  )
else
  test -z "${DEPLOY_BRANCH}" || test -z "${DOCKER_USER}" || (
    docker login -e $DOCKER_EMAIL -u $DOCKER_USER -p $DOCKER_PASS &&
    docker tag kinvolk/tcptracer-bpf:latest ${DOCKER_ORGANIZATION:-$DOCKER_USER}/tcptracer-bpf:semaphore-${BRANCH_NAME//\//-} &&
    docker push ${DOCKER_ORGANIZATION:-$DOCKER_USER}/tcptracer-bpf:semaphore-${BRANCH_NAME//\//-}
  )
fi


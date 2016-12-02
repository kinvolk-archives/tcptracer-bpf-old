#!/bin/bash
set -x
set -e

sudo docker build -t kinvolk/ebpf-user-builder -f Dockerfile.user-builder .
sudo docker run --rm -e DEBUG=${DEBUG:-} \
  -v ${PWD}:/src:ro \
  -v ${PWD}:/dist/ kinvolk/ebpf-user-builder \
  gcc -Wall -Wno-unused-variable -o /dist/trace_output_user trace_output_user.c bpf_load.c libbpf.c -lelf

sudo chown $UID:$UID trace_output_user

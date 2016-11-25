#!/bin/bash
set -x
set -e

sudo docker build -t kinvolk/ebpf-user-builder -f Dockerfile.user-builder .
sudo docker run -v $PWD:/host/ kinvolk/ebpf-user-builder cp /src/trace_output_user /host/trace_output_user
sudo chown $UID:$UID trace_output_user



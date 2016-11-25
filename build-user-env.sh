#!/bin/bash
set -x
set -e

sudo docker build -t alban/ebpf-user-env -f Dockerfile.user-env .



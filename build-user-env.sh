#!/bin/bash
set -x
set -e

sudo docker build -t kinvolk/ebpf-kprobe-example -f Dockerfile.user-env .



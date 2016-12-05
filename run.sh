#!/bin/sh
test -n "$DEBUG" && set -x
if [ $# -lt 1 ]; then
  echo "Usage: $0 <path/ebpf.o>" >&2
  exit 1
fi
sudo docker run --rm -e DEBUG=${DEBUG:-} -ti \
  --privileged --net=host --pid=host \
  -v /sys/kernel/debug:/sys/kernel/debug \
  kinvolk/tcptracer-bpf "$@"

#!/bin/bash
sudo docker run --rm -it \
	--privileged --net=host --pid=host \
	-v /sys/kernel/debug:/sys/kernel/debug \
	-ti \
	kinvolk/ebpf-kprobe-example

#!/bin/bash
sudo docker run --rm -it \
	--privileged --net=host --pid=host \
	-v /sys/kernel/debug:/sys/kernel/debug \
	-v $PWD:/mnt \
	alban/ebpf-user-env /bin/sh -c 'cd /mnt && ./trace_output_user ebpf/x86_64/4.8.8-200.fc24.x86_64/ebpf.o'

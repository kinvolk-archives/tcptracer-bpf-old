#!/bin/bash
sudo docker run --rm -it \
	--privileged --net=host --pid=host \
	-v /sys/kernel/debug:/sys/kernel/debug \
	-v $PWD:/mnt \
	alban/ebpf-user-env /bin/sh -c 'cd /mnt && ./trace_output_user'

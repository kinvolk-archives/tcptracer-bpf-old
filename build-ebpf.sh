#!/bin/sh

KERNEL_VERSION="4.8.8-200.fc24.x86_64"

ls -l /usr/src/kernels/

KERNEL_HEADERS=/usr/src/kernels/${KERNEL_VERSION}
ARCH=$(uname -i)
DEST=ebpf/${ARCH}/${KERNEL_VERSION}
mkdir -p $DEST

echo "KERNEL_HEADERS=$KERNEL_HEADERS"
echo "DEST=$DEST"

clang -D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types \
		-O2 -emit-llvm -c trace_output_kern.c \
		-I ${KERNEL_HEADERS}/arch/x86/include \
		-I ${KERNEL_HEADERS}/arch/x86/include/generated \
		-I ${KERNEL_HEADERS}/include \
		-o - | llc -march=bpf -filetype=obj -o ${DEST}/ebpf.o

pwd
find ebpf/

#!/bin/bash

test -n "$DEBUG" && set -x
set -eu

if [ $# -lt 2 ]; then
  echo "Usage: %s <ebpf.c file> <destdir> [<kernel version>]" >&2
  exit 1
fi

ARCH="$(uname -i)"
SOURCE_FILE="$1"
DEST_DIR="${2}/${ARCH}/${KERNEL_VERSION}"

mkdir -p "${DEST_DIR}"

clang -D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types \
    -O2 -emit-llvm -c "${SOURCE_FILE}" \
		-I "${KERNEL_HEADERS}/arch/x86/include" \
		-I "${KERNEL_HEADERS}/arch/x86/include/generated" \
		-I "${KERNEL_HEADERS}/include" \
    -I ${KERNEL_HEADERS/amd64/common}/arch/x86/include \
    -I ${KERNEL_HEADERS/amd64/common}/include \
		-o - | llc -march=bpf -filetype=obj -o "${DEST_DIR}/ebpf.o"

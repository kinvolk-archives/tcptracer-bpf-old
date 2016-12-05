This is an experiment under development on how to build ebpf.o files (ready to
use object files of eBPF programs) for different distributions and kernel
versions.

Goal is to be able to load compiled ebpf object files without dependencies on
kernel headers in production, so [bcc](https://github.com/iovsior/bcc) cannot
be used in this case.

## Usage

```
make <environment> # build an environment, e.g.
make fedora-24

make trace-output-user # build trace-output-user

make user-env # build a container with all ebpf.o files found in ebpf/
              # and trace_output_user entrypoint

./run.sh /ebpf/debian-testing/x86_64/4.8.0-1-amd64/ebpf.o # test ebpf.o
```

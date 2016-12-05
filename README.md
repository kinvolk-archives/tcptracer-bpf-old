This is an experiment under development to build eBPF tcptracer objects
for different distributions and kernel versions.

Goal is to be able to load the compiled ebpf object files without dependencies
on kernel headers in production, so [bcc](https://github.com/iovisor/bcc)
cannot be used in this case.

The generated object files can be used and tested with the
[gobpf-elf-loader](https://github.com/kinvolk/gobpf-elf-loader).

## Usage

```
make <environment> # build an environment, e.g.
make fedora-24
```

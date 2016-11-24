#include <linux/kconfig.h>

#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"

#include <net/sock.h>

struct bpf_map_def SEC("maps") my_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 2,
};

SEC("kprobe/tcp_v4_connect")
int bpf_prog1(struct pt_regs *ctx)
{
	struct sock *sk;
	struct S {
		__u64 pid;
		__u32 netns;
		__u16 dport;
		__u16 sport;
	} data = {0,};
	u16 dport = 0;
	char called_msg[] = "kprobe/tcp_v4_connect called\n";

	bpf_trace_printk(called_msg, sizeof(called_msg));

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

	data.pid = bpf_get_current_pid_tgid();
	data.dport = dport;


	bpf_perf_event_output(ctx, &my_map, 0, &data, sizeof(data));

	return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;

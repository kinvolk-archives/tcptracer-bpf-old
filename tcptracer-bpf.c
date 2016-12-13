#include <linux/kconfig.h>

#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"

#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>

#define TCP_EVENT_TYPE_CONNECT 1
#define TCP_EVENT_TYPE_ACCEPT  2
#define TCP_EVENT_TYPE_CLOSE   3

struct tcp_event_v4_t {
	/* timestamp must be the first field, the sorting depends on it */
	u64 timestamp;
	u64 cpu;
	u32 ev_type;
	u32 pid;
	char comm[TASK_COMM_LEN];
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u32 netns;
};

struct bpf_map_def SEC("maps/tcp_event_v4") tcp_event_v4 = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 16,
};

struct bpf_map_def SEC("maps/connectsock_v4") connectsock_v4 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(void *),
	.max_entries = 128,
};

#define TCPTRACER_STATUS_UNINITIALIZED 0
#define TCPTRACER_STATUS_CHECKING      1
#define TCPTRACER_STATUS_CHECKED       2
#define TCPTRACER_STATUS_READY         3
struct tcptracer_status_t {
	u64 status;

	/* checking */
	u64 pid_tgid;
	u64 what;
	u64 offset_saddr;
	u64 offset_daddr;
	u64 offset_sport;
	u64 offset_dport;
	u64 offset_netns;

	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u32 netns;
};

struct bpf_map_def SEC("maps/tcptracer_status") tcptracer_status = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct tcptracer_status_t),
	.max_entries = 128,
};

SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	struct sock *sk;
	u64 pid = bpf_get_current_pid_tgid();
	u64 zero = 0;
	struct tcptracer_status_t *status;

	if (status->status == TCPTRACER_STATUS_UNINITIALIZED) {
		return 0;
	}

	char called_msg[] = "kprobe/tcp_v4_connect called\n";
	bpf_trace_printk(called_msg, sizeof(called_msg));

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&connectsock_v4, &pid, &sk, BPF_ANY);

	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();
	struct sock **skpp;
	u64 zero = 0;
	struct tcptracer_status_t *status;

	skpp = bpf_map_lookup_elem(&connectsock_v4, &pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}
	bpf_map_delete_elem(&connectsock_v4, &pid);

	struct sock *skp = *skpp;

	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		return 0;
	}

	status = bpf_map_lookup_elem(&tcptracer_status, &zero);
	if (status == NULL || status->status == TCPTRACER_STATUS_UNINITIALIZED) {
		return 0;
	}

	switch (status->status) {
		case TCPTRACER_STATUS_UNINITIALIZED:
			return 0;
		case TCPTRACER_STATUS_CHECKING:
			if (status->pid_tgid != pid)
				return 0;

			struct tcptracer_status_t updated_status = {
			    .status = TCPTRACER_STATUS_CHECKED,
			    .pid_tgid = status->pid_tgid,
			    .what = status->what,
			    .offset_saddr = status->offset_saddr,
			    .offset_daddr = status->offset_daddr,
			    .offset_sport = status->offset_sport,
			    .offset_dport = status->offset_dport,
			    .offset_netns = status->offset_netns,
			    .saddr = status->saddr,
			    .daddr = status->daddr,
			    .sport = status->sport,
			    .dport = status->dport,
			    .netns = status->netns,
			};

			switch (status->what) {
				u32 possible_saddr = 0;
				u32 possible_daddr = 0;
				u16 possible_sport = 0;
				u16 possible_dport = 0;
				possible_net_t possible_skc_net;
				u32 possible_netns = 0;
				case 0:
					bpf_probe_read(&possible_saddr, sizeof(possible_saddr), ((char *)skp) + status->offset_saddr);
					updated_status.saddr = possible_saddr;
					break;
				case 1:
					bpf_probe_read(&possible_daddr, sizeof(possible_daddr), ((char *)skp) + status->offset_daddr);
					updated_status.daddr = possible_daddr;
					break;
				case 2:
					bpf_probe_read(&possible_sport, sizeof(possible_sport), ((char *)skp) + status->offset_sport);
					updated_status.sport = possible_sport;
					break;
				case 3:
					bpf_probe_read(&possible_dport, sizeof(possible_dport), ((char *)skp) + status->offset_dport);
					updated_status.dport = possible_dport;
					break;
				case 4:
					bpf_probe_read(&possible_skc_net, sizeof(possible_skc_net), ((char *)skp) + status->offset_netns);
					// TODO offset here
					bpf_probe_read(&possible_netns, sizeof(possible_netns), &possible_skc_net.net->ns.inum);
					updated_status.netns = possible_netns;
					break;
			}
			bpf_map_update_elem(&tcptracer_status, &zero, &updated_status, BPF_ANY);

			return 0;
		case TCPTRACER_STATUS_CHECKED:
			return 0;
		case TCPTRACER_STATUS_READY:
			// continue
			break;
		default:
			return 0;
	}

	// pull in details
	struct ns_common *ns;
	u32 saddr = 0, daddr = 0, net_ns_inum = 0;
	u16 sport = 0, dport = 0;
	bpf_probe_read(&sport, sizeof(sport), ((char *)skp) + status->offset_sport);
	bpf_probe_read(&saddr, sizeof(saddr), ((char *)skp) + status->offset_saddr);
	bpf_probe_read(&daddr, sizeof(daddr), ((char *)skp) + status->offset_daddr);
	bpf_probe_read(&dport, sizeof(dport), ((char *)skp) + status->offset_dport);

	// Get network namespace id
	possible_net_t skc_net;
	bpf_probe_read(&skc_net, sizeof(skc_net), ((char *)skp) + status->offset_netns);
	// TODO offset here
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), &skc_net.net->ns.inum);

	// output
	struct tcp_event_v4_t evt = {
		.timestamp = bpf_ktime_get_ns(),
		.cpu = bpf_get_smp_processor_id(),
		.ev_type = TCP_EVENT_TYPE_CONNECT,
		.pid = pid >> 32,
		.saddr = saddr,
		.daddr = daddr,
		.sport = ntohs(sport),
		.dport = ntohs(dport),
		.netns = net_ns_inum,
	};

	bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

	// do not send event if IP address is 0.0.0.0 or port is 0
	if (evt.saddr != 0 && evt.daddr != 0 && evt.sport != 0 && evt.dport != 0) {
		bpf_perf_event_output(ctx, &tcp_event_v4, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	}

	return 0;
}

SEC("kprobe/tcp_close")
int kprobe__tcp_close(struct pt_regs *ctx)
{
	struct sock *sk;
	struct tcptracer_status_t *status;
	u64 zero = 0;
	u64 pid = bpf_get_current_pid_tgid();

	sk = (struct sock *) PT_REGS_PARM1(ctx);

	status = bpf_map_lookup_elem(&tcptracer_status, &zero);
	if (status == NULL || status->status == TCPTRACER_STATUS_UNINITIALIZED) {
		return 0;
	}

	u32 net_ns_inum = 0;
	u16 family = 0, sport = 0, dport = 0;

	bpf_probe_read(&sport, sizeof(sport), ((char *)sk) + status->offset_sport);
	bpf_probe_read(&dport, sizeof(dport), ((char *)sk) + status->offset_dport);

	// TODO get family
	family = 2;

	// Get network namespace id
	possible_net_t skc_net;
	bpf_probe_read(&skc_net, sizeof(skc_net), ((char *)sk) + status->offset_netns);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), &skc_net.net->ns.inum);

	if (family == AF_INET) {
		u32 saddr = 0, daddr = 0;
		bpf_probe_read(&saddr, sizeof(saddr), ((char *)sk) + status->offset_saddr);
		bpf_probe_read(&daddr, sizeof(daddr), ((char *)sk) + status->offset_daddr);
		// output
		struct tcp_event_v4_t evt = {
			.timestamp = bpf_ktime_get_ns(),
			.cpu = bpf_get_smp_processor_id(),
			.ev_type = TCP_EVENT_TYPE_CLOSE,
			.pid = pid >> 32,
			.saddr = saddr,
			.daddr = daddr,
			.sport = ntohs(sport),
			.dport = ntohs(dport),
			.netns = net_ns_inum,
		};
		bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
		// do not send event if IP address is 0.0.0.0 or port is 0
		if (evt.saddr != 0 && evt.daddr != 0 && evt.sport != 0 && evt.dport != 0) {
			bpf_perf_event_output(ctx, &tcp_event_v4, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
		}
	} // else drop

	return 0;
}

SEC("kretprobe/inet_csk_accept")
int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
	struct tcptracer_status_t *status;
	u64 zero = 0;
	struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();

	if (newsk == NULL)
		return 0;

	status = bpf_map_lookup_elem(&tcptracer_status, &zero);
	if (status == NULL || status->status == TCPTRACER_STATUS_UNINITIALIZED) {
		return 0;
	}

	// TODO get protocol
	// check this is TCP
	u8 protocol = 0;
	// workaround for reading the sk_protocol bitfield:
	bpf_probe_read(&protocol, 1, (void *)((long)&newsk->sk_wmem_queued) - 3);
	if (protocol != IPPROTO_TCP)
		return 0;

	// pull in details
	u16 family = 0, lport = 0, dport = 0;
	u32 net_ns_inum = 0;
	bpf_probe_read(&family, sizeof(family), &newsk->__sk_common.skc_family);
	// TODO get skc_num
	bpf_probe_read(&lport, sizeof(lport), &newsk->__sk_common.skc_num);
	bpf_probe_read(&dport, sizeof(dport), &newsk->__sk_common.skc_dport);
// Get network namespace id, if kernel supports it
#ifdef CONFIG_NET_NS
	possible_net_t skc_net;
	bpf_probe_read(&skc_net, sizeof(skc_net), &newsk->__sk_common.skc_net);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), &skc_net.net->ns.inum);
#else
	net_ns_inum = 0;
#endif
	if (family == AF_INET) {
		struct tcp_event_v4_t evt = {
			.timestamp = bpf_ktime_get_ns(),
			.cpu = bpf_get_smp_processor_id(),
			.ev_type = TCP_EVENT_TYPE_ACCEPT,
			.netns = net_ns_inum,
		};
		evt.pid = pid >> 32;
		bpf_probe_read(&evt.saddr, sizeof(u32),
			&newsk->__sk_common.skc_rcv_saddr);
		bpf_probe_read(&evt.daddr, sizeof(u32),
			&newsk->__sk_common.skc_daddr);
			evt.sport = lport;
		evt.dport = ntohs(dport);
		bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
		// do not send event if IP address is 0.0.0.0 or port is 0
		if (evt.saddr != 0 && evt.daddr != 0 && evt.sport != 0 && evt.dport != 0) {
			bpf_perf_event_output(ctx, &tcp_event_v4, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
		}
	} // else drop

	return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 264205;

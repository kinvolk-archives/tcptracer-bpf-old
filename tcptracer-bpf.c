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

struct tcp_ipv4_event_t {
	/* timestamp must be the first field, the sorting depends on it */
	u64 timestamp;
	u64 cpu;
	u32 type;
	u32 pid;
	char comm[TASK_COMM_LEN];
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u32 netns;
};

struct tcp_ipv6_event_t {
	/* timestamp must be the first field, the sorting depends on it */
	u64 timestamp;
	u64 cpu;
	u32 type;
	u32 pid;
	char comm[TASK_COMM_LEN];
	/* Using the type unsigned __int128 generates an error in the ebpf verifier */
	u64 saddr_h;
	u64 saddr_l;
	u64 daddr_h;
	u64 daddr_l;
	u16 sport;
	u16 dport;
	u32 netns;
};

// tcp_set_state doesn't run in the context of the process that initiated the
// connection so we need to store a map TUPLE -> PID to send the right PID on
// the event
struct ipv4_tuple_t {
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u32 netns;
};

struct ipv6_tuple_t {
	/* Using the type unsigned __int128 generates an error in the ebpf verifier */
	u64 saddr_h;
	u64 saddr_l;
	u64 daddr_h;
	u64 daddr_l;
	u16 sport;
	u16 dport;
	u32 netns;
};

struct pid_comm {
	u64 pid;
	char comm[TASK_COMM_LEN];
};

/* This is a key/value store with the keys being the cpu number
 * and the values being a perf file descriptor.
 */
struct bpf_map_def SEC("maps/tcp_event_ipv4") tcp_event_ipv4 = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 1024,
};

/* This is a key/value store with the keys being the cpu number
 * and the values being a perf file descriptor.
 */
struct bpf_map_def SEC("maps/tcp_event_ipv6") tcp_event_ipv6 = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 1024,
};

/* This maps is used to match the kprobe & kretprobe of connect
 * it is used for both ipv4 and ipv6.
 */
struct bpf_map_def SEC("maps/connectsock") connectsock = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(void *),
	.max_entries = 1024,
};

struct bpf_map_def SEC("maps/tuplepid_ipv4") tuplepid_ipv4 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct ipv4_tuple_t),
	.value_size = sizeof(struct pid_comm),
	.max_entries = 1024,
};

struct bpf_map_def SEC("maps/tuplepid_ipv6") tuplepid_ipv6 = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct ipv6_tuple_t),
	.value_size = sizeof(struct pid_comm),
	.max_entries = 1024,
};

SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	struct sock *sk;
	u64 pid = bpf_get_current_pid_tgid();
	sk = (struct sock *) PT_REGS_PARM1(ctx);
	bpf_map_update_elem(&connectsock, &pid, &sk, BPF_ANY);

	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();
	struct sock **skpp;
	skpp = bpf_map_lookup_elem(&connectsock, &pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	bpf_map_delete_elem(&connectsock, &pid);

	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		return 0;
	}

	// pull in details
	struct sock *skp = *skpp;
	struct ns_common *ns;
	u32 saddr = 0, daddr = 0, net_ns_inum = 0;
	u16 sport = 0, dport = 0;
	bpf_probe_read(&sport, sizeof(sport), &((struct inet_sock *)skp)->inet_sport);
	bpf_probe_read(&saddr, sizeof(saddr), &skp->__sk_common.skc_rcv_saddr);
	bpf_probe_read(&daddr, sizeof(daddr), &skp->__sk_common.skc_daddr);
	bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);
	// Get network namespace id
#ifdef CONFIG_NET_NS
	possible_net_t skc_net;
	bpf_probe_read(&skc_net, sizeof(skc_net), &skp->__sk_common.skc_net);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), &skc_net.net->ns.inum);
#endif
	// if addresses or ports are 0, ignore
	if (saddr == 0 || daddr == 0 || sport == 0 || dport == 0) {
		return 0;
	}
	// output
	struct ipv4_tuple_t t = {
		.saddr = saddr,
		.daddr = daddr,
		.sport = ntohs(sport),
		.dport = ntohs(dport),
		.netns = net_ns_inum,
	};

	struct pid_comm p = { .pid = pid };
	bpf_get_current_comm(p.comm, sizeof(p.comm));
	bpf_map_update_elem(&tuplepid_ipv4, &t, &p, BPF_ANY);

	return 0;
}

SEC("kprobe/tcp_v6_connect")
int kprobe__tcp_v6_connect(struct pt_regs *ctx)
{
	struct sock *sk;
	u64 pid = bpf_get_current_pid_tgid();
	sk = (struct sock *) PT_REGS_PARM1(ctx);
	bpf_map_update_elem(&connectsock, &pid, &sk, BPF_ANY);

    return 0;
}

SEC("kretprobe/tcp_v6_connect")
int kretprobe__tcp_v6_connect(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();
	struct sock **skpp;
	skpp = bpf_map_lookup_elem(&connectsock, &pid);
	if (skpp == 0) {
		return 0;	// missed entry
	}

	bpf_map_delete_elem(&connectsock, &pid);

	if (ret != 0) {
		// failed to send SYNC packet, may not have populated
		// socket __sk_common.{skc_rcv_saddr, ...}
		return 0;
	}

	// pull in details
	struct sock *skp = *skpp;
	struct ns_common *ns;
	u64 saddr_h = 0, saddr_l = 0, daddr_h = 0, daddr_l = 0;
	u32 net_ns_inum = 0;
	u16 sport = 0, dport = 0;
	bpf_probe_read(&sport, sizeof(sport), &((struct inet_sock *)skp)->inet_sport);
	bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);
	bpf_probe_read(&saddr_h, sizeof(saddr_h), &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	bpf_probe_read(&saddr_l, sizeof(saddr_l), &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[2]);
	bpf_probe_read(&daddr_h, sizeof(daddr_h), &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	bpf_probe_read(&daddr_l, sizeof(daddr_l), &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32[2]);

	// if addresses or ports are 0, ignore
	if (!(saddr_h || saddr_l) || !(daddr_h || daddr_l) || sport == 0 || dport == 0) {
		return 0;
	}

	// Get network namespace id
	possible_net_t skc_net;
	bpf_probe_read(&skc_net, sizeof(skc_net), &skp->__sk_common.skc_net);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), &skc_net.net->ns.inum);

	// output
	struct ipv6_tuple_t t = {
		.saddr_h = saddr_h,
		.saddr_l = saddr_l,
		.daddr_h = daddr_h,
		.daddr_l = daddr_l,
		.sport = ntohs(sport),
		.dport = ntohs(dport),
		.netns = net_ns_inum,
	};

	struct pid_comm p = { .pid = pid };
	bpf_get_current_comm(p.comm, sizeof(p.comm));
	bpf_map_update_elem(&tuplepid_ipv6, &t, &p, BPF_ANY);

	return 0;
}

SEC("kprobe/tcp_set_state")
int kprobe__tcp_set_state(struct pt_regs *ctx)
{
	u64 pid = bpf_get_current_pid_tgid();
	struct sock *skp;
	int state;
	skp =  (struct sock *) PT_REGS_PARM1(ctx);
	state = (int) PT_REGS_PARM2(ctx);
	if (state != TCP_ESTABLISHED) {
		return 0;
	}
	struct ns_common *ns;
	u32 net_ns_inum = 0;
	u16 sport = 0, dport = 0, family = 0;
	// Get network namespace id, if kernel supports it
#ifdef CONFIG_NET_NS
	possible_net_t skc_net;
	bpf_probe_read(&skc_net, sizeof(skc_net), &skp->__sk_common.skc_net);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), &skc_net.net->ns.inum);
#endif
	bpf_probe_read(&family, sizeof(family), &skp->__sk_common.skc_family);
	if (family == AF_INET) {
		u32 saddr = 0, daddr = 0;
		bpf_probe_read(&saddr, sizeof(saddr), &skp->__sk_common.skc_rcv_saddr);
		bpf_probe_read(&daddr, sizeof(daddr), &skp->__sk_common.skc_daddr);
		bpf_probe_read(&sport, sizeof(sport), &((struct inet_sock *)skp)->inet_sport);
		bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);
		// if addresses or ports are 0, ignore
		if (saddr == 0 || daddr == 0 || sport == 0 || dport == 0) {
			return 0;
		}
		struct ipv4_tuple_t t = {
			.saddr = saddr,
			.daddr = daddr,
			.sport = ntohs(sport),
			.dport = ntohs(dport),
			.netns = net_ns_inum,
		};
		struct pid_comm *pp;
		pp = bpf_map_lookup_elem(&tuplepid_ipv4, &t);
		if (pp == 0) {
			return 0;	// missed entry
		}
		struct pid_comm p;
		bpf_probe_read(&p, sizeof(struct pid_comm), pp);
		struct tcp_ipv4_event_t evt4 = {
			.timestamp = bpf_ktime_get_ns(),
			.cpu = bpf_get_smp_processor_id(),
			.type = TCP_EVENT_TYPE_CONNECT,
			.pid = p.pid >> 32,
			.saddr = saddr,
			.daddr = daddr,
			.sport = ntohs(sport),
			.dport = ntohs(dport),
			.netns = net_ns_inum,
		};
		int i;
		for (i = 0; i < TASK_COMM_LEN; i++) {
			evt4.comm[i] = p.comm[i];
		}
		bpf_perf_event_output(ctx, &tcp_event_ipv4, BPF_F_CURRENT_CPU, &evt4, sizeof(evt4));
		bpf_map_delete_elem(&tuplepid_ipv4, &t);
	} else if (family == AF_INET6) {
		u64 saddr_h = 0, saddr_l = 0, daddr_h = 0, daddr_l = 0;
		bpf_probe_read(&saddr_h, sizeof(saddr_h), &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read(&saddr_l, sizeof(saddr_l), &skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[2]);
		bpf_probe_read(&daddr_h, sizeof(daddr_h), &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
		bpf_probe_read(&daddr_l, sizeof(daddr_l), &skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32[2]);
		bpf_probe_read(&sport, sizeof(sport), &((struct inet_sock *)skp)->inet_sport);
		bpf_probe_read(&dport, sizeof(dport), &skp->__sk_common.skc_dport);
		// if addresses or ports are 0, ignore
		if ((saddr_h || saddr_l) == 0 || (daddr_h || daddr_l) == 0 || sport == 0 || dport == 0 ) {
			return 0;
		}
		struct ipv6_tuple_t t = {
			t.saddr_h = saddr_h,
			t.saddr_l = saddr_l,
			t.daddr_h = daddr_h,
			t.daddr_l = daddr_l,
			t.sport = ntohs(sport),
			t.dport = ntohs(dport),
			t.netns = net_ns_inum,
		};
		struct pid_comm *pp;
		pp = bpf_map_lookup_elem(&tuplepid_ipv6, &t);
		if (pp == 0) {
			return 0;       // missed entry
		}
		struct pid_comm p;
		bpf_probe_read(&p, sizeof(struct pid_comm), pp);
		struct tcp_ipv6_event_t evt6 = {
			.timestamp = bpf_ktime_get_ns(),
			.cpu = bpf_get_smp_processor_id(),
			.type = TCP_EVENT_TYPE_CONNECT,
			.pid = p.pid >> 32,
			.saddr_h = saddr_h,
			.saddr_l = saddr_l,
			.daddr_h = daddr_h,
			.daddr_l = daddr_l,
			.sport = ntohs(sport),
			.dport = ntohs(dport),
			.netns = net_ns_inum,
		};
		int i;
		for (i = 0; i < TASK_COMM_LEN; i++) {
			evt6.comm[i] = p.comm[i];
		}
		bpf_perf_event_output(ctx, &tcp_event_ipv6, BPF_F_CURRENT_CPU, &evt6, sizeof(evt6));
		bpf_map_delete_elem(&tuplepid_ipv6, &t);
	}
	return 0;
}

SEC("kprobe/tcp_close")
int kprobe__tcp_close(struct pt_regs *ctx)
{
	struct sock *sk;
	u64 pid = bpf_get_current_pid_tgid();
	sk = (struct sock *) PT_REGS_PARM1(ctx);
	u32 net_ns_inum = 0;
	u16 family = 0, sport = 0, dport = 0;
	unsigned char oldstate;

	oldstate = 0;
	bpf_probe_read(&oldstate, sizeof(unsigned char), (unsigned char *)&sk->sk_state);
	// Don't generate close events for connections that were never
	// established in the first place.
	if (oldstate == TCP_SYN_SENT || oldstate == TCP_SYN_RECV || oldstate == TCP_NEW_SYN_RECV)
		return 0;

	// Get network namespace id, if kernel supports it
#ifdef CONFIG_NET_NS
	possible_net_t skc_net;
	bpf_probe_read(&skc_net, sizeof(skc_net), &sk->__sk_common.skc_net);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), &skc_net.net->ns.inum);
#endif
	bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);
	if (family == AF_INET) {
		u32 saddr = 0, daddr = 0;
		bpf_probe_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
		bpf_probe_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
		bpf_probe_read(&sport, sizeof(sport), &((struct inet_sock *)sk)->inet_sport);
		bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
		// output
		struct tcp_ipv4_event_t evt = {
			.timestamp = bpf_ktime_get_ns(),
			.cpu = bpf_get_smp_processor_id(),
			.type = TCP_EVENT_TYPE_CLOSE,
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
			bpf_perf_event_output(ctx, &tcp_event_ipv4, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
		}
		struct ipv4_tuple_t t = {
			.saddr = saddr,
			.daddr = daddr,
			.sport = ntohs(sport),
			.dport = ntohs(dport),
			.netns = net_ns_inum,
		};
		bpf_map_delete_elem(&tuplepid_ipv4, &t);
	} else if (family == AF_INET6) {
		u64 saddr_h = 0, saddr_l = 0, daddr_h = 0, daddr_l = 0;
		bpf_probe_read(&saddr_h, sizeof(saddr_h), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read(&saddr_l, sizeof(saddr_l), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[2]);
		bpf_probe_read(&daddr_h, sizeof(daddr_h), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
		bpf_probe_read(&daddr_l, sizeof(daddr_l), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[2]);
		bpf_probe_read(&sport, sizeof(sport), &((struct inet_sock *)sk)->inet_sport);
		bpf_probe_read(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
		// output
		struct tcp_ipv6_event_t evt = {
			.timestamp = bpf_ktime_get_ns(),
			.cpu = bpf_get_smp_processor_id(),
			.type = TCP_EVENT_TYPE_CLOSE,
			.pid = pid >> 32,
			.saddr_h = saddr_h,
			.saddr_l = saddr_l,
			.daddr_h = daddr_h,
			.daddr_l = daddr_l,
			.sport = ntohs(sport),
			.dport = ntohs(dport),
			.netns = net_ns_inum,
		};
		bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
		// do not send event if IP address is :: or port is 0
		if ((evt.saddr_h || evt.saddr_l) && (evt.daddr_h || evt.daddr_l) && evt.sport != 0 && evt.dport != 0) {
			bpf_perf_event_output(ctx, &tcp_event_ipv6, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
		}
		struct ipv6_tuple_t t = {
			t.saddr_h = saddr_h,
			t.saddr_l = saddr_l,
			t.daddr_h = daddr_h,
			t.daddr_l = daddr_l,
			t.sport = ntohs(sport),
			t.dport = ntohs(dport),
			t.netns = net_ns_inum,
		};
		bpf_map_delete_elem(&tuplepid_ipv6, &t);
	}
	return 0;
}

SEC("kretprobe/inet_csk_accept")
int kretprobe__inet_csk_accept(struct pt_regs *ctx)
{
	struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
	u64 pid = bpf_get_current_pid_tgid();

	if (newsk == NULL)
		return 0;

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
	bpf_probe_read(&lport, sizeof(lport), &newsk->__sk_common.skc_num);
	bpf_probe_read(&dport, sizeof(dport), &newsk->__sk_common.skc_dport);
// Get network namespace id, if kernel supports it
#ifdef CONFIG_NET_NS
	possible_net_t skc_net;
	bpf_probe_read(&skc_net, sizeof(skc_net), &newsk->__sk_common.skc_net);
	bpf_probe_read(&net_ns_inum, sizeof(net_ns_inum), &skc_net.net->ns.inum);
#endif
	if (family == AF_INET) {
		struct tcp_ipv4_event_t evt = {
			.timestamp = bpf_ktime_get_ns(),
			.cpu = bpf_get_smp_processor_id(),
			.type = TCP_EVENT_TYPE_ACCEPT,
			.netns = net_ns_inum,
		};
		evt.pid = pid >> 32;
		bpf_probe_read(&evt.saddr, sizeof(u32), &newsk->__sk_common.skc_rcv_saddr);
		bpf_probe_read(&evt.daddr, sizeof(u32), &newsk->__sk_common.skc_daddr);
		evt.sport = lport;
		evt.dport = ntohs(dport);
		bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
		// do not send event if IP address is 0.0.0.0 or port is 0
		if (evt.saddr != 0 && evt.daddr != 0 && evt.sport != 0 && evt.dport != 0) {
			bpf_perf_event_output(ctx, &tcp_event_ipv4, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
		}
	} else if (family == AF_INET6) {
		struct tcp_ipv6_event_t evt = {
			.timestamp = bpf_ktime_get_ns(),
			.cpu = bpf_get_smp_processor_id(),
			.type = TCP_EVENT_TYPE_ACCEPT,
			.netns = net_ns_inum,
		};
		evt.pid = pid >> 32;
		bpf_probe_read(&evt.saddr_h, sizeof(evt.saddr_h), &newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read(&evt.saddr_l, sizeof(evt.saddr_l), &newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[2]);
		bpf_probe_read(&evt.daddr_h, sizeof(evt.daddr_h), &newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
		bpf_probe_read(&evt.daddr_l, sizeof(evt.daddr_l), &newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[2]);
		evt.sport = lport;
		evt.dport = ntohs(dport);
		bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
		// do not send event if IP address is :: or port is 0
		if ((evt.saddr_h || evt.saddr_l) && (evt.daddr_h || evt.daddr_l) && evt.sport != 0 && evt.dport != 0) {
			bpf_perf_event_output(ctx, &tcp_event_ipv6, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
		}
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;

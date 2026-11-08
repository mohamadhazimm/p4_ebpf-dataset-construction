#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "attribution.h"

char LICENSE[] SEC("license") = "GPL";
const volatile __u64 selected_cgroup = 0;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} observations SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, ATTR_COUNTERS);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, struct attr_pending);
} pending SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, struct attr_pending);
} socket_pending SEC(".maps");

static __always_inline __u64 count(__u32 key)
{
    __u64 *value = bpf_map_lookup_elem(&counters, &key);
    return value ? __sync_fetch_and_add(value, 1) + 1 : 0;
}

static __always_inline int selected(void)
{
    return selected_cgroup && bpf_get_current_cgroup_id() == selected_cgroup;
}

static __always_inline struct attr_event *reserve(__u32 kind, int process_context)
{
    __u64 sequence = count(0);
    struct attr_event *event = bpf_ringbuf_reserve(&observations, sizeof(*event), 0);
    if (!event) {
        count(1);
        return 0;
    }
    _Static_assert(sizeof(*event) % sizeof(__u64) == 0, "Event must use complete words");
#pragma unroll
    for (int index = 0; index < sizeof(*event) / sizeof(__u64); index++)
        ((volatile __u64 *)event)[index] = 0;
    event->version = ATTR_VERSION;
    event->sequence = sequence;
    event->kind = kind;
    event->monotonic_ns = bpf_ktime_get_ns();
    event->abi = ATTR_ABI_UNKNOWN;
    if (process_context) {
        struct task_struct *task = (void *)bpf_get_current_task();
        __u64 identity = bpf_get_current_pid_tgid();
        event->pid = identity >> 32;
        event->tid = identity;
        event->thread_start_ns = BPF_CORE_READ(task, start_time);
        event->process_start_ns = BPF_CORE_READ(task, group_leader, start_time);
        event->cgroup_id = bpf_get_current_cgroup_id();
        event->netns_inum = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
        if (bpf_core_field_exists(task->thread_info.status))
            event->abi = !!(BPF_CORE_READ(task, thread_info.status) & 2);
        else
            count(5);
    }
    return event;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int syscall_enter(struct trace_event_raw_sys_enter *context)
{
    if (!selected())
        return 0;
    struct attr_event *event = reserve(ATTR_ENTER, 1);
    if (!event)
        return 0;
    event->syscall_id = context->id;
    if (event->syscall_id & 0x40000000) {
        event->abi = ATTR_ABI_UNKNOWN;
        count(5);
    }
    __builtin_memcpy(event->arguments, context->args, sizeof(event->arguments));
    struct attr_pending operation = {
        .begin_ns = event->monotonic_ns,
        .thread_start_ns = event->thread_start_ns,
        .syscall_id = event->syscall_id,
        .abi = event->abi,
    };
    __u64 identity = bpf_get_current_pid_tgid();
    if (bpf_map_update_elem(&pending, &identity, &operation, BPF_ANY))
        count(3);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int syscall_return(struct trace_event_raw_sys_exit *context)
{
    if (!selected())
        return 0;
    __u64 identity = bpf_get_current_pid_tgid();
    struct attr_pending *operation = bpf_map_lookup_elem(&pending, &identity);
    struct attr_event *event = reserve(ATTR_RETURN, 1);
    if (!event) {
        bpf_map_delete_elem(&pending, &identity);
        return 0;
    }
    event->syscall_id = context->id;
    event->result = context->ret;
    if (operation && operation->thread_start_ns == event->thread_start_ns && operation->syscall_id == event->syscall_id) {
        event->operation_begin_ns = operation->begin_ns;
        event->abi = operation->abi;
    } else {
        count(4);
    }
    bpf_map_delete_elem(&pending, &identity);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

static __always_inline int socket_observation(struct socket *socket, struct msghdr *message, __u32 kind, int result)
{
    if (!selected())
        return 0;
    struct attr_event *event = reserve(kind, 1);
    if (!event)
        return 0;
    struct sock *socket_state = BPF_CORE_READ(socket, sk);
    if (!socket_state) {
        count(6);
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    event->socket_cookie = BPF_CORE_READ(socket_state, __sk_common.skc_cookie.counter);
    event->family = BPF_CORE_READ(socket_state, __sk_common.skc_family);
    event->protocol = BPF_CORE_READ(socket_state, sk_protocol);
    event->local_port = BPF_CORE_READ(socket_state, __sk_common.skc_num);
    event->remote_port = bpf_ntohs(BPF_CORE_READ(socket_state, __sk_common.skc_dport));
    event->result = result;
    __u64 identity = bpf_get_current_pid_tgid();
    if (kind == ATTR_SEND_ENTER || kind == ATTR_RECV_ENTER) {
        struct attr_pending operation = {
            .begin_ns = event->monotonic_ns,
            .thread_start_ns = event->thread_start_ns,
            .syscall_id = kind,
            .abi = event->abi,
        };
        if (bpf_map_update_elem(&socket_pending, &identity, &operation, BPF_ANY))
            count(3);
    } else {
        struct attr_pending *operation = bpf_map_lookup_elem(&socket_pending, &identity);
        if (operation && operation->thread_start_ns == event->thread_start_ns && operation->syscall_id + 1 == kind) {
            event->operation_begin_ns = operation->begin_ns;
            event->abi = operation->abi;
        } else {
            count(4);
        }
        bpf_map_delete_elem(&socket_pending, &identity);
    }
    if (event->family == 2) {
        __be32 local_address = BPF_CORE_READ(socket_state, __sk_common.skc_rcv_saddr);
        __be32 remote_address = BPF_CORE_READ(socket_state, __sk_common.skc_daddr);
        __builtin_memcpy(event->local_address, &local_address, sizeof(local_address));
        __builtin_memcpy(event->remote_address, &remote_address, sizeof(remote_address));
    } else if (event->family == 10) {
        BPF_CORE_READ_INTO(&event->local_address, socket_state, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&event->remote_address, socket_state, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }
    void *name = BPF_CORE_READ(message, msg_name);
    int length = BPF_CORE_READ(message, msg_namelen);
    int peer_available = kind == ATTR_SEND_ENTER || kind == ATTR_SEND_RETURN || (kind == ATTR_RECV_RETURN && result >= 0);
    if (peer_available && name && event->family == 2 && length >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in peer = {};
        if (!bpf_probe_read_kernel(&peer, sizeof(peer), name) && peer.sin_family == 2) {
            event->remote_port = bpf_ntohs(peer.sin_port);
            __builtin_memcpy(event->remote_address, &peer.sin_addr, 4);
        } else {
            count(6);
        }
    } else if (peer_available && name && event->family == 10 && length >= sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 peer = {};
        if (!bpf_probe_read_kernel(&peer, sizeof(peer), name) && peer.sin6_family == 10) {
            event->remote_port = bpf_ntohs(peer.sin6_port);
            __builtin_memcpy(event->remote_address, &peer.sin6_addr, 16);
        } else {
            count(6);
        }
    }
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("fentry/sock_sendmsg")
int BPF_PROG(send_enter, struct socket *socket, struct msghdr *message)
{
    return socket_observation(socket, message, ATTR_SEND_ENTER, 0);
}

SEC("fexit/sock_sendmsg")
int BPF_PROG(send_return, struct socket *socket, struct msghdr *message, int result)
{
    return socket_observation(socket, message, ATTR_SEND_RETURN, result);
}

SEC("fentry/sock_recvmsg")
int BPF_PROG(recv_enter, struct socket *socket, struct msghdr *message, int flags)
{
    return socket_observation(socket, message, ATTR_RECV_ENTER, 0);
}

SEC("fexit/sock_recvmsg")
int BPF_PROG(recv_return, struct socket *socket, struct msghdr *message, int flags, int result)
{
    return socket_observation(socket, message, ATTR_RECV_RETURN, result);
}

static __always_inline int packet_observation(struct __sk_buff *packet, __u32 kind)
{
    struct attr_event *event = reserve(kind, 0);
    if (!event)
        return 1;
    event->socket_cookie = bpf_get_socket_cookie(packet);
    event->netns_cookie = bpf_get_netns_cookie(packet);
    event->cgroup_id = selected_cgroup;
    event->interface_index = packet->ifindex;
    event->wire_size = packet->len;
    __u32 length = packet->len;
    if (length > ATTR_SNAPSHOT)
        length = ATTR_SNAPSHOT;
    if (length && !bpf_skb_load_bytes(packet, 0, event->snapshot, length))
        event->captured_size = length;
    else
        count(2);
    bpf_ringbuf_submit(event, 0);
    return 1;
}

SEC("cgroup_skb/egress")
int packet_egress(struct __sk_buff *packet)
{
    return packet_observation(packet, ATTR_EGRESS);
}

SEC("cgroup_skb/ingress")
int packet_ingress(struct __sk_buff *packet)
{
    return packet_observation(packet, ATTR_INGRESS);
}

SEC("tracepoint/sched/sched_process_exec")
int process_exec(struct trace_event_raw_sched_process_exec *context)
{
    if (!selected())
        return 0;
    struct attr_event *event = reserve(ATTR_EXEC, 1);
    if (!event)
        return 0;
    event->related_pid = context->old_pid;
    __u32 offset = context->__data_loc_filename & 0xffff;
    int length = bpf_probe_read_kernel_str(event->snapshot, sizeof(event->snapshot), (void *)context + offset);
    if (length > 0)
        event->captured_size = length;
    else
        count(2);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int process_fork(struct trace_event_raw_sched_process_fork *context)
{
    if (!selected())
        return 0;
    struct attr_event *event = reserve(ATTR_FORK, 1);
    if (event) {
        event->related_pid = context->child_pid;
        bpf_ringbuf_submit(event, 0);
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int process_exit(void *context)
{
    if (!selected())
        return 0;
    __u64 identity = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&pending, &identity);
    bpf_map_delete_elem(&socket_pending, &identity);
    struct attr_event *event = reserve(ATTR_EXIT, 1);
    if (event)
        bpf_ringbuf_submit(event, 0);
    return 0;
}
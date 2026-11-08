#include "../attribution-v1/attribution.h"
#undef ATTR_VERSION
#define ATTR_VERSION 2
#include "../attribution-v1/attribution.bpf.c"

enum lifecycle_kind {
    ATTR_DESCRIPTOR_INSTALL = 12, ATTR_FILE_CLOSE, ATTR_FILE_FINAL,
    ATTR_DESCRIPTOR_RECEIVE_CHECK, ATTR_SOCKET_CREATE_CHECK,
    ATTR_SOCKET_ACCEPT_CHECK, ATTR_SOCKET_RELEASE, ATTR_SOCKET_CONNECT_CHECK,
    ATTR_FORK_FILES, ATTR_FILES_FINAL
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} object_sequence SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, __u64);
} file_objects SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u64);
    __type(value, __u64);
} files_objects SEC(".maps");

static __always_inline __u64 object_identity(void *map, const void *object)
{
    __u64 key = (__u64)object;
    if (!key)
        return 0;
    __u64 *existing = bpf_map_lookup_elem(map, &key);
    if (existing)
        return *existing;
    __u32 zero = 0;
    __u64 *sequence = bpf_map_lookup_elem(&object_sequence, &zero);
    if (!sequence) {
        count(3);
        return 0;
    }
    __u64 identifier = __sync_fetch_and_add(sequence, 1) + 1;
    long installed = bpf_map_update_elem(map, &key, &identifier, BPF_NOEXIST);
    existing = bpf_map_lookup_elem(map, &key);
    if (!existing) {
        count(3);
        return 0;
    }
    if (installed && installed != -17)
        count(3);
    return *existing;
}

static __always_inline void socket_fields(struct attr_event *event, struct socket *socket)
{
    struct sock *state = BPF_CORE_READ(socket, sk);
    if (!state) {
        count(6);
        return;
    }
    event->socket_cookie = BPF_CORE_READ(state, __sk_common.skc_cookie.counter);
    event->family = BPF_CORE_READ(state, __sk_common.skc_family);
    event->protocol = BPF_CORE_READ(state, sk_protocol);
    event->local_port = BPF_CORE_READ(state, __sk_common.skc_num);
    event->remote_port = bpf_ntohs(BPF_CORE_READ(state, __sk_common.skc_dport));
    if (event->family == 2) {
        __be32 local = BPF_CORE_READ(state, __sk_common.skc_rcv_saddr);
        __be32 remote = BPF_CORE_READ(state, __sk_common.skc_daddr);
        __builtin_memcpy(event->local_address, &local, 4);
        __builtin_memcpy(event->remote_address, &remote, 4);
    } else if (event->family == 10) {
        BPF_CORE_READ_INTO(&event->local_address, state, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&event->remote_address, state, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }
}

static __always_inline int file_observation(struct file *file, __u32 kind, __u32 descriptor, int result)
{
    __u64 key = (__u64)file;
    if (!file || (!selected() && !bpf_map_lookup_elem(&file_objects, &key)))
        return 0;
    if ((BPF_CORE_READ(file, f_inode, i_mode) & 0170000) != 0140000)
        return 0;
    struct attr_event *event = reserve(kind, 1);
    if (!event)
        return 0;
    struct task_struct *task = (void *)bpf_get_current_task();
    struct files_struct *files = BPF_CORE_READ(task, files);
    event->arguments[0] = descriptor;
    event->arguments[1] = object_identity(&file_objects, file);
    event->arguments[2] = object_identity(&files_objects, files);
    event->arguments[3] = files ? BPF_CORE_READ(files, count.counter) : 0;
    event->arguments[4] = BPF_CORE_READ(file, f_inode, i_ino);
    event->result = result;
    struct socket *socket = BPF_CORE_READ(file, private_data);
    socket_fields(event, socket);
    bpf_ringbuf_submit(event, 0);
    if (kind == ATTR_FILE_FINAL)
        bpf_map_delete_elem(&file_objects, &key);
    return 0;
}

SEC("fentry/fd_install")
int BPF_PROG(descriptor_install, unsigned int descriptor, struct file *file)
{
    return file_observation(file, ATTR_DESCRIPTOR_INSTALL, descriptor, 0);
}

SEC("fentry/filp_close")
int BPF_PROG(file_close, struct file *file, void *files)
{
    return file_observation(file, ATTR_FILE_CLOSE, 0xffffffff, 0);
}

SEC("fentry/__fput")
int BPF_PROG(file_final, struct file *file)
{
    return file_observation(file, ATTR_FILE_FINAL, 0xffffffff, 0);
}

SEC("fexit/security_file_receive")
int BPF_PROG(descriptor_receive_check, struct file *file, int result)
{
    return file_observation(file, ATTR_DESCRIPTOR_RECEIVE_CHECK, 0xffffffff, result);
}

static __always_inline int socket_lifecycle(struct socket *socket, struct socket *related, __u32 kind, int result)
{
    if (!selected())
        return 0;
    struct attr_event *event = reserve(kind, 1);
    if (!event)
        return 0;
    event->result = result;
    event->arguments[0] = 0xffffffff;
    struct task_struct *task = (void *)bpf_get_current_task();
    event->arguments[2] = object_identity(&files_objects, BPF_CORE_READ(task, files));
    if (related) {
        struct sock *state = BPF_CORE_READ(related, sk);
        event->arguments[5] = state ? BPF_CORE_READ(state, __sk_common.skc_cookie.counter) : 0;
    }
    socket_fields(event, socket);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("fexit/security_socket_post_create")
int BPF_PROG(socket_create_check, struct socket *socket, int family, int type, int protocol, int kern, int result)
{
    return socket_lifecycle(socket, 0, ATTR_SOCKET_CREATE_CHECK, result);
}

SEC("fexit/security_socket_accept")
int BPF_PROG(socket_accept_check, struct socket *socket, struct socket *accepted, int result)
{
    return socket_lifecycle(socket, accepted, ATTR_SOCKET_ACCEPT_CHECK, result);
}

SEC("fentry/sock_release")
int BPF_PROG(socket_release, struct socket *socket)
{
    return socket_lifecycle(socket, 0, ATTR_SOCKET_RELEASE, 0);
}

SEC("fexit/security_socket_connect")
int BPF_PROG(socket_connect_check, struct socket *socket, struct sockaddr *address, int length, int result)
{
    return socket_lifecycle(socket, 0, ATTR_SOCKET_CONNECT_CHECK, result);
}

SEC("raw_tp/sched_process_fork")
int fork_files(struct bpf_raw_tracepoint_args *context)
{
    if (!selected())
        return 0;
    struct task_struct *parent = (void *)context->args[0];
    struct task_struct *child = (void *)context->args[1];
    struct attr_event *event = reserve(ATTR_FORK_FILES, 1);
    if (!event)
        return 0;
    event->related_pid = BPF_CORE_READ(child, pid);
    event->arguments[0] = BPF_CORE_READ(child, start_time);
    event->arguments[1] = BPF_CORE_READ(child, tgid);
    event->arguments[2] = object_identity(&files_objects, BPF_CORE_READ(parent, files));
    event->arguments[3] = object_identity(&files_objects, BPF_CORE_READ(child, files));
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("fentry/close_files")
int files_final(struct files_struct *files)
{
    __u64 key = (__u64)files;
    __u64 *identifier = bpf_map_lookup_elem(&files_objects, &key);
    if (!identifier)
        return 0;
    struct attr_event *event = reserve(ATTR_FILES_FINAL, 1);
    if (event) {
        event->arguments[2] = *identifier;
        bpf_ringbuf_submit(event, 0);
    }
    bpf_map_delete_elem(&files_objects, &key);
    return 0;
}
#ifndef HAZIM_ATTRIBUTION_V1_H
#define HAZIM_ATTRIBUTION_V1_H

#define ATTR_VERSION 1
#define ATTR_SNAPSHOT 2048
#define ATTR_COUNTERS 8
#define ATTR_ABI_UNKNOWN 255

enum attr_kind {
    ATTR_ENTER = 1, ATTR_RETURN, ATTR_SEND_ENTER, ATTR_SEND_RETURN,
    ATTR_RECV_ENTER, ATTR_RECV_RETURN, ATTR_EGRESS, ATTR_INGRESS,
    ATTR_EXEC, ATTR_FORK, ATTR_EXIT
};

struct attr_event {
    unsigned long long sequence;
    unsigned long long monotonic_ns;
    unsigned long long process_start_ns;
    unsigned long long thread_start_ns;
    unsigned long long cgroup_id;
    unsigned long long socket_cookie;
    unsigned long long netns_cookie;
    unsigned long long operation_begin_ns;
    long long result;
    unsigned long long arguments[6];
    unsigned int version;
    unsigned int kind;
    unsigned int pid;
    unsigned int tid;
    unsigned int related_pid;
    unsigned int syscall_id;
    unsigned int netns_inum;
    unsigned int interface_index;
    unsigned int wire_size;
    unsigned int captured_size;
    unsigned short family;
    unsigned short local_port;
    unsigned short remote_port;
    unsigned char abi;
    unsigned char protocol;
    unsigned char local_address[16];
    unsigned char remote_address[16];
    unsigned char snapshot[ATTR_SNAPSHOT];
};

struct attr_pending {
    unsigned long long begin_ns;
    unsigned long long thread_start_ns;
    unsigned int syscall_id;
    unsigned char abi;
};

#endif
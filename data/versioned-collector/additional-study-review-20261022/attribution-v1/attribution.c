#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <time.h>
#include <unistd.h>
#include "attribution.h"

static volatile sig_atomic_t stopping;
static unsigned long long emitted;
static unsigned long long invalid_records;

static void stop_capture(int signal_number)
{
    (void)signal_number;
    stopping = 1;
}

static unsigned long long nanoseconds(clockid_t clock)
{
    struct timespec moment;
    if (clock_gettime(clock, &moment))
        return 0;
    return (unsigned long long)moment.tv_sec * 1000000000ULL + moment.tv_nsec;
}

static void clock_bracket(FILE *output, const char *phase)
{
    unsigned long long before = nanoseconds(CLOCK_REALTIME);
    unsigned long long monotonic = nanoseconds(CLOCK_MONOTONIC);
    unsigned long long after = nanoseconds(CLOCK_REALTIME);
    fprintf(output, "{\"record\":\"clock\",\"phase\":\"%s\",\"realtime_before_ns\":%llu,\"monotonic_ns\":%llu,\"realtime_after_ns\":%llu}\n", phase, before, monotonic, after);
}

static bool valid_event(const struct attr_event *event, size_t size)
{
    if (size != sizeof(*event) || event->version != ATTR_VERSION || event->kind < ATTR_ENTER || event->kind > ATTR_EXIT || event->captured_size > ATTR_SNAPSHOT)
        return false;
    if (event->abi != 0 && event->abi != 1 && event->abi != ATTR_ABI_UNKNOWN)
        return false;
    if (event->kind == ATTR_EGRESS || event->kind == ATTR_INGRESS)
        return !event->pid && !event->tid && !event->process_start_ns && event->captured_size <= event->wire_size;
    return event->pid && event->tid && event->process_start_ns && event->thread_start_ns;
}

static void hex(FILE *output, const unsigned char *bytes, size_t length)
{
    for (size_t index = 0; index < length; index++)
        fprintf(output, "%02x", bytes[index]);
}

static int observation(void *context, void *data, size_t size)
{
    FILE *output = context;
    const struct attr_event *event = data;
    if (size != sizeof(*event) || !valid_event(event, size)) {
        invalid_records++;
        return 0;
    }
    emitted++;
    fprintf(output, "{\"record\":\"observation\",\"schema\":\"attribution-sensor-v1\",\"sequence\":%llu,\"monotonic_ns\":%llu,\"kind\":%u,\"pid\":%u,\"tid\":%u,\"process_start_ns\":%llu,\"thread_start_ns\":%llu,\"cgroup_id\":%llu,\"socket_cookie\":%llu,\"netns_cookie\":%llu,\"netns_inum\":%u,\"related_pid\":%u,\"syscall_id\":%u,\"abi\":%u,\"operation_begin_ns\":%llu,\"result\":%lld,\"family\":%u,\"protocol\":%u,\"local_port\":%u,\"remote_port\":%u,\"interface_index\":%u,\"wire_size\":%u,\"captured_size\":%u,\"frame_link_verified\":false,\"ownership_verified\":false,\"arguments\":[", event->sequence, event->monotonic_ns, event->kind, event->pid, event->tid, event->process_start_ns, event->thread_start_ns, event->cgroup_id, event->socket_cookie, event->netns_cookie, event->netns_inum, event->related_pid, event->syscall_id, event->abi, event->operation_begin_ns, event->result, event->family, event->protocol, event->local_port, event->remote_port, event->interface_index, event->wire_size, event->captured_size);
    for (size_t index = 0; index < 6; index++)
        fprintf(output, "%s%llu", index ? "," : "", event->arguments[index]);
    fputs("],\"local_address_hex\":\"", output);
    hex(output, event->local_address, sizeof(event->local_address));
    fputs("\",\"remote_address_hex\":\"", output);
    hex(output, event->remote_address, sizeof(event->remote_address));
    fputs("\",\"snapshot_hex\":\"", output);
    hex(output, event->snapshot, event->captured_size);
    fputs("\"}\n", output);
    if (ferror(output))
        return -EIO;
    return 0;
}

static int evidence_status(int status, bool available, unsigned long long records, unsigned long long invalid, const uint64_t *values)
{
    if (!available || !records || invalid)
        return 1;
    for (size_t index = 1; index < ATTR_COUNTERS; index++)
        if (values[index])
            return 1;
    return status;
}

static int self_test(void)
{
    uint64_t values[ATTR_COUNTERS] = {};
    if (evidence_status(0, true, 1, 0, values) || !evidence_status(0, false, 1, 0, values) || !evidence_status(0, true, 0, 0, values) || !evidence_status(0, true, 1, 1, values) || evidence_status(130, true, 1, 0, values) != 130)
        return 1;
    for (size_t index = 1; index < ATTR_COUNTERS; index++) {
        values[index] = 1;
        if (!evidence_status(0, true, 1, 0, values))
            return 1;
        values[index] = 0;
    }
    struct attr_event event = {.version = ATTR_VERSION, .kind = ATTR_ENTER, .pid = 10, .tid = 11, .process_start_ns = 1, .thread_start_ns = 2, .abi = 1};
    if (!valid_event(&event, sizeof(event)) || valid_event(&event, sizeof(event) - 1))
        return 1;
    event.abi = 3;
    if (valid_event(&event, sizeof(event)))
        return 1;
    event.abi = ATTR_ABI_UNKNOWN;
    if (!valid_event(&event, sizeof(event)))
        return 1;
    event.kind = ATTR_EGRESS;
    if (valid_event(&event, sizeof(event)))
        return 1;
    event.pid = event.tid = 0;
    event.process_start_ns = 0;
    event.thread_start_ns = 0;
    event.wire_size = event.captured_size = 40;
    if (!valid_event(&event, sizeof(event)))
        return 1;
    event.captured_size = ATTR_SNAPSHOT + 1;
    if (valid_event(&event, sizeof(event)))
        return 1;
    event.captured_size = 41;
    if (valid_event(&event, sizeof(event)))
        return 1;
    event.captured_size = 40;
    return observation(stdout, &event, sizeof(event));
}

static int configure_object(struct bpf_object *object, uint64_t cgroup_id)
{
    struct bpf_map *map;
    bpf_object__for_each_map(map, object) {
        if (bpf_map__is_internal(map) && strstr(bpf_map__name(map), ".rodata"))
            return bpf_map__set_initial_value(map, &cgroup_id, sizeof(cgroup_id));
    }
    return -ENOENT;
}

static int inspect(const char *path)
{
    struct bpf_object *object = bpf_object__open_file(path, NULL);
    if (libbpf_get_error(object))
        return 1;
    if (configure_object(object, 123)) {
        bpf_object__close(object);
        return 1;
    }
    struct bpf_program *program;
    unsigned int count = 0;
    bpf_object__for_each_program(program, object) {
        printf("%s\t%s\n", bpf_program__name(program), bpf_program__section_name(program));
        count++;
    }
    bpf_object__close(object);
    return count == 11 ? 0 : 1;
}

static bool safe_run_id(const char *text)
{
    size_t length = strlen(text);
    if (!length || length > 80)
        return false;
    for (size_t index = 0; index < length; index++)
        if (!((text[index] >= 'a' && text[index] <= 'z') || (text[index] >= 'A' && text[index] <= 'Z') || (text[index] >= '0' && text[index] <= '9') || text[index] == '-'))
            return false;
    return true;
}

static int capture(const char *object_path, const char *cgroup_path, const char *duration_text, const char *run_id, const char *output_path)
{
    char *end = NULL;
    errno = 0;
    long duration = strtol(duration_text, &end, 10);
    if (errno || !*duration_text || *end || duration < 1 || duration > 30 || !safe_run_id(run_id))
        return 2;
    int cgroup = open(cgroup_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat identity;
    struct stat hierarchy_root;
    struct statfs filesystem;
    if (cgroup < 0)
        return 2;
    if (fstat(cgroup, &identity) || fstatfs(cgroup, &filesystem) || stat("/sys/fs/cgroup", &hierarchy_root) || filesystem.f_type != CGROUP2_SUPER_MAGIC || (identity.st_dev == hierarchy_root.st_dev && identity.st_ino == hierarchy_root.st_ino)) {
        close(cgroup);
        return 2;
    }
    int descriptor = open(output_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0) {
        close(cgroup);
        return 2;
    }
    FILE *output = fdopen(descriptor, "w");
    if (!output) {
        close(descriptor);
        close(cgroup);
        return 2;
    }
    int result = 1;
    struct bpf_object *object = NULL;
    struct ring_buffer *buffer = NULL;
    struct bpf_link *links[11] = {};
    size_t link_count = 0;
    char boot_id[80] = {};
    FILE *boot = fopen("/proc/sys/kernel/random/boot_id", "r");
    if (!boot || !fgets(boot_id, sizeof(boot_id), boot)) {
        if (boot)
            fclose(boot);
        goto cleanup;
    }
    fclose(boot);
    boot_id[strcspn(boot_id, "\r\n")] = 0;
    if (!safe_run_id(boot_id))
        goto cleanup;
    fprintf(output, "{\"record\":\"session\",\"schema\":\"attribution-sensor-v1\",\"run_id\":\"%s\",\"boot_id\":\"%s\",\"cgroup_id\":%llu,\"duration_seconds\":%ld,\"collection_ready\":false,\"frame_mapping_validated\":false,\"descriptor_ownership_complete\":false,\"socket_lifetimes_complete\":false,\"live_validation_passed\":false}\n", run_id, boot_id, (unsigned long long)identity.st_ino, duration);
    clock_bracket(output, "before");
    object = bpf_object__open_file(object_path, NULL);
    if (libbpf_get_error(object)) {
        object = NULL;
        goto cleanup;
    }
    uint64_t cgroup_id = identity.st_ino;
    if (configure_object(object, cgroup_id) || bpf_object__load(object))
        goto cleanup;
    struct bpf_program *program;
    bpf_object__for_each_program(program, object) {
        if (link_count >= 11)
            goto cleanup;
        const char *section = bpf_program__section_name(program);
        struct bpf_link *link = !strncmp(section, "cgroup_skb/", 11) ? bpf_program__attach_cgroup(program, cgroup) : bpf_program__attach(program);
        if (libbpf_get_error(link))
            goto cleanup;
        links[link_count++] = link;
    }
    buffer = ring_buffer__new(bpf_object__find_map_fd_by_name(object, "observations"), observation, output, NULL);
    if (!buffer)
        goto cleanup;
    signal(SIGINT, stop_capture);
    signal(SIGTERM, stop_capture);
    unsigned long long deadline = nanoseconds(CLOCK_MONOTONIC) + duration * 1000000000ULL;
    fputs("{\"record\":\"attached\",\"target_workload_launched\":false}\n", output);
    fflush(output);
    while (!stopping && nanoseconds(CLOCK_MONOTONIC) < deadline) {
        int polled = ring_buffer__poll(buffer, 100);
        if (polled < 0 && polled != -EINTR)
            goto cleanup;
    }
    result = stopping ? 130 : 0;

cleanup:
    for (size_t index = 0; index < link_count; index++)
        bpf_link__destroy(links[index]);
    if (buffer) {
        int drained;
        while ((drained = ring_buffer__consume(buffer)) > 0) {}
        if (drained < 0)
            result = 1;
    }
    bool counters_available = object && link_count == 11;
    uint64_t values[ATTR_COUNTERS] = {};
    for (uint32_t index = 0; index < ATTR_COUNTERS; index++) {
        if (!object || bpf_map_lookup_elem(bpf_object__find_map_fd_by_name(object, "counters"), &index, &values[index]))
            counters_available = false;
    }
    result = evidence_status(result, counters_available, emitted, invalid_records, values);
    if (ferror(output))
        result = 1;
    fprintf(output, "{\"record\":\"final\",\"returncode\":%d,\"events_emitted\":%llu,\"invalid_records\":%llu,\"counters\":[", result, emitted, invalid_records);
    for (uint32_t index = 0; index < ATTR_COUNTERS; index++)
        fprintf(output, "%s%llu", index ? "," : "", (unsigned long long)values[index]);
    fprintf(output, "],\"counters_available\":%s,\"collection_ready\":false}\n", counters_available ? "true" : "false");
    clock_bracket(output, "after");
    ring_buffer__free(buffer);
    bpf_object__close(object);
    if (fclose(output))
        result = 1;
    close(cgroup);
    return result;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--self-test"))
        return self_test();
    if (argc == 3 && !strcmp(argv[1], "--inspect"))
        return inspect(argv[2]);
    if (argc == 7 && !strcmp(argv[1], "--capture"))
        return capture(argv[2], argv[3], argv[4], argv[5], argv[6]);
    fputs("Build candidate only. --self-test | --inspect OBJECT | --capture OBJECT CGROUP SECONDS RUN-ID NEW-OUTPUT\nCapture needs a separately approved isolated benign pilot; no workload is launched.\n", stderr);
    return 2;
}
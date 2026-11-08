#!/usr/bin/env python3
"""Compile a separately versioned allocator-finality candidate; never load BPF."""

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import subprocess
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REVIEW = ROOT.parent
PREPARATION = REVIEW / "remediation-preparation/20261022T122641888212Z"
BASE = PREPARATION / "attribution-builds/20261022T124141961818Z"
V2 = REVIEW / "attribution-v2"
GUEST = REVIEW / "remediation-static-guest-readiness/20261022T133122216945Z"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source():
    text = (V2 / "lifecycle.bpf.c").read_text()
    old = 'SEC("fentry/close_files")\nint files_final(struct files_struct *files)\n{\n    __u64 key = (__u64)files;'
    new = '''SEC("fentry/kmem_cache_free")
int BPF_PROG(files_final, struct kmem_cache *cache, void *object)
{
    __u64 key = (__u64)object;'''
    if text.count(old) != 1 or text.count("#define ATTR_VERSION 2") != 1:
        raise ValueError("Pinned v2 finality hook changed")
    text = text.replace(old, new).replace("#define ATTR_VERSION 2", "#define ATTR_VERSION 3")
    anchor = '''    if (!identifier)
        return 0;
    struct attr_event *event = reserve(ATTR_FILES_FINAL, 1);'''
    replacement = '''    if (!identifier)
        return 0;
    const char *cache_name = 0;
    char name[12];
    if (BPF_CORE_READ_INTO(&cache_name, cache, name) ||
        bpf_probe_read_kernel_str(name, sizeof(name), cache_name) != sizeof(name)) {
        count(2);
        return 0;
    }
    const char expected[12] = "files_cache";
#pragma clang loop unroll(full)
    for (int index = 0; index < sizeof(name); index++) {
        if (name[index] != expected[index])
            return 0;
    }
    struct attr_event *event = reserve(ATTR_FILES_FINAL, 1);'''
    if text.count(anchor) != 1:
        raise ValueError("Pinned v2 tracked-object guard changed")
    return text.replace(anchor, replacement)


def boundary_core(core):
    anchor = "static __always_inline int selected(void)\n{\n    return selected_cgroup && bpf_get_current_cgroup_id() == selected_cgroup;\n}"
    replacement = '''struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} exec_scope SEC(".maps");

static __always_inline int selected(void)
{
    if (!selected_cgroup || bpf_get_current_cgroup_id() != selected_cgroup)
        return 0;
    __u32 zero = 0;
    __u32 *active = bpf_map_lookup_elem(&exec_scope, &zero);
    return active && *active;
}'''
    if core.count(anchor) != 1:
        raise ValueError("Pinned cgroup selection changed")
    core = core.replace(anchor, replacement)
    anchor = '''int syscall_enter(struct trace_event_raw_sys_enter *context)
{
    if (!selected())'''
    replacement = '''int syscall_enter(struct trace_event_raw_sys_enter *context)
{
    if (selected_cgroup && bpf_get_current_cgroup_id() == selected_cgroup) {
        struct task_struct *task = (void *)bpf_get_current_task();
        if (!bpf_core_field_exists(task->thread_info.status)) {
            count(5);
            return 0;
        }
        int compat = !!(BPF_CORE_READ(task, thread_info.status) & 2);
        long syscall_id = context->id;
        if ((!compat && (syscall_id == 59 || syscall_id == 322)) ||
            (compat && (syscall_id == 11 || syscall_id == 358))) {
            __u32 zero = 0, active = 1;
            if (bpf_map_update_elem(&exec_scope, &zero, &active, BPF_ANY))
                count(3);
        }
    }
    if (!selected())'''
    if core.count(anchor) != 1:
        raise ValueError("Pinned syscall entry changed")
    core = core.replace(anchor, replacement)
    anchor = "        event->operation_begin_ns = operation->begin_ns;\n        event->abi = operation->abi;"
    if core.count(anchor) != 1:
        raise ValueError("Pinned syscall return match changed")
    return core.replace(anchor, anchor + "\n        event->related_pid = operation->origin_tid;")


def boundary_lifecycle(text):
    anchor = "    struct task_struct *child = (void *)context->args[1];\n    struct attr_event *event = reserve(ATTR_FORK_FILES, 1);"
    replacement = '''    struct task_struct *child = (void *)context->args[1];
    __u64 parent_identity = bpf_get_current_pid_tgid();
    struct attr_pending *operation = bpf_map_lookup_elem(&pending, &parent_identity);
    if (operation && operation->thread_start_ns == BPF_CORE_READ(parent, start_time)) {
        __u32 syscall_id = operation->syscall_id;
        int cloning = operation->abi == 0 ?
            (syscall_id == 56 || syscall_id == 57 || syscall_id == 58 || syscall_id == 435) :
            (syscall_id == 2 || syscall_id == 120 || syscall_id == 190 || syscall_id == 435);
        if (cloning) {
            __u32 child_tid = BPF_CORE_READ(child, pid);
            __u32 child_tgid = BPF_CORE_READ(child, tgid);
            __u64 child_identity = ((__u64)child_tgid << 32) | child_tid;
            struct attr_pending inherited = {
                .begin_ns = operation->begin_ns,
                .thread_start_ns = BPF_CORE_READ(child, start_time),
                .syscall_id = syscall_id,
                .abi = operation->abi,
                .origin_tid = (__u32)parent_identity,
            };
            if (bpf_map_update_elem(&pending, &child_identity, &inherited, BPF_NOEXIST))
                count(3);
        }
    }
    struct attr_event *event = reserve(ATTR_FORK_FILES, 1);'''
    if text.count(anchor) != 1:
        raise ValueError("Pinned raw fork identity changed")
    return text.replace(anchor, replacement)


def transport_core(core):
    replacements = {
        '''SEC("fentry/sock_sendmsg")
int BPF_PROG(send_enter, struct socket *socket, struct msghdr *message)
{
    return socket_observation(socket, message, ATTR_SEND_ENTER, 0);
}''': '''SEC("fentry/udp_sendmsg")
int BPF_PROG(send_enter, struct sock *state, struct msghdr *message, size_t size)
{
    return socket_observation(BPF_CORE_READ(state, sk_socket), message, ATTR_SEND_ENTER, 0);
}''',
        '''SEC("fexit/sock_sendmsg")
int BPF_PROG(send_return, struct socket *socket, struct msghdr *message, int result)
{
    return socket_observation(socket, message, ATTR_SEND_RETURN, result);
}''': '''SEC("fexit/udp_sendmsg")
int BPF_PROG(send_return, struct sock *state, struct msghdr *message, size_t size, int result)
{
    return socket_observation(BPF_CORE_READ(state, sk_socket), message, ATTR_SEND_RETURN, result);
}''',
    }
    for old, new in replacements.items():
        if core.count(old) != 1:
            raise ValueError("Pinned send operation hook changed")
        core = core.replace(old, new)
    tcp = "\n\n".join(block.replace("udp_sendmsg", "tcp_sendmsg").replace("BPF_PROG(send_", "BPF_PROG(tcp_send_") for block in replacements.values())
    return core + "\n" + tcp + "\n"


def run(target_boundary=False, transport_sends=False):
    if transport_sends and not target_boundary:
        raise ValueError("Transport revision requires the explicit exec boundary")
    pins = {V2 / "lifecycle.bpf.c": "6992e1512c59f384343444a5d0eafe77080518e2fa8ddcc5a6916adb2a1cc4bd",
            V2 / "build_lifecycle.py": "ca08912c0faa72897c34595af9c06d4f12daec99392e729f6d22f71a2e43f0ff",
            GUEST / "guest_validation.json": "73a2abb0fb9edf7c82d6a010ae32df37d2e1a4c1df05608ba79c82c55e0f8bae"}
    for name, expected in json.loads((BASE / "source_hashes.json").read_text()).items():
        pins[Path(name)] = expected
    dependencies = PREPARATION / "dependencies/root"
    for name, expected in json.loads((PREPARATION / "dependencies/authentication.json").read_text())["extracted_files"].items():
        pins[dependencies / name] = expected
    for path, expected in pins.items():
        if digest(path) != expected:
            raise ValueError("Pinned input changed: " + str(path))
    guest = json.loads((GUEST / "guest_validation.json").read_text())
    prototype = guest["btf"]["functions"]["kmem_cache_free"]
    if not prototype["count_matches"] or [row["type"] for row in prototype["parameters"]] != ["kmem_cache*", "void*"]:
        raise ValueError("Guest allocator prototype differs")
    with tarfile.open(GUEST / "evidence.tgz") as archive:
        members = [member for member in archive if member.name == "kernel.btf"]
        if len(members) != 1 or not members[0].isfile():
            raise ValueError("Missing unique raw guest BTF")
        kernel_btf = archive.extractfile(members[0]).read()
    if hashlib.sha256(kernel_btf).hexdigest() != guest["btf"]["sha256"]:
        raise ValueError("Raw guest BTF differs")
    specification = importlib.util.spec_from_file_location("pinned_lifecycle_builder", V2 / "build_lifecycle.py")
    v2 = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(v2)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt = PREPARATION / "attribution-allocator-builds" / stamp
    attempt.mkdir(parents=True, exist_ok=False)
    version = 5 if transport_sends else 4 if target_boundary else 3
    binary_name = "attribution-v" + str(version)
    (attempt / "build_allocator.py").write_bytes(Path(__file__).read_bytes())
    (attempt / "guest.btf").write_bytes(kernel_btf)
    core = (REVIEW / "attribution-v1/attribution.bpf.c").read_text()
    copied_arguments = "    __builtin_memcpy(event->arguments, context->args, sizeof(event->arguments));"
    if core.count(copied_arguments) != 1:
        raise ValueError("Pinned syscall argument copy changed")
    scalar_arguments = "\n".join("    event->arguments[%d] = ((volatile struct trace_event_raw_sys_enter *)context)->args[%d];" % (index, index) for index in range(6))
    core = core.replace(copied_arguments, scalar_arguments)
    lifecycle = source().replace('#include "../attribution-v1/attribution.bpf.c"', '#include "core.bpf.c"')
    if target_boundary:
        header = (REVIEW / "attribution-v1/attribution.h").read_text()
        field = "    unsigned int syscall_id;\n    unsigned char abi;"
        if header.count(field) != 1:
            raise ValueError("Pinned pending operation changed")
        (attempt / "sensor-private.h").write_text(header.replace(field, field + "\n    unsigned int origin_tid;"))
        core = boundary_core(core).replace('#include "attribution.h"', '#include "sensor-private.h"')
        lifecycle = boundary_lifecycle(lifecycle).replace('#include "../attribution-v1/attribution.h"', '#include "sensor-private.h"').replace("#define ATTR_VERSION 3", "#define ATTR_VERSION " + str(version))
    if transport_sends:
        core = transport_core(core)
    (attempt / "core.bpf.c").write_text(core)
    bpf_source = attempt / "lifecycle.bpf.c"
    bpf_source.write_text(lifecycle)
    recorder_source = v2.recorder_source().replace("#define ATTR_VERSION 2", "#define ATTR_VERSION " + str(version)).replace("attribution-sensor-v2", "attribution-sensor-v" + str(version))
    if transport_sends:
        for old, new in {"return count == 21 ? 0 : 1;": "return count == 23 ? 0 : 1;",
                         "links[21]": "links[23]", "link_count >= 21": "link_count >= 23",
                         "link_count == 21": "link_count == 23"}.items():
            if recorder_source.count(old) != 1:
                raise ValueError("Pinned recorder program capacity changed: " + old)
            recorder_source = recorder_source.replace(old, new)
    (attempt / "recorder.c").write_text(recorder_source)
    previous = json.loads((PREPARATION / "attribution-lifecycle-builds/20261022T130814329509Z/result.json").read_text())
    command = previous["command"][:]
    command[-3], command[-1] = str(bpf_source), str(attempt / "lifecycle.bpf.o")
    command.insert(1, "-I" + str(V2))
    command.insert(1, "-I" + str(REVIEW / "attribution-v1"))
    environment = dict(os.environ, LD_LIBRARY_PATH=str(dependencies / "usr/lib/x86_64-linux-gnu"))
    report = {"schema": "attribution-lifecycle-build-v" + str(version), "status": "building", "command": command,
              "capture_scope": "dedicated cgroup from first exec attempt; child clone returns identify actual parent entry" if target_boundary else "cgroup membership",
              "build_driver_sha256": digest(Path(__file__)), "guest_btf_sha256": guest["btf"]["sha256"],
              "finality_hook": "fentry/kmem_cache_free", "guest_hook_prototype": prototype,
              "cache_name_live_validation_required": True, "collection_ready": False, "bpf_loaded": False,
              "hooks_attached": False, "live_validation_passed": False,
              "input_hashes": {str(path): expected for path, expected in pins.items()}}
    try:
        with (attempt / "compile.log").open("xb") as output:
            subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, env=environment, check=True)
        skeleton = subprocess.run(["bpftool", "gen", "skeleton", str(attempt / "lifecycle.bpf.o")], capture_output=True, text=True, check=True).stdout
        expected = set(v2.EXPECTED) | ({"tcp_send_enter", "tcp_send_return"} if transport_sends else set())
        if skeleton.count("struct bpf_program *") != len(expected) or any("*" + name + ";" not in skeleton for name in expected):
            raise ValueError("Compiled program inventory differs")
        (attempt / "skeleton.h").write_text(skeleton)
        relocation = subprocess.run(["bpftool", "gen", "min_core_btf", str(attempt / "guest.btf"),
                                     str(attempt / "minimum-guest.btf"), str(attempt / "lifecycle.bpf.o")],
                                    capture_output=True, text=True)
        (attempt / "guest-core-check.log").write_text(relocation.stdout + relocation.stderr)
        if relocation.returncode != 0:
            raise ValueError("Guest CO-RE field check failed; inspect guest-core-check.log")
        recorder = attempt / binary_name
        subprocess.run(["gcc", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-I" + str(REVIEW / "attribution-v1"),
                        "-I" + str(BASE / "headers/include"), "-I" + str(dependencies / "usr/include"),
                        str(attempt / "recorder.c"), str(BASE / "headers/lib/libbpf.a"),
                        "-L" + str(dependencies / "usr/lib/x86_64-linux-gnu"),
                        "-Wl,-rpath," + str(dependencies / "usr/lib/x86_64-linux-gnu"), "-lelf", "-lz", "-o", str(recorder)], check=True, env=environment)
        observation = json.loads(subprocess.run([str(recorder), "--self-test"], capture_output=True, text=True, check=True).stdout)
        if observation["schema"] != "attribution-sensor-v" + str(version) or observation["ownership_verified"] or observation["frame_link_verified"]:
            raise ValueError("Conservative schema-v3 guards differ")
        inspected = subprocess.run([str(recorder), "--inspect", str(attempt / "lifecycle.bpf.o")], capture_output=True, text=True, check=True).stdout
        if len(inspected.splitlines()) != len(expected) or "fentry/close_files" in inspected or "fentry/kmem_cache_free" not in inspected:
            raise ValueError("Wrong finality hook in compiled object")
        for index, (cgroup, duration, run_id) in enumerate([( "/", "1", "guard"), ("/sys/fs/cgroup", "1", "guard"),
                ("/sys/fs/cgroup", "0", "guard"), ("/sys/fs/cgroup", "31", "guard"), ("/sys/fs/cgroup", "1", "../unsafe")]):
            output = attempt / ("must-not-exist-" + str(index))
            invalid = subprocess.run([str(recorder), "--capture", str(attempt / "lifecycle.bpf.o"), cgroup, duration,
                                      run_id, str(output)], capture_output=True)
            if invalid.returncode != 2 or output.exists():
                raise ValueError("Invalid capture request passed a pre-load guard")
        for path, expected in pins.items():
            if digest(path) != expected:
                raise ValueError("Pinned input changed during build")
        outputs = ["core.bpf.c", "lifecycle.bpf.c", "lifecycle.bpf.o", "recorder.c", binary_name, "skeleton.h", "minimum-guest.btf"]
        if target_boundary:
            outputs.append("sensor-private.h")
        report.update(status="programs_and_recorder_compiled_not_live_validated", programs=sorted(expected),
                      negative_capture_guards_passed=5, recorder_self_test_passed=True, guest_core_field_check_passed=True,
                      outputs={name: digest(attempt / name) for name in outputs})
    except Exception as error:
        report.update(status="failed_preserved", error=str(error))
        raise
    finally:
        with (attempt / "result.json").open("x") as output:
            json.dump(report, output, indent=2, sort_keys=True)
            output.write("\n")
        print(attempt, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compile-only", action="store_true", required=True)
    parser.add_argument("--target-exec-boundary", action="store_true")
    parser.add_argument("--transport-sends", action="store_true")
    options = parser.parse_args()
    run(options.target_exec_boundary, options.transport_sends)
#!/usr/bin/env bash
set -euo pipefail

if [[ "${BASH_SOURCE[0]}" == "/home/csci/.corrected-pilot-setup.sh" ]]; then
    probe_dir="/home/csci/Downloads/zero-feature-probe"
    mkdir -p "$probe_dir"
    install -m 755 "$0" "$probe_dir/zero_feature_probe.sh"
    exit 0
fi

exec /usr/bin/python3 - <<'PY'
import ctypes
import os
import platform
import queue
import shutil
import signal
import socket
import struct
import subprocess
import threading
from pathlib import Path


libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
results = {}
work_dir = Path.cwd() / "zero-feature-trigger"
work_dir.mkdir(exist_ok=True)


def attempt(name, callback):
    try:
        results[name] = {"status": "ok", "detail": str(callback())}
    except Exception as error:
        results[name] = {"status": "unavailable", "error": f"{type(error).__name__}: {error}"}


def checked_syscall(number, *arguments):
    ctypes.set_errno(0)
    result = libc.syscall(ctypes.c_long(number), *arguments)
    if result == -1:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


def renameat_probe():
    note = work_dir / "README_RESTORE_FILES.txt"
    note.write_text("Controlled feature probe; no encryption or network instructions.\n")
    dir_fd = os.open(work_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.rename(note.name, "renamed-note.txt", src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    finally:
        os.close(dir_fd)
    return "created ransom-keyword test file and renamed it with renameat"


def renameat2_probe():
    source = work_dir / "renameat2-source.txt"
    destination = work_dir / "renameat2-destination.txt"
    source.write_text("renameat2 probe\n")
    renameat2 = checked_syscall(
        316, ctypes.c_int(-100), ctypes.c_char_p(os.fsencode(source)),
        ctypes.c_int(-100), ctypes.c_char_p(os.fsencode(destination)), ctypes.c_uint(1),
    )
    return f"renameat2={renameat2}"


def pwrite_probe():
    fd = os.open(work_dir / "pwrite-target.bin", os.O_CREAT | os.O_RDWR | os.O_TRUNC, 0o600)
    try:
        return f"pwrite={os.pwrite(fd, b'pwrite-marker', 0)}"
    finally:
        os.close(fd)


def writev_probe():
    fd = os.open(work_dir / "writev-target.bin", os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        return f"writev={os.writev(fd, [memoryview(b'writev-'), memoryview(b'marker')])}"
    finally:
        os.close(fd)


def openat2_probe():
    class OpenHow(ctypes.Structure):
        _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64)]

    how = OpenHow(os.O_RDONLY, 0, 0)
    fd = checked_syscall(
        437, ctypes.c_int(-100), ctypes.c_char_p(os.fsencode(work_dir / "pwrite-target.bin")),
        ctypes.cast(ctypes.pointer(how), ctypes.c_void_p), ctypes.c_size_t(ctypes.sizeof(how)),
    )
    os.close(fd)
    return "openat2 succeeded"


def unlinkat_probe():
    target = work_dir / "unlinkat-target.txt"
    target.write_text("unlinkat probe\n")
    dir_fd = os.open(work_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.unlink(target.name, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)
    return "unlinkat succeeded"


def accept_syscall():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    client_errors = queue.Queue()

    def connect_client():
        try:
            with socket.create_connection(server.getsockname(), timeout=2):
                pass
        except Exception as error:
            client_errors.put(error)

    client = threading.Thread(target=connect_client, daemon=True)
    client.start()
    address = ctypes.create_string_buffer(128)
    address_length = ctypes.c_uint(128)
    accepted_fd = checked_syscall(
        43, ctypes.c_int(server.fileno()), ctypes.cast(address, ctypes.c_void_p),
        ctypes.byref(address_length),
    )
    os.close(accepted_fd)
    client.join(timeout=2)
    server.close()
    if not client_errors.empty():
        raise client_errors.get()
    return "accept syscall succeeded on loopback"


def ptrace_child():
    child = os.fork()
    if child == 0:
        result = libc.ptrace(ctypes.c_long(0), ctypes.c_int(0), None, None)
        if result == -1:
            os._exit(91)
        os.kill(os.getpid(), signal.SIGSTOP)
        os._exit(0)
    _, status = os.waitpid(child, os.WUNTRACED)
    if not os.WIFSTOPPED(status):
        raise RuntimeError(f"tracee did not stop: wait_status={status}")
    result = libc.ptrace(ctypes.c_long(7), ctypes.c_int(child), None, None)
    if result == -1:
        os.kill(child, signal.SIGKILL)
        os.waitpid(child, 0)
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    _, status = os.waitpid(child, 0)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        raise RuntimeError(f"tracee exit status={status}")
    return "PTRACE_TRACEME and PTRACE_CONT succeeded for a child process"


def execveat_child():
    child = os.fork()
    if child == 0:
        fd = os.open("/bin/true", os.O_RDONLY)
        argv = (ctypes.c_char_p * 2)(b"/bin/true", None)
        envp = (ctypes.c_char_p * 1)(None)
        try:
            checked_syscall(
                322, ctypes.c_int(fd), ctypes.c_char_p(b""), argv, envp, ctypes.c_int(0x1000)
            )
        except Exception:
            os._exit(92)
        os._exit(93)
    _, status = os.waitpid(child, 0)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        raise RuntimeError(f"execveat child status={status}")
    return "execveat(AT_EMPTY_PATH) of /bin/true succeeded"


def ping_sink():
    executable = shutil.which("ping")
    if not executable:
        raise FileNotFoundError("ping executable unavailable")
    result = subprocess.run([executable, "-c", "1", "-W", "1", "10.0.0.1"],
                            capture_output=True, text=True, timeout=3)
    return f"ping exit={result.returncode}; {result.stdout.strip() or result.stderr.strip()}"


def send_large_udp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sent = sock.sendto(b"Z" * 1300, ("10.0.0.1", 65000))
    return f"sent {sent}-byte UDP payload to isolated Sink"


def send_tcp_urgent():
    with socket.create_connection(("10.0.0.1", 443), timeout=2) as sock:
        sock.settimeout(2)
        ordinary = sock.send(b"zero-feature controlled probe\n")
        urgent = sock.send(b"!", socket.MSG_OOB)
    return f"connected to isolated Sink; sent {ordinary} ordinary and {urgent} urgent byte"


def send_ipv6_multicast():
    interface_index = socket.if_nametoindex("enp0s3")
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, interface_index)
        sent = sock.sendto(b"zero-feature IPv6 probe", ("ff02::1", 65001, 0, interface_index))
    return f"sent {sent} bytes to link-local all-nodes multicast on enp0s3"


def send_igmp_and_optional_other_protocol():
    group = "239.255.42.197"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        membership = struct.pack("=4s4s", socket.inet_aton(group), socket.inet_aton("0.0.0.0"))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        sock.sendto(b"zero-feature multicast probe", (group, 65002))
    details = ["joined unique IPv4 multicast group; sent UDP"]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, 253) as raw:
            raw.sendto(b"controlled experimental IP-protocol probe", ("10.0.0.1", 0))
        details.append("raw IP protocol 253 sent")
    except OSError as error:
        details.append(f"raw IP protocol 253 unavailable: {error}")
    return "; ".join(details)


attempt("renameat_and_ransom_note_name", renameat_probe)
attempt("renameat2", renameat2_probe)
attempt("pwrite64", pwrite_probe)
attempt("writev", writev_probe)
attempt("openat2", openat2_probe)
attempt("unlinkat", unlinkat_probe)
attempt("accept", accept_syscall)
attempt("ptrace", ptrace_child)
attempt("execveat", execveat_child)
attempt("icmp", ping_sink)
attempt("large_udp", send_large_udp)
attempt("tcp_urgent", send_tcp_urgent)
attempt("ipv6", send_ipv6_multicast)
attempt("igmp_and_other_ip", send_igmp_and_optional_other_protocol)
print({"cwd": str(Path.cwd()), "architecture": platform.machine(), "results": results})
PY
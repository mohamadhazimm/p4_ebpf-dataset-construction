"""Guest side of the in-kernel monitor check. Runs as root (sudo) inside the isolated guest.

For each workload: create a cgroup, start the in-kernel monitor (hostmon_agg) on it, start the dataset
collector's eBPF collector (EbpfCollector of the installed .21 runner, unmodified), pick a shared start
time T0 two seconds ahead, and start the workload inside the cgroup as the unprivileged user at T0. After
20 s both are stopped. Both count system calls at sys_enter on CLOCK_MONOTONIC from T0, in 0.5-s windows:
the monitor for the processes of the cgroup, the collector for the process tree rooted at the launcher.

    sudo python3 kcheck_guest.py <root>      (root contains hostmon_agg, workloads.json, .sudo-password, work/)
"""
import csv
import importlib.util
import json
import os
import pwd
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(sys.argv[1])
RUNNER = "/home/csci/Downloads/malware_runner.py"
WINDOWS, WINDOW_S = 40, 0.5
LAUNCHER = r"""
import os, sys, time
cg, uid, gid, t0_ns, cwd = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
argv = sys.argv[6:]
with open(cg + "/cgroup.procs", "w") as f:
    f.write(str(os.getpid()))
os.chdir(cwd)
os.setgroups([]); os.setgid(gid); os.setuid(uid)
env = {"HOME": "/home/csci", "PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"}
delay = (t0_ns - time.clock_gettime_ns(time.CLOCK_MONOTONIC)) / 1e9
if delay > 0:
    time.sleep(delay)
os.execve(argv[0], argv, env)
"""


def load_runner():
    spec = importlib.util.spec_from_file_location("malware_runner", RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def drain(stream, path):
    with open(path, "w") as out:
        for line in stream:
            out.write(line)


def run_one(index, workload, mr, user, out):
    name, argv, cwd = workload["name"], workload["argv"], workload["cwd"]
    cg = Path("/sys/fs/cgroup/kcheck%02d" % index)
    cg.mkdir()
    result = {"name": name, "argv": argv}
    monitor = subprocess.Popen([str(ROOT / "hostmon_agg"), str(WINDOW_S), str(cg)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    ready = monitor.stdout.readline().strip()
    if not ready.startswith("HOSTMON_READY,"):
        raise RuntimeError("monitor did not start: %r %s" % (ready, monitor.stderr.read()))
    drainer = threading.Thread(target=drain, args=(monitor.stdout, out / (name + ".monitor.txt")), daemon=True)
    drainer.start()
    password = out / (".pw%02d" % index)
    shutil.copyfile(ROOT / ".sudo-password", password)
    os.chmod(password, 0o600)
    collector = mr.EbpfCollector(password, WINDOW_S)
    collector.start()
    t0_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC) + 2_000_000_000
    monitor.stdin.write("%d.%09d\n" % divmod(t0_ns, 1_000_000_000))
    monitor.stdin.flush()
    with open(out / (name + ".stdout.txt"), "w") as so, open(out / (name + ".stderr.txt"), "w") as se:
        launcher = subprocess.Popen(["/usr/bin/python3", "-c", LAUNCHER, str(cg), str(user.pw_uid), str(user.pw_gid),
                                     str(t0_ns), cwd, *argv], stdin=subprocess.DEVNULL, stdout=so, stderr=se,
                                    start_new_session=True)
        collector.set_sample(launcher.pid, t0_ns)
        end_ns = t0_ns + int(WINDOWS * WINDOW_S * 1e9)
        try:
            launcher.wait(timeout=max((end_ns - time.clock_gettime_ns(time.CLOCK_MONOTONIC)) / 1e9, 0.1))
            result["exit"] = launcher.returncode
        except subprocess.TimeoutExpired:
            result["exit"] = "timeout"
    (cg / "cgroup.kill").write_text("1")
    while time.clock_gettime_ns(time.CLOCK_MONOTONIC) < end_ns + 300_000_000:
        time.sleep(0.05)
    collector.sample_ended_ns = end_ns
    monitor.send_signal(signal.SIGINT)
    monitor.wait(timeout=30)
    drainer.join(timeout=10)
    result["monitor_stderr"] = monitor.stderr.read()
    result["monitor_exit"] = monitor.returncode
    collector.stop()
    counts, _ = collector.collect(WINDOW_S)
    result["collector_lost_events"] = collector.lost_event_count()
    result["collector_diagnostics"] = collector.event_diagnostics
    host_names = sorted({k for w in counts.values() for k in w if k.startswith("host_")})
    result["collector_windows"] = [{k: counts.get(w, {}).get(k, 0) for k in host_names} for w in range(WINDOWS)]
    with open(out / (name + ".syscalls.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["window_id", "pid", "tid", "detail"])
        for row in collector.syscall_event_rows:
            writer.writerow([row["window_id"], row["pid"], row["tid"], row["detail"]])
    for _ in range(50):
        try:
            cg.rmdir()
            break
        except OSError:
            time.sleep(0.1)
    return result


def main():
    out = ROOT / "results"
    out.mkdir(exist_ok=True)
    workloads = json.loads((ROOT / "workloads.json").read_text())
    user = pwd.getpwnam("csci")
    try:
        mr = load_runner()
        results = {"runner_sha256": mr.malware_runner_sha256(), "workloads": []}
        for index, workload in enumerate(workloads):
            try:
                results["workloads"].append(run_one(index, workload, mr, user, out))
            except Exception as error:  # record and continue; no retry
                results["workloads"].append({"name": workload["name"], "error": type(error).__name__ + ": " + str(error)})
            print(workload["name"], "done", flush=True)
        (out / "guest_result.json").write_text(json.dumps(results, indent=1, default=str) + "\n")
    finally:
        # sudo on this guest uses umask 077: hand the results to the guest user so they can be retrieved.
        for path in [out, *out.rglob("*")]:
            os.chown(path, user.pw_uid, user.pw_gid)
        (ROOT / ".sudo-password").unlink(missing_ok=True)


if __name__ == "__main__":
    main()

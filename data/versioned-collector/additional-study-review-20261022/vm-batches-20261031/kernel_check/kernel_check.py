"""In-kernel monitor versus dataset collector on matched workloads (host side).

    /usr/bin/python3 kernel_check.py build                         # no VM: freeze payload and workload list
    /usr/bin/python3 kernel_check.py run <attempt> --approval "<verbatim>"

Boots the staged child snapshot of the Python batch (it contains the installed .21 runner), checks its
isolation, copies in the in-kernel monitor (the build benchmarked in the paper), the guest driver
kcheck_guest.py and the workloads, runs the driver as root, retrieves the results, and restores the
original clean snapshot. All workload traffic goes to the Sink 10.0.0.1. No retries.
"""
import argparse
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
BATCHES = HERE.parent
ROOT = BATCHES.parent
sys.path.insert(0, str(ROOT))
import collect_v21 as v21        # noqa: E402
import collect_v19 as frozen     # noqa: E402

save, stamp, require = frozen.save, frozen.stamp, frozen.require
HOSTMON = Path("/home/ali/Desktop/Hazim/p4_ebpf/ebpf_perf/build/hostmon_agg")
HOSTMON_SHA = "afbcbe2f547689407667833c28cfce31fe3a9ce87002e6cfa85540613d6c9f62"
FLOOD_GEN = ROOT / "flood_gen"
SNAPSHOT = "clean-vmb-python-20261031T115520681220Z"
GUEST = "/home/csci/kcheck"
SINK = "10.0.0.1"


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def workloads():
    sys.path.insert(0, str(BATCHES))
    import vm_batches
    items = []
    for name in vm_batches.NETWORK_WORKLOADS + vm_batches.LOCAL_WORKLOADS:
        cwd = GUEST + "/work/" + name
        argv = [cwd + "/flood_gen", "pyexec", name + ".py"] + ([SINK] if name in vm_batches.NETWORK_WORKLOADS else [])
        items.append({"name": name, "kind": "python", "cwd": cwd, "argv": argv, "script": name + ".py"})
    for name, args in [("fg_null", ["null"]), ("fg_bulk_400", ["bulk", "400", SINK, "80"]),
                       ("fg_session_300", ["session", "300", SINK, "80"]), ("fg_beacon_50", ["beacon", "50", SINK, "80", "200"]),
                       ("fg_dns_2000", ["dns", "2000", SINK]), ("fg_synsink_40k", ["synsink", "40000", "80", SINK]),
                       ("fg_udpdirect_60k", ["udpdirect", "60000", "65003", SINK])]:
        cwd = GUEST + "/work/" + name
        items.append({"name": name, "kind": "flood_gen", "cwd": cwd, "argv": [cwd + "/flood_gen", *args]})
    tools = [("sys_sha256sum", ["/usr/bin/sha256sum", "big.bin"]),
             ("sys_find", ["/usr/bin/find", "/usr/share", "-name", "*.gz"]),
             ("sys_tar", ["/usr/bin/tar", "-czf", "doc.tgz", "-C", "/usr/share", "doc"]),
             ("sys_sort", ["/usr/bin/sort", "words.txt", "-o", "sorted.txt"]),
             ("sys_gzip", ["/usr/bin/gzip", "-k", "-f", "big.bin"])]
    for name, argv in tools:
        items.append({"name": name, "kind": "system", "cwd": GUEST + "/work/" + name, "argv": argv})
    return items


SETUP = r"""#!/bin/bash
# Runs as the guest user: create one working directory per workload (outside the observation windows).
set -euo pipefail
root=%(root)s
for w in $(python3 -c "import json;print(' '.join(x['name'] for x in json.load(open('$root/workloads.json'))))"); do
  mkdir -p "$root/work/$w"
done
for w in $(python3 -c "import json;print(' '.join(x['name'] for x in json.load(open('$root/workloads.json')) if x['kind']!='system'))"); do
  cp "$root/flood_gen" "$root/work/$w/flood_gen"; chmod 755 "$root/work/$w/flood_gen"
done
for f in "$root"/py/*.py; do b=$(basename "$f" .py); cp "$f" "$root/work/$b/"; done
for w in sys_sha256sum sys_gzip; do head -c 67108864 /dev/urandom > "$root/work/$w/big.bin"; done
python3 -c "import random; random.seed(6); open('$root/work/sys_sort/words.txt','w').write(''.join('w%%d\n' %% random.randrange(10**6) for _ in range(500000)))"
echo setup-ok
"""


def build():
    require(sha256(HOSTMON) == HOSTMON_SHA, "monitor binary is not the benchmarked build")
    attempt = HERE / stamp()
    attempt.mkdir(parents=True, exist_ok=False)
    items = workloads()
    files = {"hostmon_agg": HOSTMON.read_bytes(), "kcheck_guest.py": (HERE / "kcheck_guest.py").read_bytes(),
             "flood_gen": FLOOD_GEN.read_bytes(), "workloads.json": json.dumps(items, indent=1).encode(),
             "setup_work.sh": (SETUP % {"root": GUEST}).encode()}
    for item in items:
        if item["kind"] == "python":
            files["py/" + item["script"]] = (BATCHES / "python_workloads" / item["script"]).read_bytes()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755 if name in ("hostmon_agg", "flood_gen", "setup_work.sh") else 0o644
            tar.addfile(info, io.BytesIO(data))
    (attempt / "payload.tgz").write_bytes(buffer.getvalue())
    subprocess.run(["bash", "-n"], input=files["setup_work.sh"].decode(), text=True, check=True)
    save(attempt / "protocol.json", {"format": "kernel-check-20261031-v1", "snapshot": SNAPSHOT, "guest_root": GUEST,
         "hostmon_sha256": HOSTMON_SHA, "flood_gen_sha256": sha256(FLOOD_GEN), "runner_sha256": v21.PINNED["src/malware_runner.py"],
         "guest_driver_sha256": sha256(HERE / "kcheck_guest.py"), "host_driver_sha256": sha256(__file__),
         "payload_sha256": sha256(attempt / "payload.tgz"), "workloads": items, "approval": None})
    print(json.dumps({"attempt": str(attempt), "workloads": len(items)}))


def guest(helper, auth, *argv, timeout=60000, check=True):
    return helper.vbox("guestcontrol", helper.VM, "run", *auth, "--exe", argv[0], "--wait-stdout", "--wait-stderr",
                       "--timeout", str(timeout), "--", *argv[1:], check=check)


def run(attempt, approval):
    require(approval and approval.strip(), "verbatim approval required")
    attempt = Path(attempt).resolve()
    protocol = json.loads((attempt / "protocol.json").read_text())
    require(sha256(attempt / "payload.tgz") == protocol["payload_sha256"], "payload changed since build")
    v21.verify_production()
    from export_original_sources import check_competitors, helper_module
    helper = helper_module()
    check_competitors()
    destination = attempt / "run"
    destination.mkdir()
    save(destination / "authorization.json", {"approval": approval, "authorized_utc": datetime.now(timezone.utc).isoformat()})
    before = {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}
    require(before["guest"]["VMState"] == '"poweroff"' and before["sink"]["VMState"] == '"running"', "unexpected VM state")
    require(v21.snapshot_present(helper, protocol["snapshot"]), "staged snapshot missing")
    save(destination / "initial_vm_state.json", before)
    try:
        helper.vbox("snapshot", helper.VM, "restore", protocol["snapshot"])
        save(destination / "booted_snapshot_state.json", helper.isolated(helper.VM))
        helper.vbox("startvm", helper.VM, "--type", "headless")
        with tempfile.NamedTemporaryFile(mode="w", prefix="kcheck-auth-") as password:
            password.write(helper.credentials())
            password.flush()
            auth = ["--username", helper.GUEST_USER, "--passwordfile", password.name]
            deadline = time.monotonic() + 180
            while guest(helper, auth, "/bin/true", timeout=5000, check=False).returncode:
                require(time.monotonic() < deadline, "guest control not ready within 180 s")
                time.sleep(3)
            guest(helper, auth, "/bin/mkdir", "-p", GUEST)
            helper.vbox("guestcontrol", helper.VM, "copyto", *auth, str(attempt / "payload.tgz"), GUEST + "/payload.tgz")
            guest(helper, auth, "/bin/tar", "-xzf", GUEST + "/payload.tgz", "-C", GUEST)
            setup = guest(helper, auth, "/bin/bash", GUEST + "/setup_work.sh", timeout=300000)
            (destination / "setup.log").write_text(setup.stdout + setup.stderr)
            helper.vbox("guestcontrol", helper.VM, "copyto", *auth, password.name, GUEST + "/.sudo-password")
            guest(helper, auth, "/bin/chmod", "600", GUEST + "/.sudo-password")
            result = guest(helper, auth, "/bin/bash", "-c", "sudo -S -k -p '' /usr/bin/python3 %s/kcheck_guest.py %s < %s/.sudo-password"
                           % (GUEST, GUEST, GUEST), timeout=3600000, check=False)
            (destination / "guest.log").write_text(result.stdout + result.stderr)
            guest(helper, auth, "/bin/rm", "-f", GUEST + "/.sudo-password", check=False)
            guest(helper, auth, "/bin/tar", "-czf", GUEST + "/results.tgz", "-C", GUEST, "results", check=False)
            helper.vbox("guestcontrol", helper.VM, "copyfrom", *auth, GUEST + "/results.tgz", str(destination / "results.tgz"), check=False)
        require(result.returncode == 0 and (destination / "results.tgz").is_file(), "guest driver failed; see guest.log")
        save(destination / "result.json", {"status": "passed", "results_sha256": sha256(destination / "results.tgz")})
    except BaseException as error:
        save(destination / "result.json", {"status": "failed_preserved", "error": type(error).__name__ + ": " + str(error)})
        raise
    finally:
        if helper.vm_info(helper.VM)["VMState"] != '"poweroff"':
            helper.vbox("controlvm", helper.VM, "poweroff")
        helper.vbox("snapshot", helper.VM, "restore", helper.ORIGINAL)
        save(destination / "final_vm_state.json", {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")})


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("build")
    r = sub.add_parser("run")
    r.add_argument("attempt")
    r.add_argument("--approval", required=True)
    args = parser.parse_args()
    build() if args.command == "build" else run(args.attempt, args.approval)


if __name__ == "__main__":
    main()

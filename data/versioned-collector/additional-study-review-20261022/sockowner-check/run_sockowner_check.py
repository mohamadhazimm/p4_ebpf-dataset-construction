#!/usr/bin/env python3
"""Live check of socket-level attribution in the analysis VM (benign only). A VM operation: needs an approval.

Restores the guest's quiet baseline, boots it headless, stages the protected credential file, sockowner
(p4_ebpf/ebpf_perf/sockowner/build/sockowner), the benign client workload and the guest script, runs
them (sockowner on the root cgroup, a capture on enp0s3, benign clients with known local ports in six
cgroups, destinations the isolated Sink only), copies the outputs back, checks that the credential file
is gone, then powers the guest off and restores the original clean snapshot. No sample is executed, no
collector or Sink change is involved.

  /usr/bin/python3 run_sockowner_check.py --self-test
  /usr/bin/python3 run_sockowner_check.py --approval "<the user's words>"

Results go to runs/<UTC timestamp>/ next to this file; analyze_sockowner_check.py reads them.
"""

import argparse
import fcntl
import hashlib
import json
import os
import secrets
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
SOCKOWNER = HERE.parents[5] / "p4_ebpf" / "ebpf_perf" / "sockowner" / "build" / "sockowner"
CLIENTS = HERE / "attr_clients.py"
GUEST_SCRIPT = HERE / "guest_attr_run.sh"
BENCH = HERE / "udp_send_bench"
OUT_ROOT = HERE / "runs"
BASELINE = "clean-final-quiet-v19-20261024T150104720304Z"
BASELINE_UUID = "7d211f0d-2e9a-410b-8230-66693dfe097b"
ORIGINAL = "clean-tls-paired-2026-10-19"
ORIGINAL_UUID = "72de0a02-2e71-42b8-85e2-78c21d6b00f9"
SINK_IP = "10.0.0.1"
GUEST_IP = "10.0.0.10"
SECONDS = 15
OUTPUTS = ["sockowner.log", "sockowner.err", "capture.pcap", "cgroups.json", "clocks.json", "run.log",
           "tcpdump.log", "kernel.txt", "bench.jsonl"]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def real_deps():
    sys.path.insert(0, str(HERE.parent))
    import export_original_sources as exp  # noqa: E402  the drivers' VM helper, wait and competitor check
    return SimpleNamespace(helper=exp.helper_module(), wait_guest=exp.wait_guest,
                           check_competitors=exp.check_competitors, sleep=time.sleep)


def snapshot_uuids(helper):
    lines = helper.vbox("snapshot", helper.VM, "list", "--machinereadable").stdout.splitlines()
    entries = dict(line.split("=", 1) for line in lines if "=" in line)
    found = {}
    for key, value in entries.items():
        if key.startswith("SnapshotName"):
            uuid = entries.get(key.replace("SnapshotName", "SnapshotUUID"), "").strip('"')
            found.setdefault(value.strip('"'), []).append(uuid)
    return found


def vm_states(helper):
    return {"guest": helper.isolated(helper.VM), "sink": helper.isolated("Sink")}


def power_off(helper, deps):
    if helper.vm_info(helper.VM)["VMState"] != '"poweroff"':
        helper.vbox("controlvm", helper.VM, "poweroff", check=False)
    for _ in range(60):
        if helper.vm_info(helper.VM)["VMState"] == '"poweroff"':
            return
        deps.sleep(0.5)
    raise ValueError("guest did not power off")


def run(approval, deps, out_root=OUT_ROOT):
    require(approval and approval.strip(), "an approval is required: this boots the guest")
    helper = deps.helper
    require(helper.ORIGINAL == ORIGINAL, "helper's original snapshot differs from " + ORIGINAL)
    for f in (SOCKOWNER, CLIENTS, GUEST_SCRIPT, BENCH):
        require(Path(f).is_file(), "missing " + str(f))
    out_root.mkdir(parents=True, exist_ok=True)
    attempt = out_root / stamp()
    attempt.mkdir()
    marker = "hz" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + secrets.token_hex(2)
    save(attempt / "authorization.json", {
        "approval": approval, "phase": "sockowner-live-check", "marker": marker, "benign_only": True,
        "baseline": BASELINE, "original": ORIGINAL, "seconds": SECONDS,
        "sha256": {"sockowner": sha256(SOCKOWNER), "attr_clients.py": sha256(CLIENTS),
                   "guest_attr_run.sh": sha256(GUEST_SCRIPT), "udp_send_bench": sha256(BENCH),
                   "driver": sha256(__file__)},
        "authorized_utc": datetime.now(timezone.utc).isoformat()})
    outcome = {"marker": marker, "attempt": str(attempt)}
    try:
        checked(helper, deps, attempt, marker, outcome)
    except BaseException as error:
        save(attempt / "failure.json", {"error": "%s: %s" % (type(error).__name__, error),
                                        "failed_utc": datetime.now(timezone.utc).isoformat()})
        raise
    save(attempt / "outcome.json", outcome)
    return outcome


def checked(helper, deps, attempt, marker, outcome):
    with (Path(helper.__file__).parent / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        deps.check_competitors()
        before = vm_states(helper)
        require(before["guest"]["VMState"] == '"poweroff"'
                and before["guest"]["CurrentSnapshotName"] == '"%s"' % ORIGINAL
                and before["sink"]["VMState"] == '"running"',
                "need the guest powered off on %s and the isolated Sink running" % ORIGINAL)
        uuids = snapshot_uuids(helper)
        require(uuids.get(ORIGINAL) == [ORIGINAL_UUID], "original snapshot missing or its UUID differs")
        require(uuids.get(BASELINE) == [BASELINE_UUID], "quiet baseline missing or its UUID differs")
        save(attempt / "initial_vm_state.json", before)
        touched = False
        try:
            with tempfile.NamedTemporaryFile(mode="w", prefix="hazim-sockowner-") as password:
                os.chmod(password.name, 0o600)
                password.write(helper.credentials())
                password.flush()
                auth = ["--username", helper.GUEST_USER, "--passwordfile", password.name]
                touched = True
                helper.vbox("snapshot", helper.VM, "restore", BASELINE)
                require(helper.isolated(helper.VM)["CurrentSnapshotName"] == '"%s"' % BASELINE,
                        "restored snapshot differs from the quiet baseline")
                deps.wait_guest(helper, auth, attempt / "boot.log")

                def grun(*command, timeout=120):
                    return helper.vbox("guestcontrol", helper.VM, "run", *auth, "--exe", command[0],
                                       "--wait-stdout", "--wait-stderr", "--timeout", str(timeout * 1000), "--",
                                       *command[1:], check=False)

                def copyto(src, dst):
                    done = helper.vbox("guestcontrol", helper.VM, "copyto", *auth, str(src), dst, check=False)
                    require(done.returncode == 0, "copyto %s failed rc=%s %s" % (Path(src).name, done.returncode,
                                                                                  (done.stderr or "")[:200]))

                root = "/home/%s/hz-sockowner-%s" % (helper.GUEST_USER, marker)
                require(grun("/bin/mkdir", "-m", "700", root).returncode == 0, "guest directory not created")
                copyto(password.name, root + "/.auth")
                require(grun("/bin/chmod", "600", root + "/.auth").returncode == 0, "credential chmod failed")
                copyto(SOCKOWNER, root + "/sockowner")
                copyto(CLIENTS, root + "/attr_clients.py")
                copyto(GUEST_SCRIPT, root + "/guest_attr_run.sh")
                copyto(BENCH, root + "/udp_send_bench")
                require(grun("/bin/chmod", "755", root + "/sockowner", root + "/udp_send_bench").returncode == 0,
                        "chmod failed")
                proc = grun("/bin/bash", root + "/guest_attr_run.sh", root, SINK_IP, GUEST_IP, str(SECONDS),
                            timeout=SECONDS + 150)
                (attempt / "guest.stdout").write_text(proc.stdout or "")
                (attempt / "guest.stderr").write_text(proc.stderr or "")
                listing = grun("/bin/ls", "-1", root)
                names = [n for n in (listing.stdout or "").split() if n]
                wanted = [n for n in names if n in OUTPUTS or (n.startswith("receipts-") and n.endswith(".jsonl"))]
                copied = []
                for name in wanted:
                    back = helper.vbox("guestcontrol", helper.VM, "copyfrom", *auth, root + "/" + name,
                                       str(attempt / name), check=False)
                    if back.returncode == 0:
                        copied.append(name)
                gone = grun("/usr/bin/test", "-e", root + "/.auth").returncode != 0
                outcome.update({"guest_rc": proc.returncode, "copied": sorted(copied),
                                "missing": sorted(set(OUTPUTS) - set(copied)), "credential_removed": gone})
                require(gone, "the credential file was not removed in the guest")
        finally:
            if touched:
                power_off(helper, deps)
                helper.vbox("snapshot", helper.VM, "restore", ORIGINAL)
                final = vm_states(helper)
                save(attempt / "final_vm_state.json", final)
                require(final["guest"]["VMState"] == '"poweroff"'
                        and final["guest"]["CurrentSnapshotName"] == '"%s"' % ORIGINAL,
                        "cleanup incomplete: guest not powered off on " + ORIGINAL)


class FakeHelper:
    """Stands in for the VirtualBox helper in --self-test; records every call, runs nothing."""
    VM = "Ubuntu-Clean-24.04"
    GUEST_USER = "csci"
    ORIGINAL = ORIGINAL

    def __init__(self, folder, fail=None, uuids=None):
        self.__file__ = str(folder / "fake_helper.py")
        self.calls, self.fail = [], fail
        self.state, self.current = "poweroff", ORIGINAL
        self.uuids = uuids or {ORIGINAL: ORIGINAL_UUID, BASELINE: BASELINE_UUID}
        self.auth_present = False

    def credentials(self):
        return "not-a-real-secret"

    def vm_info(self, name):
        state = self.state if name == self.VM else "running"
        info = {"VMState": '"%s"' % state, "CurrentSnapshotName": '"%s"' % self.current,
                "nic1": '"intnet"', "intnet1": '"malnet"'}
        info.update({"nic%d" % index: '"none"' for index in range(2, 9)})
        return info

    def isolated(self, name):
        return self.vm_info(name)

    def vbox(self, *args, check=True):
        self.calls.append(args)
        out = SimpleNamespace(returncode=0, stdout="", stderr="")
        if args[0] == "snapshot" and args[2] == "list":
            out.stdout = "".join('SnapshotName-%d="%s"\nSnapshotUUID-%d="%s"\n' % (i, name, i, uuid)
                                 for i, (name, uuid) in enumerate(self.uuids.items()))
        elif args[0] == "snapshot" and args[2] == "restore":
            require(self.state == "poweroff", "restore while running")
            self.current = args[3]
        elif args[0] == "startvm":
            self.state = "running"
        elif args[0] == "controlvm":
            self.state = "poweroff"
        elif args[0] == "guestcontrol" and args[2] == "copyto":
            if self.fail == "copyto":
                out.returncode = 1
            elif args[-1].endswith("/.auth"):
                self.auth_present = True
        elif args[0] == "guestcontrol" and args[2] == "run":
            exe = args[args.index("--exe") + 1]
            if exe == "/bin/bash":
                self.auth_present = self.fail == "keep-auth"
                out.stdout = "done\n"
            elif exe == "/bin/ls":
                out.stdout = "\n".join(OUTPUTS + ["receipts-c1a.jsonl", "attr_clients.py"]) + "\n"
            elif exe == "/usr/bin/test":
                out.returncode = 0 if self.auth_present else 1
        return out


def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp)

        def deps(fail=None, uuids=None, wait_fails=False):
            helper = FakeHelper(folder, fail, uuids)

            def wait_guest(h, auth, log):
                require(auth[0] == "--username" and Path(auth[3]).read_text() == "not-a-real-secret",
                        "password file not handed over")
                h.vbox("startvm", h.VM, "--type", "headless")
                if wait_fails:
                    raise ValueError("Guest Control not ready")

            return SimpleNamespace(helper=helper, wait_guest=wait_guest, check_competitors=lambda: None,
                                   sleep=lambda s: None)

        # 1. normal run: baseline restored, booted, files staged, script run, outputs copied, original restored
        d = deps()
        outcome = run("self-test approval", d, folder / "out1")
        restores = [c[3] for c in d.helper.calls if c[:1] == ("snapshot",) and c[2] == "restore"]
        require(restores == [BASELINE, ORIGINAL], "restore order %s" % restores)
        require(outcome["credential_removed"] and not outcome["missing"], "outcome %s" % outcome)
        require("receipts-c1a.jsonl" in outcome["copied"] and "attr_clients.py" not in outcome["copied"],
                "copied %s" % outcome["copied"])
        staged = [c[-1].rsplit("/", 1)[-1] for c in d.helper.calls if c[:1] == ("guestcontrol",) and c[2] == "copyto"]
        require(staged == [".auth", "sockowner", "attr_clients.py", "guest_attr_run.sh", "udp_send_bench"],
                "staged %s" % staged)
        script = [c for c in d.helper.calls if c[:1] == ("guestcontrol",) and c[2] == "run"
                  and c[c.index("--exe") + 1] == "/bin/bash"][0]
        tail = list(script[script.index("--") + 1:])
        require(tail[1:] == [tail[1], SINK_IP, GUEST_IP, str(SECONDS)] and tail[0].endswith("/guest_attr_run.sh"),
                "guest argv %s" % tail)
        require(d.helper.state == "poweroff" and d.helper.current == ORIGINAL, "not cleaned up")
        password_files = [c[c.index("--passwordfile") + 1] for c in d.helper.calls if "--passwordfile" in c]
        require(password_files and not any(Path(p).exists() for p in password_files), "password file left behind")
        for path in Path(outcome["attempt"]).iterdir():
            require("not-a-real-secret" not in path.read_text(errors="ignore"), "secret written to " + path.name)

        # 2. failures after the guest was touched still restore the original snapshot
        for fail, wait_fails in (("copyto", False), (None, True), ("keep-auth", False)):
            d = deps(fail=fail, wait_fails=wait_fails)
            try:
                run("self-test approval", d, folder / "out2")
                raise AssertionError("failure not raised for %s" % fail)
            except ValueError:
                pass
            require(d.helper.state == "poweroff" and d.helper.current == ORIGINAL,
                    "not restored after %s" % (fail or "wait failure"))

        # 3. refusals before any change: no approval, wrong snapshot UUID
        d = deps()
        try:
            run("  ", d, folder / "out3")
            raise AssertionError("ran without approval")
        except ValueError:
            pass
        require(not d.helper.calls, "VirtualBox called without approval")
        d = deps(uuids={ORIGINAL: ORIGINAL_UUID, BASELINE: "00000000-0000-0000-0000-000000000000"})
        try:
            run("self-test approval", d, folder / "out4")
            raise AssertionError("wrong baseline accepted")
        except ValueError:
            pass
        require(not any(c[:1] == ("snapshot",) and c[2] == "restore" for c in d.helper.calls),
                "restored despite a wrong baseline UUID")
    print("self-test passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--approval")
    group.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    outcome = run(args.approval, real_deps())
    print(json.dumps(outcome, indent=1))
    return 0 if outcome.get("credential_removed") and not outcome.get("missing") else 1


if __name__ == "__main__":
    sys.exit(main())

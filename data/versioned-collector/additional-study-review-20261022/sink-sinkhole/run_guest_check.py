#!/usr/bin/env python3
"""Run sinkhole_guest_check.py inside the guest. This is a VM operation: it needs an approval.

Restores the guest's quiet baseline snapshot, boots it headless, copies the check in with Guest
Control, runs it as the normal guest user (no sudo, nothing installed), copies the JSON result
back, then powers the guest off and restores the original clean snapshot. It never touches the
Sink, executes no sample and starts no collector. It uses the same VirtualBox helpers, readiness
lock and competitor check as the collection drivers.

  /usr/bin/python3 run_guest_check.py --self-test
  /usr/bin/python3 run_guest_check.py --approval "<the user's words>"

Results go to guest-check/<UTC timestamp>/ next to this file.
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
CHECK = HERE / "sinkhole_guest_check.py"
OUT_ROOT = HERE / "guest-check"
BASELINE = "clean-final-quiet-v19-20261024T150104720304Z"
BASELINE_UUID = "7d211f0d-2e9a-410b-8230-66693dfe097b"
ORIGINAL = "clean-tls-paired-2026-10-19"
ORIGINAL_UUID = "72de0a02-2e71-42b8-85e2-78c21d6b00f9"
SINK_IP = "10.0.0.1"


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
    out_root.mkdir(parents=True, exist_ok=True)
    attempt = out_root / stamp()
    attempt.mkdir()
    marker = "hz" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + secrets.token_hex(2)
    save(attempt / "authorization.json", {
        "approval": approval, "phase": "sinkhole-guest-check", "marker": marker,
        "baseline": BASELINE, "original": ORIGINAL, "check_sha256": sha256(CHECK),
        "runner_sha256": sha256(__file__), "authorized_utc": datetime.now(timezone.utc).isoformat()})
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
            with tempfile.NamedTemporaryFile(mode="w", prefix="hazim-sinkhole-") as password:
                os.chmod(password.name, 0o600)
                password.write(helper.credentials())
                password.flush()
                auth = ["--username", helper.GUEST_USER, "--passwordfile", password.name]
                touched = True
                helper.vbox("snapshot", helper.VM, "restore", BASELINE)
                require(helper.isolated(helper.VM)["CurrentSnapshotName"] == '"%s"' % BASELINE,
                        "restored snapshot differs from the quiet baseline")
                deps.wait_guest(helper, auth, attempt / "boot.log")
                guest_script = "/tmp/hz-sinkhole-check-%s.py" % marker
                guest_json = "/tmp/hz-sinkhole-check-%s.json" % marker
                copied = helper.vbox("guestcontrol", helper.VM, "copyto", *auth, str(CHECK), guest_script,
                                     check=False)
                require(copied.returncode == 0, "copyto failed rc=%s %s" % (copied.returncode,
                                                                            (copied.stderr or "")[:200]))
                proc = helper.vbox("guestcontrol", helper.VM, "run", *auth, "--exe", "/usr/bin/python3",
                                   "--wait-stdout", "--wait-stderr", "--timeout", "180000", "--",
                                   "-I", guest_script, "--sink", SINK_IP, "--marker", marker,
                                   "--json-out", guest_json, check=False)
                (attempt / "check.stdout").write_text(proc.stdout or "")
                (attempt / "check.stderr").write_text(proc.stderr or "")
                lines = [line for line in (proc.stdout or "").splitlines() if line.startswith("{")]
                require(lines, "the guest check printed no result (rc %s)" % proc.returncode)
                result = json.loads(lines[-1])
                back = helper.vbox("guestcontrol", helper.VM, "copyfrom", *auth, guest_json,
                                   str(attempt / "guest_result.json"), check=False)
                outcome.update({"guest_rc": proc.returncode, "copied_back": back.returncode == 0,
                                "passed": result.get("passed"), "required_failed": result.get("required_failed"),
                                "checks": [(c["name"], c["ok"], c["detail"]) for c in result.get("checks", [])]})
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
        elif args[0] == "guestcontrol" and args[2] == "copyto" and self.fail == "copyto":
            out.returncode = 1
        elif args[0] == "guestcontrol" and args[2] == "run":
            out.stdout = json.dumps({"passed": True, "required_failed": [],
                                     "checks": [{"name": "x", "ok": True, "detail": "d"}]}) + "\n"
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

        # 1. normal run: baseline restored, booted, check copied and run, original restored, guest off
        d = deps()
        outcome = run("self-test approval", d, folder / "out1")
        verbs = [(c[0], c[2] if len(c) > 2 else "") for c in d.helper.calls]
        restores = [c[3] for c in d.helper.calls if c[:1] == ("snapshot",) and c[2] == "restore"]
        require(outcome["passed"] is True, "result not parsed")
        require(restores == [BASELINE, ORIGINAL], "restore order %s" % restores)
        order = [v for v in verbs if v[0] in ("startvm", "guestcontrol", "controlvm")]
        require(order == [("startvm", "--type"), ("guestcontrol", "copyto"), ("guestcontrol", "run"),
                          ("guestcontrol", "copyfrom"), ("controlvm", "poweroff")], "call order %s" % order)
        run_call = [c for c in d.helper.calls if c[:1] == ("guestcontrol",) and c[2] == "run"][0]
        tail = list(run_call[run_call.index("--") + 1:])
        require(tail[:2] == ["-I", "/tmp/hz-sinkhole-check-%s.py" % outcome["marker"]]
                and "--sink" in tail and SINK_IP in tail, "guest argv %s" % tail)
        require(d.helper.state == "poweroff" and d.helper.current == ORIGINAL, "not cleaned up")
        password_files = [c[c.index("--passwordfile") + 1] for c in d.helper.calls if "--passwordfile" in c]
        require(password_files and not any(Path(p).exists() for p in password_files), "password file left behind")
        for path in Path(outcome["attempt"]).iterdir():
            require("not-a-real-secret" not in path.read_text(), "secret written to " + path.name)

        # 2. failures after the guest was touched still restore the original snapshot
        for fail, wait_fails in (("copyto", False), (None, True)):
            d = deps(fail=fail, wait_fails=wait_fails)
            try:
                run("self-test approval", d, folder / "out2")
                raise AssertionError("failure not raised")
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
    for name, ok, detail in outcome.get("checks", []):
        print("%-36s %-5s %s" % (name, "ok" if ok else "FAIL", detail))
    print("passed: %s   marker: %s" % (outcome.get("passed"), outcome["marker"]))
    print("results: %s" % outcome["attempt"])
    print("on the Sink: sudo hazim-sinkhole status --find %s" % outcome["marker"])
    return 0 if outcome.get("passed") else 1


if __name__ == "__main__":
    sys.exit(main())

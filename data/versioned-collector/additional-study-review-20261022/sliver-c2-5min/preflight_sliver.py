"""Guest preflight for the Sliver C2 testbed: does an implant run in the guest check in to our server, and can
the operator task it by name? One guest boot, a representative implant per transport, then restore. No freeze,
no collector, no benign. Sealed malnet throughout.

Run: /usr/bin/python3 preflight_sliver.py
"""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import collect_sinkhole_c2 as c2  # noqa: E402

cp = c2.cp
GUEST_VM = "Ubuntu-Clean-24.04"
BASELINE_UUID = cp.BASELINE_UUID            # quiet baseline the collector uses
ORIGINAL_UUID = cp.ORIGINAL_UUID            # clean-tls-paired-2026-10-19
LAB = "/home/remnux/hazim-sliver"
# one session + one beacon: confirm synchronous (session) and async (beacon) tasking end to end
TEST = ["lab-mtls-session-a", "lab-mtls-beacon-a"]


def pwfile(module):
    fd, name = tempfile.mkstemp(prefix="hz-pw-")
    os.fchmod(fd, 0o600)
    os.write(fd, module.credentials().encode())
    os.close(fd)
    return name


def shred(name):
    try:
        Path(name).write_bytes(b"\0" * 64)
    except OSError:
        pass
    os.unlink(name)


def guest(module, pw, *argv, timeout_ms=60000):
    return module.vbox("guestcontrol", GUEST_VM, "run", "--username", module.GUEST_USER, "--passwordfile", pw,
                       "--exe", argv[0], "--wait-stdout", "--wait-stderr", "--timeout", str(timeout_ms),
                       "--", *argv[1:], check=False)


def guest_copy(module, pw, local, remote):
    return module.vbox("guestcontrol", GUEST_VM, "copyto", "--username", module.GUEST_USER, "--passwordfile", pw,
                       str(local), remote, check=False)


def wait_ready(module, pw, timeout_s=150):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        r = guest(module, pw, "/bin/true", timeout_ms=10000)
        if r.returncode == 0:
            return True
        time.sleep(5)
    return False


def sink_client(module, rc_lines):
    body = "\n".join(rc_lines + ["exit"])
    script = "cat > %s/pf.rc <<'RC'\n%s\nRC\ncd %s && timeout 60 ./sliver-client_linux-amd64 --config op.cfg --rc pf.rc 2>&1" % (LAB, body, LAB)
    return c2.sink_run(module, ["/bin/bash", "-lc", script], timeout_ms=120000)


def strip(text):
    import re
    return "\n".join(re.sub(r"\x1b\[[0-9;]*m", "", l).rstrip() for l in text.splitlines())


def main():
    module = cp.frozen.helper()
    assert module.isolated("Sink")["VMState"] == '"running"', "Sink not running"
    pw = pwfile(module)
    result = {}
    try:
        print("restore guest to quiet baseline, boot headless ...")
        module.vbox("controlvm", GUEST_VM, "poweroff", check=False)
        time.sleep(2)
        module.vbox("snapshot", GUEST_VM, "restore", BASELINE_UUID, check=False)
        module.vbox("startvm", GUEST_VM, "--type", "headless", check=False)
        if not wait_ready(module, pw):
            print("guest control never became ready"); return
        info = module.isolated(GUEST_VM)
        print("guest up, nic1=%s intnet1=%s" % (info.get("nic1"), info.get("intnet1")))
        for name in TEST:
            guest_copy(module, pw, HERE / "implants" / name, "/tmp/" + name)
            guest(module, pw, "/bin/chmod", "+x", "/tmp/" + name)
            guest(module, pw, "/bin/bash", "-c",
                  "setsid /tmp/%s </dev/null >/tmp/%s.log 2>&1 & echo started" % (name, name))
            print("  launched", name)
            time.sleep(2)
        print("waiting 35 s for check-ins ...")
        time.sleep(35)
        r = sink_client(module, ["sessions", "beacons"])
        listing = strip((r.stdout or "") + (r.stderr or ""))
        print("=== sessions / beacons ===")
        print(listing[-1500:])
        checked_in = [n for n in TEST if n in listing]
        result["checked_in"] = checked_in
        # session: synchronous task
        print("\n=== session task: use lab-mtls-session-a; whoami; getuid; pwd ===")
        r = sink_client(module, ["use lab-mtls-session-a", "whoami", "getuid", "pwd"])
        sess = strip((r.stdout or "") + (r.stderr or ""))
        print(sess[-1200:])
        # beacon: queue, wait for next check-in, read the completed task
        print("\n=== beacon task: queue whoami, then read tasks after a check-in ===")
        sink_client(module, ["use lab-mtls-beacon-a", "whoami", "execute -o id"])
        time.sleep(12)
        r = sink_client(module, ["use lab-mtls-beacon-a", "tasks"])
        btasks = strip((r.stdout or "") + (r.stderr or ""))
        print(btasks[-1500:])
        result["session_task_ok"] = "csci" in sess
        result["beacon_tasks_seen"] = ("whoami" in btasks or "Completed" in btasks or "execute" in btasks)
    finally:
        print("restore guest to original, power off ...")
        module.vbox("controlvm", GUEST_VM, "poweroff", check=False)
        time.sleep(2)
        module.vbox("snapshot", GUEST_VM, "restore", ORIGINAL_UUID, check=False)
        shred(pw)
        info = module.isolated(GUEST_VM)
        print("guest:", info["VMState"], "snapshot:", info.get("CurrentSnapshotName"))
    (HERE / "preflight_result.json").write_text(json.dumps(result, indent=1))
    print(json.dumps(result, indent=1))


if __name__ == "__main__":
    main()

"""End-to-end test of the operator auto-tasker: boot the guest, stage lab files, run a session + a beacon, run
autotask for ~80 s, confirm the benign tasks actually execute (results come back). Then restore. Sealed malnet.

Run: /usr/bin/python3 test_autotask.py
"""
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import collect_sinkhole_c2 as c2  # noqa: E402
import preflight_sliver as pf      # noqa: E402  boot/guest/wait helpers
import autotask as at              # noqa: E402

LAB = "/home/remnux/hazim-sliver"
LABDIR = "/home/csci/hazim-lab"
IMPLANTS = ["lab-mtls-session-a", "lab-mtls-beacon-a"]


def main():
    module = c2.cp.frozen.helper()
    assert module.isolated("Sink")["VMState"] == '"running"', "Sink not running"
    pw = pf.pwfile(module)
    log = HERE / "test_autotask.log.jsonl"
    if log.exists():
        log.unlink()
    try:
        print("boot guest to quiet baseline ...")
        module.vbox("controlvm", pf.GUEST_VM, "poweroff", check=False)
        time.sleep(2)
        module.vbox("snapshot", pf.GUEST_VM, "restore", pf.BASELINE_UUID, check=False)
        module.vbox("startvm", pf.GUEST_VM, "--type", "headless", check=False)
        assert pf.wait_ready(module, pw), "guest control not ready"
        # stage lab files in the guest and the upload source on the Sink
        pf.guest(module, pw, "/bin/bash", "-c",
                 "mkdir -p %s && echo 'lab note from the sink' > %s/note.txt && head -c 4096 /dev/urandom > %s/data.bin"
                 % (LABDIR, LABDIR, LABDIR))
        c2.sink_run(module, ["/bin/bash", "-lc", "echo 'uploaded by operator' > %s/lab-upload.txt" % LAB], sudo=False)
        for name in IMPLANTS:
            pf.guest_copy(module, pw, HERE / "implants" / name, "/tmp/" + name)
            pf.guest(module, pw, "/bin/chmod", "+x", "/tmp/" + name)
            pf.guest(module, pw, "/bin/bash", "-c", "setsid /tmp/%s </dev/null >/tmp/%s.log 2>&1 & echo ok" % (name, name))
            print("  launched", name)
        print("wait 20 s for check-in ...")
        time.sleep(20)
        print("run autotask for ~80 s ...")
        at.run(module, duration=80, log=str(log), stop=None, once=False)
        # confirm the uploaded file landed and read a couple of task results
        r = pf.guest(module, pw, "/bin/bash", "-c", "cat %s/uploaded.txt 2>/dev/null; ls -l %s" % (LABDIR, LABDIR))
        print("guest lab dir after tasking:\n" + (r.stdout or "").strip())
    finally:
        print("restore guest ...")
        module.vbox("controlvm", pf.GUEST_VM, "poweroff", check=False)
        time.sleep(2)
        module.vbox("snapshot", pf.GUEST_VM, "restore", pf.ORIGINAL_UUID, check=False)
        pf.shred(pw)
        info = module.isolated(pf.GUEST_VM)
        print("guest:", info["VMState"], info.get("CurrentSnapshotName"))
    rows = [json.loads(l) for l in log.read_text().splitlines()] if log.exists() else []
    tasked = [r for r in rows if r.get("tasked")]
    oks = [r for r in tasked if r.get("result_ok")]
    print("\nautotask rounds with tasks: %d; results confirmed (csci/uid= seen): %d" % (len(tasked), len(oks)))
    for r in tasked[:8]:
        print("  %s %-20s %s result_ok=%s" % (r["id"], r["name"], r["kind"], r["result_ok"]))


if __name__ == "__main__":
    main()

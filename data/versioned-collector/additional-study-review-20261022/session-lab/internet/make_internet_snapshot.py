#!/usr/bin/env python3
"""Makes the guest snapshot for benign session runs with real internet (user request 2026-11-19: "adjust the script
that it doesn't have simulated internet or anything and have a clean snapshot with real internet").

  1. restore the quiet baseline (clean-final-quiet-v19-...) -- still on the isolated network -- and boot it;
  2. guest_prep.sh as root: delete the staged lab inputs (everything in ~/Downloads) and every sample-like file
     (known sample/archive SHA-256, sample-style names, ELF files and archives in user folders), scan again, and
     switch the enp0s3 NetworkManager profile from the lab's static address to DHCP; the report comes back here;
  3. power off; attach NIC 1 to VirtualBox NAT (no other adapter, no trace);
  4. boot; check address, route, DNS and HTTPS from the guest, and that Downloads is empty;
  5. power off; take snapshot clean-internet-benign-<UTC time>, record it in snapshot.json (the internet driver
     reads it);
  6. restore the original snapshot (clean-tls-paired-2026-10-19, isolated network) and power off.
If a step fails, no snapshot is taken and the VM goes back to the original snapshot. The scrub runs before the
adapter changes, so no sample file is on the disk when the guest first reaches the internet.

  /usr/bin/python3 make_internet_snapshot.py --self-test
  /usr/bin/python3 make_internet_snapshot.py --run --approval "<the user's words>"
"""
import argparse
import fcntl
import json
import re
import secrets
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
LAB = HERE.parent
sys.path.insert(0, str(LAB))
import run_session_lab as lab   # noqa: E402

base = lab.base
require, sha256, save, load, now_utc, stamp = lab.require, lab.sha256, lab.save, lab.load, lab.now_utc, lab.stamp
STUDY = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010")
ASR = LAB.parent
GUEST_HOME = lab.GUEST_HOME
RECORD = HERE / "snapshot.json"
PREP_FILES = ["guest_prep.sh", "guest_scrub.py"]
HEX = re.compile(r"\b[0-9a-f]{64}\b")
NAME_HEX = re.compile(r"^([0-9a-f]{64})")
KEYWORDS = ("manifest", "selection", "cases", "protocol", "verification", "known", "metadata", "label",
            "inventory", "chosen", "sha256", "hashes", "census")


def known_hashes():
    """Every 64-hex SHA-256 the host side knows for samples: file names under data/malware, the contents of its small
    text manifests, the session-lab protocols, the recovered-source record and the quarantine manifests."""
    found, sources = set(), 0
    roots = [STUDY / "data/malware", ASR / "source-recovery", ASR / "revision5-collection", LAB / "runs",
             LAB / "triage-cohort-samples", LAB / "netpilot-samples"]
    for root in roots:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            m = NAME_HEX.match(p.name)
            if m:
                found.add(m.group(1))
            if p.suffix in (".json", ".jsonl", ".csv", ".txt") and p.stat().st_size < 20 << 20 \
                    and (p.suffix == ".jsonl" or any(k in p.name for k in KEYWORDS)):
                found |= set(HEX.findall(p.read_text(errors="ignore").lower()))
                sources += 1
    return found, sources


def make_auth(module, attempt):
    password = tempfile.NamedTemporaryFile(mode="w", prefix="hz-inetsnap-", delete=False)
    Path(password.name).chmod(0o600)
    password.write(module.credentials())
    password.close()
    return Path(password.name), ["--username", module.GUEST_USER, "--passwordfile", password.name]


def grun(module, auth, *command, timeout=120):
    return module.vbox("guestcontrol", module.VM, "run", *auth, "--exe", command[0], "--wait-stdout",
                       "--wait-stderr", "--timeout", str(timeout * 1000), "--", *command[1:], check=False)


def copyto(module, auth, src, dst):
    done = module.vbox("guestcontrol", module.VM, "copyto", *auth, str(src), dst, check=False)
    require(done.returncode == 0, "copyto %s failed: %s" % (Path(src).name, (done.stderr or "")[:200]))


def graceful_off(module, deps, rec, key):
    module.vbox("controlvm", module.VM, "acpipowerbutton", check=False)
    for _ in range(240):
        if module.vm_info(module.VM)["VMState"] == '"poweroff"':
            rec[key] = "acpi"
            return
        deps.sleep(0.5)
    base.power_off(module, deps)
    rec[key] = "hard (acpi did not finish in 120 s)"


def run(approval, deps=None, out_root=HERE / "snapshot-runs"):
    require(approval and approval.strip(), "the user's request is required")
    deps = deps or base.real_deps()
    module = deps.helper
    attempt = Path(out_root) / stamp()
    attempt.mkdir(parents=True)
    rec = {"approval": approval, "started_utc": now_utc(), "baseline": base.BASELINE, "status": "failed",
           "driver_sha256": sha256(__file__),
           "files": {n: sha256(HERE / n) for n in PREP_FILES + ["guest_verify.py"]}}
    name = "clean-internet-benign-" + attempt.name[:15] + "Z"
    known, sources = known_hashes()
    (attempt / "known_hashes.txt").write_text("\n".join(sorted(known)) + "\n")
    rec["known_hashes"] = {"count": len(known), "text_sources": sources,
                           "sha256": sha256(attempt / "known_hashes.txt")}
    password, auth = None, None
    took = False
    with (Path(module.__file__).parent / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        deps.check_competitors()
        try:
            info = module.vm_info(module.VM)
            require(info["VMState"] == '"poweroff"', "guest is running; stop it first")
            uuids = base.snapshot_uuids(module)
            require(uuids.get(base.BASELINE) == [base.BASELINE_UUID], "quiet baseline missing or its UUID differs")
            require(uuids.get(base.ORIGINAL) == [base.ORIGINAL_UUID], "original snapshot missing or its UUID differs")
            require(name not in uuids, "snapshot %s exists" % name)
            password, auth = make_auth(module, attempt)
            # 1-2. scrub and network profile, on the isolated network
            module.vbox("snapshot", module.VM, "restore", base.BASELINE)
            info = module.vm_info(module.VM)
            require(info["CurrentSnapshotName"] == '"%s"' % base.BASELINE, "baseline not restored")
            rec["nic_before"] = {k: info.get(k) for k in ("nic1", "intnet1", "nic2")}
            deps.wait_guest(module, auth, attempt / "boot1.log")
            stage = "%s/prep-%s" % (GUEST_HOME, secrets.token_hex(4))
            require(grun(module, auth, "/bin/mkdir", "-m", "700", stage).returncode == 0, "staging folder")
            copyto(module, auth, password, stage + "/.auth")
            require(grun(module, auth, "/bin/chmod", "600", stage + "/.auth").returncode == 0, "credential chmod")
            for n in PREP_FILES:
                copyto(module, auth, HERE / n, "%s/%s" % (stage, n))
            copyto(module, auth, attempt / "known_hashes.txt", stage + "/known_hashes.txt")
            proc = grun(module, auth, "/bin/bash", stage + "/guest_prep.sh", stage, timeout=3600)
            rec["prep"] = {"rc": proc.returncode, "stdout": (proc.stdout or "")[-2000:],
                           "stderr": (proc.stderr or "")[-1000:]}
            back = module.vbox("guestcontrol", module.VM, "copyfrom", *auth, GUEST_HOME + "/prep-report.tgz",
                               str(attempt / "prep-report.tgz"), check=False)
            if back.returncode == 0 and (attempt / "prep-report.tgz").is_file():
                with tarfile.open(attempt / "prep-report.tgz") as tar:
                    for m in tar.getmembers():
                        require(m.isfile() or m.isdir(), "unexpected report member " + m.name)
                        require(not m.name.startswith("/") and ".." not in m.name.split("/"), "bad member " + m.name)
                    tar.extractall(attempt / "prep-report")
                scrub = attempt / "prep-report" / "scrub.json"
                if scrub.is_file():
                    rec["scrub_counts"] = load(scrub)["counts"]
            grun(module, auth, "/bin/rm", "-rf", GUEST_HOME + "/prep-report", GUEST_HOME + "/prep-report.tgz")
            rec["report_removed"] = grun(module, auth, "/usr/bin/test", "-e",
                                         GUEST_HOME + "/prep-report.tgz").returncode != 0
            rec["staging_removed"] = grun(module, auth, "/usr/bin/test", "-e", stage).returncode != 0
            require(proc.returncode == 0 and "prep done status 0" in (proc.stdout or ""),
                    "guest preparation failed (see prep-report): %s" % rec["prep"])
            require(rec["report_removed"] and rec["staging_removed"], "report or staging folder left in the guest")
            require(rec.get("scrub_counts", {}).get("left_after") == 0, "sample-like files left after the scrub")
            # 3. NAT adapter
            graceful_off(module, deps, rec, "poweroff_1")
            module.vbox("modifyvm", module.VM, "--nic1", "nat", "--cableconnected1", "on", "--nictrace1", "off")
            info = module.vm_info(module.VM)
            require(info.get("nic1") == '"nat"', "NIC 1 is not NAT: %s" % info.get("nic1"))
            rec["nic_after"] = {k: info.get(k) for k in ("nic1", "nic2", "nictrace1")}
            # 4. check the internet from the guest
            deps.wait_guest(module, auth, attempt / "boot2.log")
            vpath = "%s/verify-%s.py" % (GUEST_HOME, secrets.token_hex(4))
            copyto(module, auth, HERE / "guest_verify.py", vpath)
            for tries in range(1, 7):                 # DHCP and DNS may need a few seconds after the login
                deps.sleep(10)
                out = grun(module, auth, "/usr/bin/python3", "-I", vpath, timeout=120)
                require(out.returncode == 0, "verify script failed: %s" % (out.stderr or "")[-500:])
                v = json.loads(out.stdout.strip().splitlines()[-1])
                ok_http = [u for u, s in v["http"].items() if isinstance(s, int) and 200 <= s < 400]
                if ok_http and v.get("dns"):
                    break
            grun(module, auth, "/bin/rm", "-f", vpath)
            v["tries"] = tries
            save(attempt / "verify.json", v)
            rec["verify"] = {"default_route": [l for l in v["route"].splitlines() if l.startswith("default")],
                             "dns": v.get("dns"), "http_ok": ok_http, "downloads": v.get("downloads"),
                             "tools": v.get("tools")}
            require(rec["verify"]["default_route"], "no default route on NAT")
            require(v.get("dns"), "DNS does not resolve: %s" % v.get("dns_error"))
            require(ok_http, "no HTTPS answer: %s" % v["http"])
            require(v.get("downloads") == [], "Downloads is not empty: %s" % v.get("downloads"))
            # 5. the snapshot
            graceful_off(module, deps, rec, "poweroff_2")
            module.vbox("snapshot", module.VM, "take", name, "--description",
                        "Real-internet guest for benign session runs (no Sink, no INetSim, no sinkhole). Child of "
                        "%s: staged lab inputs and sample-like files deleted (report in session-lab/internet/"
                        "snapshot-runs/%s), enp0s3 on DHCP, NIC 1 VirtualBox NAT. Benign programs only."
                        % (base.BASELINE, attempt.name))
            took = True
            uuid = base.snapshot_uuids(module).get(name)
            require(uuid and len(uuid) == 1, "snapshot not found after taking it")
            rec["snapshot"] = {"name": name, "uuid": uuid[0], "parent": base.BASELINE, "parent_uuid": base.BASELINE_UUID,
                               "made_utc": now_utc(), "attempt": str(attempt)}
            rec["status"] = "passed"
        finally:
            try:
                base.power_off(module, deps)
            finally:
                module.vbox("snapshot", module.VM, "restore", base.ORIGINAL)
                final = module.vm_info(module.VM)
                rec["final_vm"] = {k: final.get(k) for k in ("VMState", "CurrentSnapshotName", "nic1", "intnet1",
                                                               "nic2")}
                rec["finished_utc"] = now_utc()
                if password:
                    password.unlink(missing_ok=True)
                if took and rec["status"] != "passed":
                    rec["note"] = "a snapshot was taken but a later step failed; it is not recorded in snapshot.json"
                save(attempt / "result.json", rec)
    if rec["status"] == "passed":
        if RECORD.exists() and out_root == HERE / "snapshot-runs":
            RECORD.replace(HERE / ("snapshot.json.before-" + attempt.name))
        record_path = RECORD if out_root == HERE / "snapshot-runs" else Path(out_root) / "snapshot.json"
        record_path.write_text(json.dumps(rec["snapshot"], indent=1, sort_keys=True) + "\n")
    print(json.dumps({k: rec.get(k) for k in ("status", "snapshot", "scrub_counts", "verify", "final_vm")}, indent=1))
    require(rec["final_vm"]["CurrentSnapshotName"] == '"%s"' % base.ORIGINAL
            and rec["final_vm"]["VMState"] == '"poweroff"', "VM not back on " + base.ORIGINAL)
    return attempt, rec


# ------------------------------------------------------------------------------------------------------ self-test

class FakeHelper(base.FakeHelper):
    def __init__(self, folder, fail=None):
        super().__init__(folder, fail)
        self.nic1 = "intnet"
        self.taken = []
        self.copied = {}
        self.uuids = dict(self.uuids)

    def vm_info(self, name):
        info = super().vm_info(name)
        if name == self.VM:
            info["nic1"] = '"%s"' % self.nic1
        return info

    def vbox(self, *args, check=True):
        if args[0] == "snapshot" and args[2] == "restore":
            self.nic1 = "intnet"
        if args[0] == "modifyvm" and "--nic1" in args:
            require(self.state == "poweroff", "modifyvm while running")
            self.nic1 = args[args.index("--nic1") + 1]
        if args[0] == "snapshot" and args[2] == "take":
            require(self.state == "poweroff", "snapshot taken while running")
            self.taken.append(args[3])
            self.uuids[args[3]] = "00000000-0000-0000-0000-%012d" % len(self.taken)
        if args[0] == "guestcontrol" and args[2] == "copyto":
            self.copied[args[-1]] = args[-2]
        if args[0] == "guestcontrol" and args[2] == "run":
            exe = args[args.index("--exe") + 1]
            rest = list(args[args.index("--") + 1:])
            self.calls.append(args)
            out = SimpleNamespace(returncode=0, stdout="", stderr="")
            if exe == "/bin/bash" and rest[0].endswith("guest_prep.sh"):
                out.stdout = "{}\nprep done status %d\n" % (6 if self.fail == "prep" else 0)
                out.returncode = 6 if self.fail == "prep" else 0
            elif exe == "/usr/bin/python3":
                require(self.nic1 == "nat", "verify ran before NAT")
                out.stdout = json.dumps({"route": "default via 10.0.2.2 dev enp0s3\n", "dns": ["93.184.215.14"],
                                         "http": {"https://example.com/": 200 if self.fail != "http" else "err"},
                                         "downloads": [], "tools": {"curl": None}})
            elif exe == "/usr/bin/test":
                out.returncode = 1
            return out
        if args[0] == "guestcontrol" and args[2] == "copyfrom":
            self.calls.append(args)
            with tempfile.TemporaryDirectory() as tmp:
                t = Path(tmp)
                (t / "scrub.json").write_text(json.dumps({"counts": {"left_after": 0, "deleted_files": 3}}))
                (t / "status.txt").write_text("0\n")
                with tarfile.open(args[-1], "w:gz") as tar:
                    for f in sorted(t.iterdir()):
                        tar.add(f, arcname="./" + f.name)
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return super().vbox(*args, check=check)


def self_test():
    checks = []
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp)
        for fail in (None, "prep", "http"):
            helper = FakeHelper(folder, fail)

            def wait_guest(h, auth, log):
                require(Path(auth[3]).read_text() == "not-a-real-secret", "password file not handed over")
                h.vbox("startvm", h.VM, "--type", "headless")
            deps = SimpleNamespace(helper=helper, wait_guest=wait_guest, check_competitors=lambda: None,
                                   sleep=lambda x: None)
            out = folder / ("runs-%s" % fail)
            try:
                run("self-test", deps=deps, out_root=out)
                require(fail is None, "a failure was not reported (%s)" % fail)
            except ValueError as error:
                require(fail is not None, "unexpected failure: %s" % error)
            attempt = next(out.iterdir()) if fail is not None else sorted(d for d in out.iterdir() if d.is_dir())[0]
            rec = load(attempt / "result.json")
            order = [a[0] + ":" + (a[2] if a[0] in ("snapshot", "guestcontrol") else "") for a in helper.calls]
            require(helper.current == base.ORIGINAL and helper.state == "poweroff", "not restored (%s)" % fail)
            require(not any(a[:2] == ("guestcontrol", "Sink") for a in helper.calls), "the Sink was used")
            if fail is None:
                require(rec["status"] == "passed" and helper.taken == [rec["snapshot"]["name"]], "no snapshot")
                i_prep = next(i for i, a in enumerate(helper.calls) if "guest_prep.sh" in " ".join(map(str, a)))
                i_nat = next(i for i, a in enumerate(helper.calls) if a[0] == "modifyvm")
                i_take = next(i for i, a in enumerate(helper.calls) if a[:3] == ("snapshot", helper.VM, "take"))
                require(i_prep < i_nat < i_take, "order: scrub, then NAT, then snapshot")
                require((out / "snapshot.json").is_file(), "snapshot.json not written")
                require(not RECORD.exists() or load(RECORD) != load(out / "snapshot.json"), "real record touched")
            else:
                require(rec["status"] == "failed" and not helper.taken, "snapshot taken after a failure (%s)" % fail)
            checks.append({"fail": fail, "status": rec["status"], "calls": len(order)})
    print(json.dumps({"self_test": "ok", "cases": checks}, indent=1))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--run", action="store_true")
    p.add_argument("--approval")
    a = p.parse_args()
    if a.self_test:
        self_test()
    elif a.run:
        run(a.approval)
    else:
        p.error("choose --self-test or --run")


if __name__ == "__main__":
    main()

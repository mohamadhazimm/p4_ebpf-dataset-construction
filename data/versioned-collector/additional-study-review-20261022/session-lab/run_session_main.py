#!/usr/bin/env python3
"""Session lab, main collection: the dataset's own programs injected into sessions (see DESIGN.md).

The pilot driver (run_session_lab.py) is used unchanged for the phases, the Sink, the capture and the per-session
checks. This file adds:
  plan "main"  every revision5 malware sample not already in the pilot (round-robin over families, seeded order) and
               every revision5 benign task (round-robin over projects, the dataset's own arguments), interleaved
               with controls (background-only sessions, the three null programs, five flood generators) as
               M B M B C in every five sessions. The run stops at a deadline, so any prefix is balanced across
               families, projects and controls;
  fixtures     a benign task's input files (the revision5 fixtures its arguments name) are packed into a tar at
               freeze time and extracted by the guest user at the dataset's guest path, right after boot and before
               the session's files are staged;
  keep going   a rejected or failed session is recorded and the run goes on; three in a row stop it.

  /usr/bin/python3 run_session_main.py --self-test
  /usr/bin/python3 run_session_main.py --freeze-only
  /usr/bin/python3 run_session_main.py --run-all --attempt DIR --protocol-sha256 SHA --approval "<user's words>"
                                       --deadline-utc 2026-11-16T10:00
"""
import argparse
import fcntl
import hashlib
import json
import os
import random
import re
import secrets
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run_session_lab as lab  # noqa: E402

require, sha256, save, load, now_utc = lab.require, lab.sha256, lab.save, lab.load, lab.now_utc
PAYLOAD = lab.REV5.parent
REV5_GUEST_ROOT = "/home/csci/Downloads/revision5-matched-20261025T100025568989Z/"
PILOT_MALWARE = {sha for sha, _ in lab.TSUNAMI} | {sha for sha, _, _ in lab.NETWORKED}
ATTACKS = [
    {"name": "syn-sink-40k", "args": ["synsink", "40000", "80", "10.0.0.1"]},
    {"name": "syn-fan-40k", "args": ["synflood", "40000", "23"]},
    {"name": "udp-direct-40k", "args": ["udpdirect", "40000", "9999", "10.0.0.1"]},
    {"name": "udp-fan-40k", "args": ["udpflood", "40000", "9999"]},
    {"name": "http-flood-2k", "args": ["httpflood", "2000", "10.0.0.1", "80"]}]
NULLS = ["null-native_amd64_dynamic-start.zip", "null-native_amd64_static-start.zip", "null-native_i386_static-start.zip"]
MAX_IN_A_ROW = 3


def member_sha256(path):
    import subprocess
    blob = subprocess.run(["7z", "x", "-so", "-pinfected", str(path)], capture_output=True, check=True).stdout
    return hashlib.sha256(blob).hexdigest()


def fixture_paths(args):
    """Revision5 fixture paths named in a task's arguments (also inside options such as if=...)."""
    found = set()
    for a in args:
        for m in re.finditer(re.escape(REV5_GUEST_ROOT) + r"[^\s'\"=]*", a):
            found.add(m.group(0)[len(REV5_GUEST_ROOT):].rstrip("/"))
    return sorted(found)


BG_SCALE_PM = 250      # the background 4 times faster than in the pilot (check-in every 2.5 s, jobs 4 times as often):
                       # the pilot's s01 had background activity in 56 of 360 windows; LID-DS servers in 19 of 20


def plan_env(s):
    """The pilot's plan.env with the faster background (bg.sh's own time scale; the session still lasts DUR_S)."""
    text = lab.plan_env(s)
    old_dur, old_pm = "BG_DUR_S=%d\n" % lab.DUR_S, "SCALE_PM=1000\n"
    require(old_dur in text and old_pm in text, "plan.env layout differs")
    return text.replace(old_dur, "BG_DUR_S=%d\n" % (lab.DUR_S * 1000 // BG_SCALE_PM)).replace(
        old_pm, "SCALE_PM=%d\n" % BG_SCALE_PM)


def round_robin(groups, rng):
    order = sorted(groups)
    rng.shuffle(order)
    for g in order:
        groups[g] = sorted(groups[g], key=lambda s: s["name"])
        rng.shuffle(groups[g])
    out = []
    while any(groups.values()):
        for g in order:
            if groups[g]:
                out.append(groups[g].pop(0))
    return out


def main_specs(cases, rng):
    malware, benign = {}, {}
    for c in cases:
        if c["label"] == "malware" and c["member_sha256"] not in PILOT_MALWARE:
            spec = lab.spec_malware(c["member_sha256"], c["family"], c["mode"])
            spec["dataset_split"] = c["split"]
            malware.setdefault(c["family"], []).append(spec)
        elif c["label"] == "benign":
            args = load(PAYLOAD / "arguments" / (c["sample"] + ".json"))
            spec = {"kind": "benign", "name": "%s-%s-%s" % (c["program"], c["project"], c["sample"][-12:-4]),
                    "program": c["program"], "project": c["project"], "mode": c["mode"], "network": c["network"],
                    "source": "archive", "archive": c["sample"], "args": args, "fixtures": fixture_paths(args)}
            benign.setdefault(c["project"], []).append(spec)
    m_queue, b_queue = round_robin(malware, rng), round_robin(benign, rng)
    controls = []
    attacks = [dict(a, kind="attack", source="tool", tool="webfetch") for a in ATTACKS]
    nulls = [{"kind": "null", "name": n[:-4], "source": "archive", "archive": n,
              "args": load(PAYLOAD / "arguments" / (n + ".json"))} for n in NULLS]
    extra = [x for pair in zip(attacks, nulls + [None] * len(attacks)) for x in pair if x]
    for x in extra:
        controls += [{"kind": "none", "name": "background-only"}, x]
    controls += [{"kind": "none", "name": "background-only"} for _ in range(60)]
    order, mi, bi, ci = [], 0, 0, 0
    while mi < len(m_queue) or bi < len(b_queue):
        for slot in "MBMBC":
            if slot == "M" and mi < len(m_queue):
                order.append(m_queue[mi])
                mi += 1
            elif slot == "B" and bi < len(b_queue):
                order.append(b_queue[bi])
                bi += 1
            elif slot == "C" and ci < len(controls):
                order.append(controls[ci])
                ci += 1
    return order


def freeze(out_root=None, verify=None, cases=None):
    out_root = Path(out_root or HERE / "runs")
    cases = cases if cases is not None else load(PAYLOAD / "cases.json")
    rng = random.Random(4242)
    specs = main_specs(cases, rng)
    for name, (path, want) in lab.TOOLS.items():
        require(Path(path).is_file() and sha256(path) == want, "tool %s missing or changed" % name)
    for s in specs:
        if s.get("source") != "archive":
            continue
        path = lab.REV5 / s["archive"]
        if s["kind"] == "malware":
            (verify or lab.rsm.verify_archive)(path, s["sha256"])
        else:
            s["sha256"] = member_sha256(path) if verify is None else "0" * 64
        s["archive_sha256"] = sha256(path)
    run_id = lab.stamp()
    attempt = out_root / run_id
    (attempt / "plans").mkdir(parents=True)
    (attempt / "fixtures").mkdir()
    tars = {}
    for s in specs:
        if s.get("fixtures"):
            key = tuple(s["fixtures"])
            if key not in tars:
                name = "fixtures-%s.tar" % hashlib.sha256("\n".join(key).encode()).hexdigest()[:12]
                with tarfile.open(attempt / "fixtures" / name, "w") as tar:
                    for rel in key:
                        tar.add(PAYLOAD / rel, arcname=(REV5_GUEST_ROOT + rel).lstrip("/"))
                tars[key] = name
            s["fixtures_tar"] = tars[key]
    rng_t = random.Random(4243)
    sessions = []
    for i, spec in enumerate(specs, 1):
        s = dict(spec, sid="m%03d" % i, t_inject_s=round(rng_t.uniform(*lab.INJECT_RANGE), 3),
                 bg_seed=rng_t.randrange(1, 32768), marker="hz" + secrets.token_hex(6),
                 work="/tmp/" + secrets.token_hex(4))
        (attempt / "plans" / (s["sid"] + ".env")).write_text(plan_env(s))
        s["plan_sha256"] = sha256(attempt / "plans" / (s["sid"] + ".env"))
        sessions.append(s)
    counts = {}
    for s in sessions:
        counts[s["kind"]] = counts.get(s["kind"], 0) + 1
    protocol = {
        "format": lab.FORMAT, "plan": "main", "run_id": run_id, "frozen_utc": now_utc(), "duration_s": lab.DUR_S,
        "inject_range_s": list(lab.INJECT_RANGE), "window_s": 0.5, "sessions": sessions, "counts": counts,
        "order_rule": "M B M B C per five sessions; malware round-robin over families, benign over projects "
                      "(seeded); controls: background-only alternating with 5 floods and 3 nulls, then background-only",
        "guest": {"vm": "Ubuntu-Clean-24.04", "baseline": lab.base.BASELINE, "baseline_uuid": lab.base.BASELINE_UUID,
                  "original": lab.base.ORIGINAL, "original_uuid": lab.base.ORIGINAL_UUID, "user": lab.GUEST_USER},
        "sink": {"vm": lab.SINK_VM, "capture": "tcpdump -i enp0s3 -n -U --immediate-mode -B 65536 -Z root",
                 "capture_dir": lab.SINK_CAP, "sinkhole": "on during the sessions", "dns_answer": lab.DNS_REDIRECT,
                 "redirect_conf": lab.REDIRECT_DNSMASQ_CONF, "redirect_conf_sha256": lab.REDIRECT_CONF_SHA256,
                 "after": "sinkhole off, original dnsmasq"},
        "files": {name: sha256(lab.GUEST / name) for name in lab.GUEST_FILES},
        "tools": {name: {"source": str(path), "sha256": want} for name, (path, want) in lab.TOOLS.items()},
        "fixtures": {name: sha256(attempt / "fixtures" / name) for name in sorted(set(tars.values()))},
        "fixture_guest_root": REV5_GUEST_ROOT, "pilot_malware_left_out": sorted(PILOT_MALWARE),
        "background_scale_pm": BG_SCALE_PM,
        "background_scale_reason": "pilot s01: background active in 56 of 360 windows (LID-DS servers: 19 of 20)",
        "driver_sha256": sha256(lab.__file__), "main_driver_sha256": sha256(__file__), "approval": None,
        "retries": False, "keep_going": "a rejected/failed session is recorded; %d in a row stop the run" % MAX_IN_A_ROW,
        "merge_with_any_dataset": False, "model_fitting": False,
        "limitations": ["generated background, not real users", "the Sink fakes services, no C2 protocol",
                        "VirtualBox helpers stay visible in the guest", "capture at the Sink, not the hardware switch",
                        "separate dataset; never merged with the paper's or any other collection",
                        "the deadline decides how much of the list runs"]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": sha256(attempt / "protocol.json"), "counts": counts,
                      "first_30": [(s["sid"], s["kind"], s["name"]) for s in sessions[:30]],
                      "fixture_tars": len(tars)}, indent=1))
    return attempt


def verify_main(attempt, expected):
    protocol = lab.verify_plan(attempt, expected)
    for name, want in protocol["fixtures"].items():
        require(sha256(Path(attempt) / "fixtures" / name) == want, "fixture tar changed: " + name)
    return protocol


def make_deps(attempt, protocol, real=None):
    real = real or lab.base.real_deps()
    tars = {s["sid"]: (s.get("fixtures_tar"), s.get("fixtures")) for s in protocol["sessions"]}

    def wait_guest(module, auth, log_path):
        real.wait_guest(module, auth, log_path)
        sid = Path(log_path).parent.name
        tar, paths = tars.get(sid, (None, None))
        if not tar:
            return

        def grun(*command, timeout=600):
            return module.vbox("guestcontrol", module.VM, "run", *auth, "--exe", command[0], "--wait-stdout",
                               "--wait-stderr", "--timeout", str(timeout * 1000), "--", *command[1:], check=False)
        folder = "%s/fx-%s" % (lab.GUEST_HOME, secrets.token_hex(4))
        require(grun("/bin/mkdir", "-m", "700", folder).returncode == 0, "fixture folder not created")
        done = module.vbox("guestcontrol", module.VM, "copyto", *auth, str(Path(attempt) / "fixtures" / tar),
                           folder + "/f.tar", check=False)
        require(done.returncode == 0, "fixture copy failed: %s" % (done.stderr or "")[:200])
        require(grun("/bin/tar", "-xf", folder + "/f.tar", "-C", "/").returncode == 0, "fixture extraction failed")
        require(grun("/bin/rm", "-rf", folder).returncode == 0, "fixture folder not removed")
        for rel in paths:
            require(grun("/usr/bin/test", "-e", REV5_GUEST_ROOT + rel).returncode == 0, "fixture missing: " + rel)
        with open(log_path, "a") as log:
            log.write("fixtures %s extracted (%s)\n" % (tar, ", ".join(paths)))
    return SimpleNamespace(helper=real.helper, wait_guest=wait_guest, check_competitors=real.check_competitors,
                           sleep=real.sleep)


def sessions_phase(module, deps, attempt, protocol, expected, approval, only=None, deadline=None):
    """As the pilot's, but a rejected or failed session does not stop the run; three in a row do."""
    d = lab.phase_dir(attempt, "sessions", approval, expected)
    todo = [s for s in protocol["sessions"] if (not only or s["sid"] in only)
            and not (Path(attempt) / "sessions" / s["sid"] / "result.json").exists()]
    summary = {"phase": "sessions", "started_utc": now_utc(), "done": [], "status": "failed"}
    in_a_row = 0
    with (Path(module.__file__).parent / "readiness.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        deps.check_competitors()
        try:
            with tempfile.NamedTemporaryFile(mode="w", prefix="hz-sesslab-") as password:
                os.chmod(password.name, 0o600)
                password.write(module.credentials())
                password.flush()
                auth = ["--username", module.GUEST_USER, "--passwordfile", password.name]
                for s in todo:
                    if deadline and datetime.now(timezone.utc) >= deadline:
                        summary["stopped_at_deadline"] = s["sid"]
                        break
                    try:
                        rec = lab.run_session(module, deps, attempt, protocol, s, auth, password.name)
                        status, reasons = rec["status"], rec["checks"]["reasons"]
                    except Exception as error:     # recorded; the guest was powered off in run_session's finally
                        status, reasons = "failed", ["%s: %s" % (type(error).__name__, error)]
                        sdir = Path(attempt) / "sessions" / s["sid"]
                        if sdir.is_dir():
                            save(sdir / "failure.json", {"error": reasons[0], "failed_utc": now_utc()})
                    summary["done"].append({"sid": s["sid"], "status": status, "reasons": reasons})
                    save(d / "progress.json", summary)
                    print("%s %s %-8s %-24s %s %s" % (now_utc()[11:19], s["sid"], s["kind"], s["name"][:24], status,
                                                      "; ".join(reasons)[:300]), flush=True)
                    in_a_row = 0 if status == "accepted" else in_a_row + 1
                    require(in_a_row < MAX_IN_A_ROW, "%d sessions in a row not accepted; stopping" % in_a_row)
            summary["status"] = "passed"
        finally:
            try:
                lab.base.power_off(module, deps)
            finally:
                module.vbox("snapshot", module.VM, "restore", lab.base.ORIGINAL)
                final = lab.base.vm_states(module)
                summary["final_vm_state"] = final
                summary["finished_utc"] = now_utc()
                save(d / ("result-%s.json" % lab.stamp()), summary)
                require(final["guest"]["VMState"] == '"poweroff"'
                        and final["guest"]["CurrentSnapshotName"] == '"%s"' % lab.base.ORIGINAL,
                        "cleanup incomplete: guest not powered off on " + lab.base.ORIGINAL)
    return summary


def run_all(attempt, expected, approval, deadline=None, real=None, only=None):
    require(approval and approval.strip(), "a verbatim user approval is required")
    protocol = verify_main(attempt, expected)
    lab.sessions_phase = sessions_phase      # the pilot's run_all, with this file's session loop
    lab.run_all(attempt, expected, approval, deps=make_deps(attempt, protocol, real), only=only, deadline=deadline)


class FakeHelper(lab.FakeHelper):
    def __init__(self, folder, fail=None, uuids=None):
        super().__init__(folder, fail, uuids)
        self.extracted = []

    def vbox(self, *args, check=True):
        if args[:3] == ("guestcontrol", self.VM, "run") and args[args.index("--exe") + 1] == "/bin/tar":
            self.calls.append(args)
            self.extracted.append(args[-3])
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if args[:3] == ("guestcontrol", self.VM, "run") and args[args.index("--exe") + 1] == "/usr/bin/test" \
                and args[-1].startswith(REV5_GUEST_ROOT):
            self.calls.append(args)
            return SimpleNamespace(returncode=0 if self.extracted else 1, stdout="", stderr="")
        out = super().vbox(*args, check=check)
        if args[:3] == ("guestcontrol", self.VM, "run") and self.fail == "boot-hang-m002":
            plan = [v for k, v in self.guest_files.items() if k.endswith("/plan.env")]
            if plan and Path(plan[-1]).stem == "m002" and args[args.index("--exe") + 1] == "/bin/bash":
                out.returncode, out.stdout = 1, ""
        return out


def self_test():
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp)
        cases = load(PAYLOAD / "cases.json")
        specs = main_specs(cases, random.Random(4242))
        kinds = [s["kind"] for s in specs]
        require(kinds.count("malware") == 105 - len(PILOT_MALWARE) and kinds.count("benign") == 105,
                "main composition %s" % {k: kinds.count(k) for k in set(kinds)})
        first = specs[:140]
        fams = {s["family"] for s in first if s["kind"] == "malware"}
        projs = {s["project"] for s in first if s["kind"] == "benign"}
        require(len(fams) == len({c["family"] for c in cases if c["label"] == "malware"}) and len(projs) == 24,
                "the first 140 sessions cover %d families, %d projects" % (len(fams), len(projs)))
        require([s["kind"] for s in specs[:5]] == ["malware", "benign", "malware", "benign", "none"], "pattern")
        dd = [s for s in specs if s["kind"] == "benign" and s["fixtures"]]
        require(dd and all(set(fixture_paths(s["args"])) == set(s["fixtures"]) for s in dd), "fixture paths")
        require(fixture_paths(["if=" + REV5_GUEST_ROOT + "fixtures/rev5/stream1.bin", "x"]) == ["fixtures/rev5/stream1.bin"],
                "fixture inside an option")
        # a fake attempt with the first 6 sessions; fixtures extracted before staging; keep going over one failure
        small = [c for c in cases if c["label"] != "malware" or c["member_sha256"] not in PILOT_MALWARE]
        attempt = freeze(folder / "runs", verify=lambda p, sha: sha, cases=small)
        expected = sha256(attempt / "protocol.json")
        protocol = load(attempt / "protocol.json")
        with tarfile.open(attempt / "fixtures" / sorted(protocol["fixtures"])[0]) as tar:
            require(all(m.name.startswith(REV5_GUEST_ROOT.lstrip("/")) for m in tar.getmembers()), "tar member paths")

        def real(fail=None):
            helper = FakeHelper(folder, fail)

            def wait_guest(h, auth, log):
                h.vbox("startvm", h.VM, "--type", "headless")
                Path(log).write_text("booted\n")
            return SimpleNamespace(helper=helper, wait_guest=wait_guest, check_competitors=lambda: None,
                                   sleep=lambda s: None)
        r = real("boot-hang-m002")
        only = {s["sid"] for s in protocol["sessions"][:6]}
        lab_sessions = lab.sessions_phase
        try:
            run_all(attempt, expected, "self-test approval", real=r, only=only)
        except ValueError:
            pass
        finally:
            lab.sessions_phase = lab_sessions
        done = {p.parent.name: load(p)["status"] for p in (attempt / "sessions").glob("*/result.json")}
        require(set(done) == only, "ran %s, not the first six" % sorted(done))
        require(all(done[sid] == "accepted" for sid in only - {"m002"}), "sessions %s" % sorted(done.items()))
        require(done.get("m002") in ("failed", "rejected") or (attempt / "sessions/m002/failure.json").exists(),
                "m002 not recorded as failed: %s" % done.get("m002"))
        benign_with_fx = [s["sid"] for s in protocol["sessions"][:len(done)] if s.get("fixtures_tar")]
        require(len(r.helper.extracted) >= len(benign_with_fx), "fixtures extracted %d for %s" % (
            len(r.helper.extracted), benign_with_fx))
        require(r.helper.state == "poweroff" and r.helper.current == lab.base.ORIGINAL and r.helper.sinkhole == "off",
                "not restored")
    print("PASS run_session_main self-test (composition, family/project coverage, M B M B C pattern, fixture paths "
          "and tar member paths, fixtures extracted at boot, keep going past a failed session, restore)")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--freeze-only", action="store_true")
    p.add_argument("--run-all", action="store_true")
    p.add_argument("--attempt")
    p.add_argument("--protocol-sha256")
    p.add_argument("--approval")
    p.add_argument("--deadline-utc")
    a = p.parse_args()
    if a.self_test:
        self_test()
    elif a.freeze_only:
        freeze()
    elif a.run_all:
        deadline = datetime.fromisoformat(a.deadline_utc).replace(tzinfo=timezone.utc) if a.deadline_utc else None
        run_all(Path(a.attempt).resolve(), a.protocol_sha256, a.approval, deadline=deadline)
    else:
        p.error("choose --self-test, --freeze-only or --run-all")


if __name__ == "__main__":
    main()

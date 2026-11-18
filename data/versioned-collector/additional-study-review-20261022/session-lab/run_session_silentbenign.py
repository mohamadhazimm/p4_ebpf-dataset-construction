#!/usr/bin/env python3
"""Session lab, benign programs that meet a silent server (prepared 2026-11-17; needs the user's approval to run).

Why: a post hoc check (silent_server_check.py, session_lab.md section 7.3) found that the sinkhole's catch-all
listener -- it accepts every TCP connection INetSim does not serve and never sends data -- was met only by malware
(40 of 43 C2/backdoor implants of the Triage cohort and pilot, 30 of the main run's 34 networking malware; no benign
program that sent data). The network detector's decisions follow that cue. This batch adds the missing negatives:
the dataset's own benign network clients (curl, wget, openssl, telnet, ftp, in their dataset builds and modes) and
the lab's request tool, pointed at documentation addresses (RFC 5737) on ports INetSim does not serve, so the sinkhole
hands their connections to the same silent listener. They retry, time out or hang the way benign clients do against
a firewalled, overloaded or dead server. No malware runs in this batch; everything else is the Triage cohort's:
the session-lab phases, Sink capture, strict checks, 4x background (run_session_lab.py, run_session_main.py).

Pre-registered analysis (recorded in the protocol): pool these benign rows with the Triage cohort and the pilot
(build_base.py's rows and grouped CV, 20 s) and re-score the C2/backdoor implants against all benign. The network
view is credited with seeing C2 traffic beyond the cue only if, with these benign in training and test, its
implants-only BA stays >= 0.75, its recall on Rekoobe, Sliver and AdaptixC2 stays >= 0.5 each, and its specificity
on the silent-server benign is >= 0.7; otherwise the session lab does not show it. The silent-server rule's own score
on the new pool is reported next to it.

  /usr/bin/python3 run_session_silentbenign.py --self-test
  /usr/bin/python3 run_session_silentbenign.py --freeze-only
  /usr/bin/python3 run_session_silentbenign.py --run-all --attempt DIR --protocol-sha256 SHA --approval "<user's words>"
"""
import argparse
import json
import random
import secrets
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run_session_lab as lab   # noqa: E402
import run_session_main as M    # noqa: E402

require, sha256, save, load, now_utc = lab.require, lab.sha256, lab.save, lab.load, lab.now_utc
SEED = 4263

# (program, mode, task name, argv). Every destination is an RFC 5737 documentation address on a port the sinkhole
# hands to its silent listener (anything but 53/80/443); no task touches the Sink's own address.
TASKS = [
    ("curl", m, "curl-silent-http", ["--noproxy", "*", "--max-time", "8", "--retry", "6", "--retry-delay", "3",
                                     "--retry-all-errors", "-s", "-o", "silent.out", "http://203.0.113.61:8080/status"])
    for m in ("native_amd64_dynamic", "native_amd64_static", "native_i386_static")] + [
    ("curl", m, "curl-silent-tls", ["--noproxy", "*", "--max-time", "8", "--retry", "6", "--retry-delay", "3",
                                    "--retry-all-errors", "-sk", "-o", "silent.out", "https://198.51.100.62:8443/"])
    for m in ("native_amd64_dynamic", "native_amd64_static", "native_i386_static")] + [
    ("wget", m, "wget-silent", ["--no-proxy", "--timeout=6", "--tries=6", "--waitretry=3", "-O", "silent.out",
                                "http://203.0.113.63:9000/index.html"])
    for m in ("native_amd64_dynamic", "native_amd64_static", "native_i386_static")] + [
    ("openssl", m, "openssl-silent", ["s_client", "-connect", "198.51.100.64:8443", "-servername", "updates.example"])
    for m in ("native_amd64_dynamic", "native_amd64_static", "native_i386_static")] + [
    ("telnet", "native_amd64_static", "telnet-silent", ["-E", "203.0.113.65", "2323"]),
    ("ftp", "native_amd64_static", "ftp-silent", ["-4", "-n", "-i", "-e", "192.0.2.66"]),
    ("ftp", "native_i386_static", "ftp-silent", ["-4", "-n", "-i", "-e", "192.0.2.66"])]
TOOL_TASKS = [
    {"name": "beacon-silent", "source": "tool", "tool": "webfetch", "args": ["beacon", "15", "203.0.113.67", "8443", "2000"]},
    {"name": "session-silent", "source": "tool", "tool": "webfetch", "args": ["session", "60", "198.51.100.68", "9001"]}]
PROJECT = {"curl": "curl", "wget": "wget", "openssl": "openssl", "telnet": "inetutils", "ftp": "inetutils"}


def dataset_archive(program, mode, cases):
    """The dataset's network build of `program` in `mode` (the first net-a archive; net-a and net-b hold the same
    binary, only their dataset arguments differ). Two telnet builds exist in amd64-static; both are used."""
    hits = sorted(c["sample"] for c in cases if c["label"] == "benign" and c.get("network") and c["program"] == program
                  and c["mode"] == mode and "-net-a-" in c["sample"])
    require(hits, "no dataset network build of %s in %s" % (program, mode))
    return hits


def specs():
    cases = load(M.PAYLOAD / "cases.json")
    out, seen = [], set()
    for program, mode, task, argv in TASKS:
        archives = dataset_archive(program, mode, cases)
        if program == "telnet":
            chosen = archives                       # both amd64-static telnet builds
        else:
            chosen = archives[:1]
        for arc in chosen:
            key = (task, arc)
            if key in seen:
                continue
            seen.add(key)
            out.append({"kind": "benign", "name": "%s-%s" % (task, arc[-12:-4]), "program": program,
                        "project": PROJECT[program], "mode": mode, "network": True, "source": "archive",
                        "archive": arc, "args": argv, "fixtures": [], "silent_server_task": True})
    out += [dict(t, kind="benign", network=True, project="webfetch", silent_server_task=True) for t in TOOL_TASKS]
    out += [{"kind": "null", "name": n[:-4], "source": "archive", "archive": n,
             "args": load(M.PAYLOAD / "arguments" / (n + ".json"))} for n in M.NULLS]
    out += [{"kind": "none", "name": "background-only"} for _ in range(3)]
    rng = random.Random(SEED)
    rng.shuffle(out)
    return out


def freeze(out_root=None):
    out_root = Path(out_root or HERE / "runs")
    plan = specs()
    for name, (path, want) in lab.TOOLS.items():
        require(Path(path).is_file() and sha256(path) == want, "tool %s missing or changed" % name)
    for s in plan:
        if s.get("source") == "archive":
            path = lab.REV5 / s["archive"]
            require(path.is_file(), "archive missing: " + s["archive"])
            s["sha256"] = M.member_sha256(path)
            s["archive_sha256"] = sha256(path)
    run_id = lab.stamp()
    attempt = out_root / run_id
    (attempt / "plans").mkdir(parents=True)
    (attempt / "fixtures").mkdir()                   # none needed: no task reads an input file
    rng_t = random.Random(SEED + 1)
    sessions = []
    for i, spec in enumerate(plan, 1):
        s = dict(spec, sid="q%03d" % i, t_inject_s=round(rng_t.uniform(*lab.INJECT_RANGE), 3),
                 bg_seed=rng_t.randrange(1, 32768), marker="hz" + secrets.token_hex(6),
                 work="/tmp/" + secrets.token_hex(4))
        (attempt / "plans" / (s["sid"] + ".env")).write_text(M.plan_env(s))
        s["plan_sha256"] = sha256(attempt / "plans" / (s["sid"] + ".env"))
        sessions.append(s)
    counts = {}
    for s in sessions:
        counts[s["kind"]] = counts.get(s["kind"], 0) + 1
    protocol = {
        "format": lab.FORMAT, "plan": "silent-server-benign", "run_id": run_id, "frozen_utc": now_utc(),
        "duration_s": lab.DUR_S, "inject_range_s": list(lab.INJECT_RANGE), "window_s": 0.5, "sessions": sessions,
        "counts": counts,
        "why": "the sinkhole's silent listener was met only by malware (session_lab.md 7.3); these benign clients "
               "meet it too, so the network view's C2 result can be re-scored without that cue",
        "expectations": {
            "pool": "these benign rows + the Triage cohort + the network-active pilot (build_base.py rows, grouped CV, "
                    "10 fold assignments, 20 s)",
            "primary": "network view on the C2/backdoor implants vs all benign: implants-only BA, recall on Rekoobe, "
                       "Sliver, AdaptixC2, and specificity on the silent-server benign",
            "decision": "credited with seeing C2 beyond the cue only if implants-only BA >= 0.75, recall >= 0.5 on each "
                        "of Rekoobe, Sliver and AdaptixC2, and silent-server-benign specificity >= 0.7; otherwise the "
                        "session lab does not show it",
            "also": "the silent-server rule's own BA on the new pool; host, concatenated and stacked on the same folds",
            "prediction": "the cue rule falls towards chance; the network view's implants-only BA falls if its C2 "
                          "catches rested on the cue"},
        "guest": {"vm": "Ubuntu-Clean-24.04", "baseline": lab.base.BASELINE, "baseline_uuid": lab.base.BASELINE_UUID,
                  "original": lab.base.ORIGINAL, "original_uuid": lab.base.ORIGINAL_UUID, "user": lab.GUEST_USER},
        "sink": {"vm": lab.SINK_VM, "capture": "tcpdump -i enp0s3 -n -U --immediate-mode -B 65536 -Z root (full frames)",
                 "capture_dir": lab.SINK_CAP, "sinkhole": "on during the sessions", "dns_answer": lab.DNS_REDIRECT,
                 "redirect_conf": lab.REDIRECT_DNSMASQ_CONF, "redirect_conf_sha256": lab.REDIRECT_CONF_SHA256,
                 "after": "sinkhole off, original dnsmasq"},
        "files": {name: sha256(lab.GUEST / name) for name in lab.GUEST_FILES},
        "tools": {name: {"source": str(path), "sha256": want} for name, (path, want) in lab.TOOLS.items()},
        "fixtures": {}, "fixture_guest_root": M.REV5_GUEST_ROOT,
        "samples_dir": str(lab.REV5), "background_scale_pm": M.BG_SCALE_PM,
        "driver_sha256": sha256(lab.__file__), "main_driver_sha256": sha256(M.__file__),
        "silentbenign_driver_sha256": sha256(__file__), "approval": None, "retries": False,
        "malware": "none in this batch", "keep_going": "a rejected/failed session is recorded; %d in a row stop the run"
                                                        % M.MAX_IN_A_ROW,
        "merge_with_any_dataset": False, "model_fitting": False,
        "limitations": ["silent servers stand in for firewalled or dead ones", "generated background",
                        "one batch, 18 silent-server benign tasks of 6 programs", "separate collection; never merged"]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": sha256(attempt / "protocol.json"), "counts": counts},
                     indent=1))
    return attempt


def self_test():
    plan = specs()
    names = [s["name"] for s in plan if s["kind"] == "benign"]
    require(len(names) == len(set(names)), "duplicate benign session names")
    benign = [s for s in plan if s["kind"] == "benign"]
    require(len(benign) == 18 and all(s["silent_server_task"] for s in benign), "expected 18 silent-server benign")
    for s in benign:
        dests = [a for a in s["args"] if any(x in a for x in ("203.0.113.", "198.51.100.", "192.0.2."))]
        require(dests, "no documentation address in " + s["name"])
        require(not any("10.0.0.1" in a for a in s["args"]), "task touches the Sink: " + s["name"])
        require(not any(":80/" in a or ":443/" in a or a in ("80", "443", "53") for a in s["args"]),
                "task uses an INetSim port: " + s["name"])
        if s.get("source") == "archive":
            require((lab.REV5 / s["archive"]).is_file(), "archive missing: " + s["archive"])
    kinds = {k: sum(1 for s in plan if s["kind"] == k) for k in ("benign", "null", "none", "malware")}
    require(kinds == {"benign": 18, "null": 3, "none": 3, "malware": 0}, "composition %s" % kinds)
    env = M.plan_env(dict(plan[0], sid="q001", t_inject_s=50.0, bg_seed=1, marker="hz000000000000", work="/tmp/x"))
    require("SCALE_PM=%d" % M.BG_SCALE_PM in env, "plan.env lacks the 4x background")
    import tempfile
    from types import SimpleNamespace
    with tempfile.TemporaryDirectory() as tmp:                 # a fake run of the first 6 sessions (no VirtualBox)
        folder = Path(tmp)
        attempt = freeze(folder / "runs")
        expected = sha256(attempt / "protocol.json")
        protocol = load(attempt / "protocol.json")
        helper = M.FakeHelper(folder, None)

        def wait_guest(h, auth, log):
            h.vbox("startvm", h.VM, "--type", "headless")
            Path(log).write_text("booted\n")
        fake = SimpleNamespace(helper=helper, wait_guest=wait_guest, check_competitors=lambda: None, sleep=lambda x: None)
        only = {s["sid"] for s in protocol["sessions"][:6]}
        keep = lab.sessions_phase
        try:
            M.run_all(attempt, expected, "self-test approval", real=fake, only=only)
        finally:
            lab.sessions_phase = keep
        done = {q.parent.name: load(q)["status"] for q in (attempt / "sessions").glob("*/result.json")}
        require(set(done) == only and all(v == "accepted" for v in done.values()), "fake run: %s" % done)
        require(helper.state == "poweroff" and helper.current == lab.base.ORIGINAL and helper.sinkhole == "off",
                "fake run: not restored")
    print(json.dumps({"self_test": "ok", "fake_run_sessions": len(done), "sessions": len(plan), "kinds": kinds,
                      "modes": sorted({s.get("mode") for s in benign if s.get("mode")}),
                      "tasks": sorted({s["name"].rsplit("-", 1)[0] for s in benign})}, indent=1))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--freeze-only", action="store_true")
    p.add_argument("--run-all", action="store_true")
    p.add_argument("--attempt")
    p.add_argument("--protocol-sha256")
    p.add_argument("--approval")
    a = p.parse_args()
    if a.self_test:
        self_test()
    elif a.freeze_only:
        freeze()
    elif a.run_all:
        M.run_all(Path(a.attempt).resolve(), a.protocol_sha256, a.approval)
    else:
        p.error("choose --self-test, --freeze-only or --run-all")


if __name__ == "__main__":
    main()

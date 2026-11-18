#!/usr/bin/env python3
"""Session lab, the rest of the main plan (see DESIGN.md).

The main run (runs/20261115T214153675625Z) stopped at its 10:00 UTC deadline after 163 of its 254 sessions. This plan
completes it with the pilot driver (run_session_lab.py) and the main driver (run_session_main.py) unchanged:

  unreached     the main plan's sessions that never started (m164..m254: 30 malware, 40 benign, 21 background-only),
                each with the main plan's own spec, injection time and background seed, in the main plan's order;
  never booted  the main sessions whose guest never booted (the VirtualBox login event timed out before anything was
                staged, so the program never started; the Sink capture is empty): run once here with the same spec,
                injection time and background seed. No session whose program started is repeated;
  pilot nine    the nine dataset malware the main plan left to the pilot (five Tsunami, Mirai, Kaiji, Ngioweb,
                CoinMiner), collected here under the main settings; the pilot ran with the 1x background, so without
                them nine dataset programs would have a session only under different settings.

The extra sessions (never booted + pilot nine) are inserted at evenly spaced positions into the unreached sequence,
malware round-robin over families. Per-session checks are the main run's (strict); a rejected or failed session is
recorded and the run goes on; three in a row stop it.

  /usr/bin/python3 run_session_rest.py --self-test
  /usr/bin/python3 run_session_rest.py --freeze-only
  /usr/bin/python3 run_session_rest.py --run-all --attempt DIR --protocol-sha256 SHA --approval "<user's words>"
                                       [--deadline-utc 2026-11-17T12:00]
"""
import argparse
import json
import random
import re
import secrets
import sys
import tarfile
import tempfile
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run_session_lab as lab   # noqa: E402
import run_session_main as M    # noqa: E402

require, sha256, save, load, now_utc = lab.require, lab.sha256, lab.save, lab.load, lab.now_utc
# The main run's guest scripts, byte-identical (checked against the main protocol at freeze and at run start). The
# scripts in guest/ gained, before the flood batch, two lines that stage Python attack tools (*.py, pyexec) -- inert
# for program and background sessions, but the rest of the main plan runs with the main plan's own files.
MAIN_GUEST = HERE / "guest-main"
lab.GUEST = MAIN_GUEST
MAIN_ID = "20261115T214153675625Z"
MAIN_SHA = "79092d6f40ac870dc93fb95fd3f210d7924cb0768508dc784436200395f13fa3"
NEVER_BOOTED = "Guest login event timed out"
BOOT_ONLY_FILES = {"boot.log", "failure.json", "result.json", "sink.pcap"}
STATUS_RE = re.compile(r"^\d\d:\d\d:\d\d (m\d+) \S+\s+\S+\s+(accepted|rejected|failed)\b")
SEED = 4251
CARRY = ("kind", "name", "family", "mode", "source", "archive", "sha256", "args", "dataset_split", "program",
         "project", "network", "fixtures", "t_inject_s", "bg_seed")


def main_outcomes(main_dir):
    """sid -> accepted/rejected/failed from the main run's log, cross-checked with its session folders."""
    out = {}
    for line in (Path(main_dir) / "main.log").read_text().splitlines():
        m = STATUS_RE.match(line)
        if m:
            require(m.group(1) not in out, "two outcomes for " + m.group(1))
            out[m.group(1)] = m.group(2)
    started = {p.name for p in (Path(main_dir) / "sessions").iterdir() if p.is_dir()}
    require(started == set(out), "main log and session folders disagree: %s" % sorted(started ^ set(out)))
    return out


def never_booted(main_dir, sid):
    """True only if the session failed waiting for the guest login, before anything was staged (capture empty)."""
    sdir = Path(main_dir) / "sessions" / sid
    if not (sdir / "failure.json").is_file() or NEVER_BOOTED not in load(sdir / "failure.json").get("error", ""):
        return False
    extra = sorted(set(p.name for p in sdir.iterdir()) - BOOT_ONLY_FILES)
    require(not extra, "%s failed at boot but has %s" % (sid, extra))
    counters = load(sdir / "result.json").get("capture", {}).get("counters", {})
    require(counters.get("received") == 0 and counters.get("captured") == 0, "%s: capture not empty %s" % (sid, counters))
    return True


def pilot_specs(cases):
    split = {c["member_sha256"]: c for c in cases if c["label"] == "malware"}
    pilot = [(sha, "Tsunami", mode) for sha, mode in lab.TSUNAMI] + list(lab.NETWORKED)
    specs = []
    for sha, fam, mode in pilot:
        require(sha in split and split[sha]["family"] == fam and split[sha]["mode"] == mode,
                "pilot sample not in the dataset cases as expected: " + sha[:8])
        spec = lab.spec_malware(sha, fam, mode)
        spec["dataset_split"] = split[sha]["split"]
        specs.append(spec)
    return specs


def spread(groups, rng):
    """The largest family alternated with the others (round-robin), so its samples are not collected together."""
    big = max(sorted(groups), key=lambda g: len(groups[g]))
    rest = M.round_robin({g: v for g, v in groups.items() if g != big}, rng)
    b = sorted(groups[big], key=lambda s: s["name"])
    rng.shuffle(b)
    out = []
    while b or rest:
        if b:
            out.append(b.pop(0))
        if rest:
            out.append(rest.pop(0))
    return out


def rest_specs(main_protocol, outcomes, main_dir, cases, rng):
    """(ordered specs, report). Specs from the main plan keep its spec, injection time and background seed."""
    by_sid = {s["sid"]: s for s in main_protocol["sessions"]}
    unreached = [s for s in main_protocol["sessions"] if s["sid"] not in outcomes]
    booted_not = [by_sid[sid] for sid, st in sorted(outcomes.items()) if st == "failed" and never_booted(main_dir, sid)]
    other_failed = sorted(sid for sid, st in outcomes.items() if st == "failed" and by_sid[sid] not in booted_not)
    require(not other_failed, "failed main sessions that did start (not repeated, decide by hand): %s" % other_failed)

    def carry(s, origin):
        out = {k: s[k] for k in CARRY if k in s}
        out.update(origin=origin, main_sid=s["sid"])
        return out
    base = [carry(s, "main-unreached") for s in unreached]
    require(not any(s["kind"] == "attack" or s["kind"] == "null" for s in base), "attacks/nulls left in the rest")
    extra_m = [carry(s, "main-never-booted") for s in booted_not if s["kind"] == "malware"]
    extra_b = [carry(s, "main-never-booted") for s in booted_not if s["kind"] == "benign"]
    pil = pilot_specs(cases)
    rng_t = random.Random(SEED + 1)
    for spec in pil:
        spec.update(origin="pilot-recollected", t_inject_s=round(rng_t.uniform(*lab.INJECT_RANGE), 3),
                    bg_seed=rng_t.randrange(1, 32768))
    fams = {}
    for s in extra_m + pil:
        fams.setdefault(s["family"], []).append(s)
    extra_m = spread(fams, rng)
    # extras: malware and benign alternated as evenly as their numbers allow, then spread over the unreached sequence
    extras, bi = [], 0
    step = (len(extra_m) + len(extra_b)) / max(1, len(extra_b))
    for i in range(len(extra_m) + len(extra_b)):
        if bi < len(extra_b) and i >= round((bi + 0.5) * step) - 1:
            extras.append(extra_b[bi])
            bi += 1
        else:
            extras.append(extra_m[i - bi])
    order, n = list(base), len(base)
    positions = [round((k + 1) * n / (len(extras) + 1)) for k in range(len(extras))]
    for k, (pos, x) in enumerate(zip(positions, extras)):
        order.insert(pos + k, x)
    report = {"unreached": [s["sid"] for s in unreached], "never_booted": [s["sid"] for s in booted_not],
              "pilot_recollected": [s["sha256"][:8] for s in pil], "extras_positions": positions}
    return order, report


def freeze(out_root=None, main_dir=None, main_sha=MAIN_SHA, verify=None, cases=None):
    main_dir = Path(main_dir or HERE / "runs" / MAIN_ID)
    out_root = Path(out_root or HERE / "runs")
    require(sha256(main_dir / "protocol.json") == main_sha, "main protocol hash differs")
    main_protocol = load(main_dir / "protocol.json")
    cases = cases if cases is not None else load(M.PAYLOAD / "cases.json")
    outcomes = main_outcomes(main_dir)
    rng = random.Random(SEED)
    specs, report = rest_specs(main_protocol, outcomes, main_dir, cases, rng)
    for name, (path, want) in lab.TOOLS.items():
        require(Path(path).is_file() and sha256(path) == want, "tool %s missing or changed" % name)
        require(main_protocol["tools"][name]["sha256"] == want, "tool %s differs from the main run" % name)
    for name, want in main_protocol["files"].items():
        require(sha256(lab.GUEST / name) == want, "guest file differs from the main run: " + name)
    for s in specs:
        if s.get("source") != "archive":
            continue
        path = lab.REV5 / s["archive"]
        if s["kind"] == "malware":
            (verify or lab.rsm.verify_archive)(path, s["sha256"])
        else:
            want = s.get("sha256")
            got = M.member_sha256(path) if verify is None else (want or "0" * 64)
            require(want is None or got == want, "benign member differs from the main plan: " + s["archive"])
            s["sha256"] = got
        s["archive_sha256"] = sha256(path)
    run_id = lab.stamp()
    attempt = out_root / run_id
    (attempt / "plans").mkdir(parents=True)
    (attempt / "fixtures").mkdir()
    tars = {}
    for s in specs:                                  # benign fixtures, built as run_session_main.freeze builds them
        if s.get("fixtures"):
            key = tuple(s["fixtures"])
            if key not in tars:
                name = "fixtures-%s.tar" % hashlib.sha256("\n".join(key).encode()).hexdigest()[:12]
                with tarfile.open(attempt / "fixtures" / name, "w") as tar:
                    for rel in key:
                        tar.add(M.PAYLOAD / rel, arcname=(M.REV5_GUEST_ROOT + rel).lstrip("/"))
                tars[key] = name
            s["fixtures_tar"] = tars[key]
    fixture_hashes = {name: sha256(attempt / "fixtures" / name) for name in sorted(set(tars.values()))}
    for name, h in fixture_hashes.items():           # same input files as the main run's tar of the same name
        if verify is None and name in main_protocol["fixtures"]:
            require(main_protocol["fixtures"][name] == h, "fixture tar differs from the main run: " + name)
    sessions = []
    for i, spec in enumerate(specs, 1):
        s = dict(spec, sid="r%03d" % i, marker="hz" + secrets.token_hex(6), work="/tmp/" + secrets.token_hex(4))
        (attempt / "plans" / (s["sid"] + ".env")).write_text(M.plan_env(s))
        s["plan_sha256"] = sha256(attempt / "plans" / (s["sid"] + ".env"))
        sessions.append(s)
    counts, origins = {}, {}
    for s in sessions:
        counts[s["kind"]] = counts.get(s["kind"], 0) + 1
        origins[s["origin"]] = origins.get(s["origin"], 0) + 1
    protocol = {k: main_protocol[k] for k in ("format", "duration_s", "inject_range_s", "window_s", "guest", "sink",
                                              "files", "tools", "fixture_guest_root", "background_scale_pm",
                                              "background_scale_reason", "keep_going")}
    protocol.update({
        "plan": "rest", "run_id": run_id, "frozen_utc": now_utc(), "sessions": sessions, "counts": counts,
        "origins": origins, "fixtures": fixture_hashes,
        "derived_from": {"main_attempt": "runs/" + main_dir.name, "main_protocol_sha256": main_sha,
                         "main_outcomes": {st: sum(v == st for v in outcomes.values()) for st in set(outcomes.values())},
                         **report},
        "order_rule": "the main plan's unreached sessions in the main plan's order (M B M B C); the extra sessions "
                      "(never booted + pilot nine, malware round-robin over families, benign spread) inserted at "
                      "evenly spaced positions",
        "guest_dir": "guest-main (the main run's guest scripts, byte-identical; guest/ later added Python-tool "
                     "staging for the flood batch, inert for these sessions)",
        "retries": False,
        "retries_note": "a main session whose guest never booted (login event timed out before staging; program never "
                        "started; capture empty) runs once here; no session whose program started is repeated",
        "pilot_note": "the pilot's nine dataset malware ran with the 1x background; they are collected again under the "
                      "main settings so every dataset program has a session under identical settings",
        "driver_sha256": sha256(lab.__file__), "main_driver_sha256": sha256(M.__file__),
        "rest_driver_sha256": sha256(__file__), "approval": None, "merge_with_any_dataset": False,
        "model_fitting": False,
        "limitations": main_protocol["limitations"] + [
            "collected a day after the main run's first sessions (time drift checked with background-only sessions)"]})
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": sha256(attempt / "protocol.json"), "counts": counts,
                      "origins": origins, "never_booted": report["never_booted"],
                      "first_20": [(s["sid"], s["kind"], s["name"], s["origin"]) for s in sessions[:20]]}, indent=1))
    return attempt


def run_all(attempt, expected, approval, deadline=None, real=None, only=None):
    M.run_all(Path(attempt).resolve(), expected, approval, deadline=deadline, real=real, only=only)


def self_test():
    main_dir = HERE / "runs" / MAIN_ID
    main_protocol = load(main_dir / "protocol.json")
    outcomes = main_outcomes(main_dir)
    cases = load(M.PAYLOAD / "cases.json")
    specs, report = rest_specs(main_protocol, outcomes, main_dir, cases, random.Random(SEED))
    by_sid = {s["sid"]: s for s in main_protocol["sessions"]}
    kinds = [s["kind"] for s in specs]
    unreached = [s for s in main_protocol["sessions"] if s["sid"] not in outcomes]
    require(len(report["never_booted"]) == 5 and set(report["never_booted"]) == {"m018", "m084", "m109", "m112", "m114"},
            "never booted %s" % report["never_booted"])
    require(len(specs) == len(unreached) + 5 + 9, "rest has %d sessions" % len(specs))
    started = {sid for sid, st in outcomes.items() if st in ("accepted", "rejected")}
    require(not any(s.get("main_sid") in started for s in specs), "a started main session is repeated")
    for s in specs:                                  # the main plan's spec, injection time and seed are kept
        if s.get("main_sid"):
            m = by_sid[s["main_sid"]]
            require(all(s.get(k) == m.get(k) for k in CARRY if k in m), "spec differs from main for " + s["main_sid"])
    require([s["main_sid"] for s in specs if s["origin"] == "main-unreached"] == [s["sid"] for s in unreached],
            "unreached order differs from the main plan")
    pil = [s for s in specs if s["origin"] == "pilot-recollected"]
    require(len(pil) == 9 and {s["sha256"] for s in pil} == M.PILOT_MALWARE, "pilot nine")
    xi = [i for i, s in enumerate(specs) if s["origin"] != "main-unreached"]
    require(all(b - a > 1 for a, b in zip(xi, xi[1:])), "two extra sessions adjacent: %s" % xi)
    require(xi[0] < len(specs) // 6 and xi[-1] > len(specs) * 5 // 6, "extras not spread: %s" % xi)
    fam_runs = [specs[i]["family"] for i in xi if specs[i]["kind"] == "malware"]
    require(all(a != b for a, b in zip(fam_runs, fam_runs[1:]) if a == "Tsunami"), "Tsunami extras clustered %s" % fam_runs)
    require(kinds.count("attack") == 0 and kinds.count("null") == 0, "no attacks/nulls in the rest")
    in99 = {c["member_sha256"] for c in cases if c["label"] == "malware"}
    # a fake attempt: freeze into a temp folder, run the first six through the main driver's fake VirtualBox
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp)
        attempt = freeze(folder / "runs", verify=lambda p, sha: sha)
        expected = sha256(attempt / "protocol.json")
        protocol = load(attempt / "protocol.json")
        require(protocol["counts"] == {k: kinds.count(k) for k in set(kinds)}, "counts")
        require(protocol["background_scale_pm"] == M.BG_SCALE_PM == main_protocol["background_scale_pm"], "background")
        for s in protocol["sessions"]:
            env = (attempt / "plans" / (s["sid"] + ".env")).read_text()
            require("SCALE_PM=%d\n" % M.BG_SCALE_PM in env, "plan.env background scale " + s["sid"])

        def real(fail=None):
            helper = M.FakeHelper(folder, fail)

            def wait_guest(h, auth, log):
                h.vbox("startvm", h.VM, "--type", "headless")
                Path(log).write_text("booted\n")
            return SimpleNamespace(helper=helper, wait_guest=wait_guest, check_competitors=lambda: None,
                                   sleep=lambda s: None)
        r = real()
        only = {s["sid"] for s in protocol["sessions"][:6]}
        keep = lab.sessions_phase
        try:
            run_all(attempt, expected, "self-test approval", real=r, only=only)
        finally:
            lab.sessions_phase = keep
        done = {p.parent.name: load(p)["status"] for p in (attempt / "sessions").glob("*/result.json")}
        require(set(done) == only and all(v == "accepted" for v in done.values()), "fake run %s" % done)
        require(r.helper.state == "poweroff" and r.helper.current == lab.base.ORIGINAL and r.helper.sinkhole == "off",
                "not restored")
    print("PASS run_session_rest self-test: %d sessions (%s), %d unreached in main order with main's spec/injection/"
          "seed, never booted %s (not started), 9 pilot malware recollected, extras spread %s, no started session "
          "repeated, revision5-selection malware in the rest: %d, fake run of 6 + restore" % (
              len(specs), {k: kinds.count(k) for k in set(kinds)}, len(unreached), report["never_booted"],
              report["extras_positions"], sum(s.get("sha256") in in99 for s in specs if s["kind"] == "malware")))


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

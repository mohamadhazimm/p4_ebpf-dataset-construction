#!/usr/bin/env python3
"""Session lab, flood batch (user approval 2026-11-16: "okay let's do that please").

Confirms the flood result on the busy-background machine. The main run carried only 6 flood sessions and 3 of them
were rejected, too few to train the fusion, so the combined detector followed the host view and missed all three.
This batch injects every attack type of the paper's dataset -- volumetric SYN/UDP floods (flood_gen's unprivileged
connect()/sendto() method), the published tools Slowloris and GoldenEye (via flood_gen's pyexec, the same way the
paper's realtools collection ran them), and HTTP floods (the type the paper's 15 attacks never had) -- several of
each, into the same background as the main run, with matched network-active benign controls so the detector is not
just learning "busy network = attack". Everything else is the main collection's: the pilot driver's phases, Sink
capture and per-session checks (run_session_lab.py), the main driver's keep-going loop (run_session_main.py).

Two check changes for attack sessions only, both pre-agreed and neither touching a detector feature:
  - the host monitor's connect-address set holds 64 entries per window; a fan-out flood overflows it and the monitor
    reports a capacity error. Those columns (unique IPs/ports) are not among the 18 ADFA host features, so a
    capacity-only overflow (lost=late=failed=0) does not reject an attack session;
  - a tiny packet-drop fraction in a 100k-packet flood does not change flow-shape features, so an attack session is
    accepted when the capture is internally consistent (received = captured + dropped, file hash matches) and the
    drop fraction is <= DROP_TOL. A silent loss (received != captured + dropped) or a hash mismatch still rejects.
Benign, null and background-only sessions keep the strict checks unchanged (no drops, no capacity errors).

SAFETY: unchanged from the main run. Floods hit only the sealed 10.0.x.y /16 (fan-out, die at the gateway) or the
Sink 10.0.0.1; the guest is intnet-only; each session restores the quiet baseline and powers off; the Sink is
restored at the end. No malware sample runs (every injected program is flood_gen or a published load tool); no C2;
no model fitting; never merged with any dataset.

  /usr/bin/python3 run_session_flood.py --freeze-only
  /usr/bin/python3 run_session_flood.py --run-all --attempt DIR --protocol-sha256 SHA --approval "<user's words>"
"""
import argparse
import hashlib
import json
import random
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run_session_lab as lab   # noqa: E402
import run_session_main as M    # noqa: E402

require, sha256, save, load, now_utc = lab.require, lab.sha256, lab.save, lab.load, lab.now_utc
ASR = lab.ASR
REALTOOLS = ASR / "realtools"
SEED = 4246
DROP_TOL = 0.02          # attack sessions only: tolerated capture-drop fraction (flow-shape unchanged)

# the two published load tools, staged like the paper's realtools collection (flood_gen pyexec execs python3 on
# the script beside its own binary, so the traced image becomes the real tool)
EXTRA_TOOLS = {"slowloris.py": (REALTOOLS / "slowloris.py",
                                "89707478b54e35b76b9ef2f43b897713ddd1e425db3bcc8cbbdc5b210b61d9d8"),
               "goldeneye.py": (REALTOOLS / "goldeneye.py",
                                "97eafe32fb3b154718fd0318fd124e956d644d8e4fecf6922be84d9afbd62e97")}

# (name, attack_type, flood_gen argv). Volumetric via flood_gen's socket method; application-layer via pyexec on
# the published tool; HTTP floods are flood_gen's tiny complete GETs (handshaked, but hang up early -> RST).
ATTACKS = [
    ("syn-sink-40k",  "syn",       ["synsink", "40000", "80", "10.0.0.1"]),
    ("syn-sink-80k",  "syn",       ["synsink", "80000", "80", "10.0.0.1"]),
    ("syn-fan-40k",   "syn",       ["synflood", "40000", "23"]),
    ("udp-sink-40k",  "udp",       ["udpdirect", "40000", "9999", "10.0.0.1"]),
    ("udp-sink-80k",  "udp",       ["udpdirect", "80000", "9999", "10.0.0.1"]),
    ("udp-fan-40k",   "udp",       ["udpflood", "40000", "9999"]),
    ("http-flood-2k", "http",      ["httpflood", "2000", "10.0.0.1", "80"]),
    ("http-flood-5k", "http",      ["httpflood", "5000", "10.0.0.1", "80"]),
    ("slowloris-150", "slowloris", ["pyexec", "slowloris.py", "10.0.0.1", "-p", "80", "-s", "150"]),
    ("slowloris-300", "slowloris", ["pyexec", "slowloris.py", "10.0.0.1", "-p", "80", "-s", "300"]),
    ("slowloris-500", "slowloris", ["pyexec", "slowloris.py", "10.0.0.1", "-p", "80", "-s", "500"]),
    ("goldeneye-g5",  "goldeneye", ["pyexec", "goldeneye.py", "http://10.0.0.1/", "-w", "5", "-s", "300", "-m", "get"]),
    ("goldeneye-g10", "goldeneye", ["pyexec", "goldeneye.py", "http://10.0.0.1/", "-w", "10", "-s", "500", "-m", "get"]),
    ("goldeneye-p10", "goldeneye", ["pyexec", "goldeneye.py", "http://10.0.0.1/", "-w", "10", "-s", "500", "-m", "post"])]

# matched network-active benign (handshaked request/response), flood_gen benign shapes
BENIGN = [
    ("download-20",  ["bulk", "20", "10.0.0.1", "80"]),
    ("download-40",  ["bulk", "40", "10.0.0.1", "80"]),
    ("upload-300",   ["bulkup", "300", "10.0.0.1", "80"]),
    ("browse-60",    ["session", "60", "10.0.0.1", "80"]),
    ("browse-300",   ["session", "300", "10.0.0.1", "80"]),
    ("beacon-50",    ["beacon", "50", "10.0.0.1", "80", "200"]),
    ("dns-2k",       ["dns", "2000", "10.0.0.1"]),
    ("dns-5k",       ["dns", "5000", "10.0.0.1"])]


def tool_set():
    """lab.TOOLS plus the two published load tools, verified against their frozen hashes."""
    tools = dict(lab.TOOLS)
    for name, (path, want) in EXTRA_TOOLS.items():
        require(Path(path).is_file() and sha256(path) == want, "tool %s missing or changed: %s" % (name, path))
        tools[name] = (path, want)
    return tools


def spec_attack(name, atype, args):
    return {"kind": "attack", "name": name, "atype": atype, "source": "tool", "tool": "webfetch", "args": args}


def spec_benign(name, args):
    return {"kind": "benign", "name": name, "source": "tool", "tool": "webfetch", "args": args}


def specs():
    """A B A B C per five, so any prefix stays balanced across attacks, benign and controls."""
    attacks = [spec_attack(*a) for a in ATTACKS]
    benign = [spec_benign(*b) for b in BENIGN]
    nulls = [dict(lab.NULLS[0], kind="null", name="null-%d" % i) for i in range(3)]
    controls = [{"kind": "none", "name": "background-only"} for _ in range(3)] + nulls
    rng = random.Random(SEED)
    rng.shuffle(attacks)
    rng.shuffle(benign)
    rng.shuffle(controls)
    order, ai, bi, ci = [], 0, 0, 0
    while ai < len(attacks) or bi < len(benign):
        for slot in "ABABC":
            if slot == "A" and ai < len(attacks):
                order.append(attacks[ai]); ai += 1
            elif slot == "B" and bi < len(benign):
                order.append(benign[bi]); bi += 1
            elif slot == "C" and ci < len(controls):
                order.append(controls[ci]); ci += 1
    order += controls[ci:]
    return order


def freeze(out_root=None):
    out_root = Path(out_root or HERE / "runs")
    plan = specs()
    tools = tool_set()
    for name in lab.GUEST_FILES:                 # guest scripts must be the pyexec-staging versions
        require((lab.GUEST / name).is_file(), "guest file missing: " + name)
    for s in plan:
        if s["kind"] == "null":
            s["sha256"] = M.member_sha256(lab.REV5 / s["archive"])
            s["archive_sha256"] = sha256(lab.REV5 / s["archive"])
    run_id = lab.stamp()
    attempt = out_root / run_id
    (attempt / "plans").mkdir(parents=True)
    (attempt / "fixtures").mkdir()               # none, but verify_main iterates it
    rng_t = random.Random(SEED + 2)
    sessions = []
    for i, spec in enumerate(plan, 1):
        s = dict(spec, sid="f%03d" % i, t_inject_s=round(rng_t.uniform(*lab.INJECT_RANGE), 3),
                 bg_seed=rng_t.randrange(1, 32768), marker="hz" + secrets.token_hex(6),
                 work="/tmp/" + secrets.token_hex(4))
        (attempt / "plans" / (s["sid"] + ".env")).write_text(M.plan_env(s))
        s["plan_sha256"] = sha256(attempt / "plans" / (s["sid"] + ".env"))
        sessions.append(s)
    counts = {}
    for s in sessions:
        counts[s["kind"]] = counts.get(s["kind"], 0) + 1
    protocol = {
        "format": lab.FORMAT, "plan": "flood", "run_id": run_id, "frozen_utc": now_utc(), "duration_s": lab.DUR_S,
        "inject_range_s": list(lab.INJECT_RANGE), "window_s": 0.5, "sessions": sessions, "counts": counts,
        "order_rule": "A B A B C per five; attacks = volumetric SYN/UDP (flood_gen) + Slowloris/GoldenEye (pyexec on "
                      "the published tools) + HTTP floods; benign = matched network-active shapes; controls = "
                      "background-only and nulls",
        "attack_check_relaxations": {
            "host_capacity_errors": "attack sessions: a connect-address-set overflow (HOSTMON_HEALTH lost=late="
                                    "failed=0, capacity>0) is accepted; those columns are not detector features",
            "capture_drop_tolerance": DROP_TOL,
            "capture_rule_attack": "accept when fetched, file hash matches, received = captured + dropped, and "
                                   "dropped/received <= %g; a silent loss or hash mismatch still rejects" % DROP_TOL,
            "benign_null_background": "strict checks unchanged (no drops, no capacity errors)"},
        "guest": {"vm": "Ubuntu-Clean-24.04", "baseline": lab.base.BASELINE, "baseline_uuid": lab.base.BASELINE_UUID,
                  "original": lab.base.ORIGINAL, "original_uuid": lab.base.ORIGINAL_UUID, "user": lab.GUEST_USER},
        "sink": {"vm": lab.SINK_VM, "capture": "tcpdump -i enp0s3 -n -U --immediate-mode -B 65536 -Z root (full frames)",
                 "capture_dir": lab.SINK_CAP, "sinkhole": "on during the sessions", "dns_answer": lab.DNS_REDIRECT,
                 "redirect_conf": lab.REDIRECT_DNSMASQ_CONF, "redirect_conf_sha256": lab.REDIRECT_CONF_SHA256,
                 "after": "sinkhole off, original dnsmasq (answers %s)" % lab.DNS_ORIGINAL},
        "files": {name: sha256(lab.GUEST / name) for name in lab.GUEST_FILES},
        "tools": {name: {"source": str(path), "sha256": want} for name, (path, want) in tools.items()},
        "fixtures": {}, "fixture_guest_root": M.REV5_GUEST_ROOT, "background_scale_pm": M.BG_SCALE_PM,
        "driver_sha256": sha256(lab.__file__), "main_driver_sha256": sha256(M.__file__),
        "flood_driver_sha256": sha256(__file__), "approval": None, "retries": False,
        "keep_going": "a rejected/failed session is recorded; %d in a row stop the run" % M.MAX_IN_A_ROW,
        "merge_with_any_dataset": False, "model_fitting": False,
        "limitations": ["one attacking machine, so a flood that completes its requests looks like a busy benign "
                        "client (real HTTP floods come from many machines; the switch would see that at the server)",
                        "generated background, not real users", "the Sink fakes services, no C2 protocol",
                        "VirtualBox helpers stay visible in the guest", "capture at the Sink, not the hardware switch",
                        "separate dataset; never merged with the paper's or any other collection"]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": sha256(attempt / "protocol.json"), "counts": counts,
                      "order": [(s["sid"], s["kind"], s["name"]) for s in sessions]}, indent=1))
    return attempt


def flood_checks(sdir, protocol, s, capture):
    """The strict per-session checks (run_session_lab.technical_checks), then two attack-only tolerances."""
    base = _ORIG_CHECKS(sdir, protocol, s, capture)
    if s["kind"] != "attack":
        return base
    kept = []
    for r in base["reasons"]:
        if ": health ['HOSTMON_HEALTH," in r:
            try:
                nums = [int(x) for x in r.split("HOSTMON_HEALTH,", 1)[1].rstrip("']").split(",")]
            except ValueError:
                nums = None
            if nums and len(nums) == 4 and nums[0] == 0 and nums[2] == 0 and nums[3] == 0:
                continue                                 # capacity-only overflow: allowed for floods
        if r.startswith("capture "):
            c = capture.get("counters", {})
            rcv, cap, drp = c.get("received"), c.get("captured"), c.get("dropped", 0)
            if (capture.get("fetched") and capture.get("sha256") == capture.get("sink_sha256")
                    and rcv is not None and cap is not None and rcv == cap + (drp or 0)
                    and rcv > 0 and (drp or 0) / rcv <= DROP_TOL):
                continue                                 # consistent capture, tiny drop fraction
        kept.append(r)
    return dict(base, reasons=kept, accepted=not kept, relaxed=(base["reasons"] != kept))


_ORIG_CHECKS = lab.technical_checks


def run_all(attempt, expected, approval):
    lab.technical_checks = flood_checks          # run_session looks this up as a module global at call time
    try:
        M.run_all(Path(attempt).resolve(), expected, approval)
    finally:
        lab.technical_checks = _ORIG_CHECKS


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--freeze-only", action="store_true")
    p.add_argument("--run-all", action="store_true")
    p.add_argument("--attempt")
    p.add_argument("--protocol-sha256")
    p.add_argument("--approval")
    a = p.parse_args()
    if a.freeze_only:
        freeze()
    elif a.run_all:
        run_all(a.attempt, a.protocol_sha256, a.approval)
    else:
        p.error("choose --freeze-only or --run-all")


if __name__ == "__main__":
    main()

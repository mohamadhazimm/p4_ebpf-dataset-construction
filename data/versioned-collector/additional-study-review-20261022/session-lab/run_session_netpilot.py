#!/usr/bin/env python3
"""Session lab, network-active pilot (user approval "yes please", 2026-11-16).

One sample of each new family that used the network on Triage's internet sandbox (../network-census-20261116/;
quarantine data/malware/revision5-diverse/network-census-20261116/), network-using benign programs (the dataset's
network tasks, round-robin over their projects, and the lab's network tools), and controls, interleaved
M B M B C. Everything else is the main collection's: the pilot driver's phases, Sink capture and per-session
checks (run_session_lab.py), the main driver's keep-going session loop, fixture staging and 4-times-faster
background (run_session_main.py). The only change is where the archives come from: netpilot-samples/ holds AES
zips of the chosen new samples (one member <sha256>.elf, password "infected", as the dataset's transports) and
copies of the dataset's benign and null archives; the pilot driver's archive folder is pointed there.

  /usr/bin/python3 run_session_netpilot.py --build-samples   # the zips and copies (host-side; nothing is run)
  /usr/bin/python3 run_session_netpilot.py --freeze-only
  /usr/bin/python3 run_session_netpilot.py --run-all --attempt DIR --protocol-sha256 SHA --approval "<words>"
"""
import argparse
import hashlib
import json
import random
import secrets
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run_session_lab as lab   # noqa: E402
import run_session_main as M    # noqa: E402

require, sha256, save, load, now_utc = lab.require, lab.sha256, lab.save, lab.load, lab.now_utc
STUDY = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010")
QUAR = STUDY / "data/malware/revision5-diverse/network-census-20261116"
REV5_SAMPLES = lab.REV5
NET_SAMPLES = HERE / "netpilot-samples"
lab.REV5 = NET_SAMPLES          # every archive lookup of the pilot driver now reads this folder
SEED = 4244


def chosen_malware():
    """One accepted sample per family, chosen with a seeded draw from the family's samples sorted by SHA-256."""
    acc = load(QUAR / "manifest.json")["accepted"]
    rng = random.Random(SEED)
    out = []
    for fam in sorted({r["family"] for r in acc}):
        pool = sorted((r for r in acc if r["family"] == fam), key=lambda r: r["sha256"])
        r = rng.choice(pool)
        out.append({"sha256": r["sha256"], "family": fam, "mode": "native_" + r["mode"], "category": r["category"],
                    "triage_class": r["triage_class"], "triage_flows": r["triage_flows"]})
    return out


def benign_specs(rng):
    cases = load(M.PAYLOAD / "cases.json")
    by_project = {}
    for c in cases:
        if c["label"] == "benign" and c.get("network"):
            args = load(M.PAYLOAD / "arguments" / (c["sample"] + ".json"))
            by_project.setdefault(c["project"], []).append(
                {"kind": "benign", "name": "%s-%s-%s" % (c["program"], c["project"], c["sample"][-12:-4]),
                 "program": c["program"], "project": c["project"], "mode": c["mode"], "network": True,
                 "source": "archive", "archive": c["sample"], "args": args, "fixtures": M.fixture_paths(args)})
    dataset = M.round_robin(by_project, rng)
    tools = [dict(b, kind="benign", network=True) for b in lab.BENIGN
             if b["name"] in ("download-burst", "browse-public", "checkin-public", "dns-poll")]
    return dataset, tools


def specs():
    rng = random.Random(SEED + 1)
    malware = [lab.spec_malware(m["sha256"], m["family"], m["mode"]) for m in chosen_malware()]
    rng.shuffle(malware)
    dataset, tools = benign_specs(rng)
    benign = tools + dataset[:len(malware) - len(tools)]
    rng.shuffle(benign)
    controls = [{"kind": "none", "name": "background-only"} for _ in range(6)]
    controls.insert(3, dict(lab.NULLS[0], kind="null"))
    order, mi, bi, ci = [], 0, 0, 0
    while mi < len(malware) or bi < len(benign):
        for slot in "MBMBC":
            if slot == "M" and mi < len(malware):
                order.append(malware[mi]); mi += 1
            elif slot == "B" and bi < len(benign):
                order.append(benign[bi]); bi += 1
            elif slot == "C" and ci < len(controls):
                order.append(controls[ci]); ci += 1
    return order


def build_samples():
    """AES zips of the chosen new samples (as the dataset's transports) and copies of the archives the plan uses."""
    NET_SAMPLES.mkdir(exist_ok=True)
    made = {}
    for m in chosen_malware():
        out = NET_SAMPLES / (m["sha256"] + ".zip")
        if not out.exists():
            elf = m["sha256"] + ".elf"
            require(sha256(QUAR / elf) == m["sha256"], "quarantined file differs: " + elf)
            subprocess.run(["7z", "a", "-tzip", "-mem=AES128", "-pinfected", str(out), elf], cwd=QUAR, check=True,
                           capture_output=True)
        lab.rsm.verify_archive(out, m["sha256"])            # one member, its SHA-256 (streamed, nothing written)
        made[out.name] = sha256(out)
    for s in specs():
        if s.get("source") == "archive" and s["kind"] != "malware":
            dst = NET_SAMPLES / s["archive"]
            if not dst.exists():
                shutil.copy2(REV5_SAMPLES / s["archive"], dst)
            require(sha256(dst) == sha256(REV5_SAMPLES / s["archive"]), "copy differs: " + s["archive"])
            made[dst.name] = sha256(dst)
    print(json.dumps(made, indent=1))
    return made


def freeze(out_root=None):
    out_root = Path(out_root or HERE / "runs")
    plan = specs()
    for name, (path, want) in lab.TOOLS.items():
        require(Path(path).is_file() and sha256(path) == want, "tool %s missing or changed" % name)
    for s in plan:
        if s.get("source") != "archive":
            continue
        path = NET_SAMPLES / s["archive"]
        require(path.is_file(), "archive missing (run --build-samples): " + s["archive"])
        if s["kind"] == "malware":
            lab.rsm.verify_archive(path, s["sha256"])
        else:
            s["sha256"] = M.member_sha256(path)
        s["archive_sha256"] = sha256(path)
    run_id = lab.stamp()
    attempt = out_root / run_id
    (attempt / "plans").mkdir(parents=True)
    (attempt / "fixtures").mkdir()
    tars = {}
    for s in plan:
        if s.get("fixtures"):
            key = tuple(s["fixtures"])
            if key not in tars:
                name = "fixtures-%s.tar" % hashlib.sha256("\n".join(key).encode()).hexdigest()[:12]
                with tarfile.open(attempt / "fixtures" / name, "w") as tar:
                    for rel in key:
                        tar.add(M.PAYLOAD / rel, arcname=(M.REV5_GUEST_ROOT + rel).lstrip("/"))
                tars[key] = name
            s["fixtures_tar"] = tars[key]
    rng_t = random.Random(SEED + 2)
    sessions = []
    for i, spec in enumerate(plan, 1):
        s = dict(spec, sid="n%03d" % i, t_inject_s=round(rng_t.uniform(*lab.INJECT_RANGE), 3),
                 bg_seed=rng_t.randrange(1, 32768), marker="hz" + secrets.token_hex(6),
                 work="/tmp/" + secrets.token_hex(4))
        (attempt / "plans" / (s["sid"] + ".env")).write_text(M.plan_env(s))
        s["plan_sha256"] = sha256(attempt / "plans" / (s["sid"] + ".env"))
        sessions.append(s)
    counts = {}
    for s in sessions:
        counts[s["kind"]] = counts.get(s["kind"], 0) + 1
    chosen = chosen_malware()
    protocol = {
        "format": lab.FORMAT, "plan": "netpilot", "run_id": run_id, "frozen_utc": now_utc(), "duration_s": lab.DUR_S,
        "inject_range_s": list(lab.INJECT_RANGE), "window_s": 0.5, "sessions": sessions, "counts": counts,
        "order_rule": "M B M B C per five sessions; one sample per new family (seeded draw), benign: the lab's four "
                      "network tools and the dataset's network tasks round-robin over projects; controls: six "
                      "background-only and one null",
        "malware_selection": {"source": "network-census-20261116: Triage x86 Linux ELF with the sample's own network "
                                        "activity on Triage's internet sandbox; families not in the dataset; "
                                        "strict ELF mode (static-PIE rejected)", "seed": SEED, "chosen": chosen,
                              "quarantine_manifest_sha256": sha256(QUAR / "manifest.json")},
        "guest": {"vm": "Ubuntu-Clean-24.04", "baseline": lab.base.BASELINE, "baseline_uuid": lab.base.BASELINE_UUID,
                  "original": lab.base.ORIGINAL, "original_uuid": lab.base.ORIGINAL_UUID, "user": lab.GUEST_USER},
        "sink": {"vm": lab.SINK_VM, "capture": "tcpdump -i enp0s3 -n -U --immediate-mode -B 65536 -Z root",
                 "capture_dir": lab.SINK_CAP, "sinkhole": "on during the sessions", "dns_answer": lab.DNS_REDIRECT,
                 "redirect_conf": lab.REDIRECT_DNSMASQ_CONF, "redirect_conf_sha256": lab.REDIRECT_CONF_SHA256,
                 "after": "sinkhole off, original dnsmasq"},
        "files": {name: sha256(lab.GUEST / name) for name in lab.GUEST_FILES},
        "tools": {name: {"source": str(path), "sha256": want} for name, (path, want) in lab.TOOLS.items()},
        "fixtures": {name: sha256(attempt / "fixtures" / name) for name in sorted(set(tars.values()))},
        "fixture_guest_root": M.REV5_GUEST_ROOT, "samples_dir": str(NET_SAMPLES),
        "background_scale_pm": M.BG_SCALE_PM,
        "driver_sha256": sha256(lab.__file__), "main_driver_sha256": sha256(M.__file__),
        "netpilot_driver_sha256": sha256(__file__), "approval": None, "retries": False,
        "keep_going": "a rejected/failed session is recorded; %d in a row stop the run" % M.MAX_IN_A_ROW,
        "merge_with_any_dataset": False, "model_fitting": False,
        "limitations": ["samples chosen because they used the network on Triage: the network view's recall on them "
                        "is optimistic", "family labels are Triage's, not verified", "generated background",
                        "the Sink fakes services, no C2 protocol", "VirtualBox helpers stay visible in the guest",
                        "capture at the Sink, not the hardware switch", "separate collection; never merged"]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": sha256(attempt / "protocol.json"), "counts": counts,
                      "order": [(s["sid"], s["kind"], s["name"]) for s in sessions]}, indent=1))
    return attempt


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--build-samples", action="store_true")
    p.add_argument("--freeze-only", action="store_true")
    p.add_argument("--run-all", action="store_true")
    p.add_argument("--attempt")
    p.add_argument("--protocol-sha256")
    p.add_argument("--approval")
    a = p.parse_args()
    if a.build_samples:
        build_samples()
    elif a.freeze_only:
        freeze()
    elif a.run_all:
        M.run_all(Path(a.attempt).resolve(), a.protocol_sha256, a.approval)
    else:
        p.error("choose --build-samples, --freeze-only or --run-all")


if __name__ == "__main__":
    main()

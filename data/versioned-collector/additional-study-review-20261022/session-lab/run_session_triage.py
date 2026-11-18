#!/usr/bin/env python3
"""Session lab, Triage network-active cohort (user approval 2026-11-16: "lets do the first bullet point of
proposed design"). The today-pulled Triage families (network-census-20261116), capped so near-duplicate families
don't dominate, injected into the busy background like the main run, with mode-matched dataset benign + controls.

Pre-registered expectations (recorded in the protocol): these families were CHOSEN because they network on Triage,
so any network-view recall is optimistic by selection -- that is not the result. The one question this cohort can
answer is whether, for the host-quiet C2/backdoor implants (rekoobe/sliver/vshell/adaptixc2/ladvix, ~24 samples
running at 289-1038 syscalls in the pilot), the network view catches what the host view misses. Expectation: host
strong on the loud half (miners/scanners/DDoS bots), weak on the quiet half; network present for all but faint for
the quiet beacons against the sinkhole; hybrid ~ host overall, with a possible edge only if a quiet subset is
host-silent yet keeps a visible flow. echobot (200k+ flows on Triage) may host-storm and be rejected; some C2
implants may beacon once and wait. Family labels are Triage's; near-duplicate families capped; separate cohort,
never merged.

Everything else is the main collection's: the pilot driver's phases/Sink/checks (run_session_lab.py), the main
driver's keep-going loop, 4x background, benign fixtures (run_session_main.py). Malware archives are AES zips of the
quarantined samples (one member <sha256>.elf, password "infected"); benign/null archives are copies of the dataset's.

  /usr/bin/python3 run_session_triage.py --build-samples
  /usr/bin/python3 run_session_triage.py --freeze-only
  /usr/bin/python3 run_session_triage.py --run-all --attempt DIR --protocol-sha256 SHA --approval "<user's words>"
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
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run_session_lab as lab   # noqa: E402
import run_session_main as M    # noqa: E402

require, sha256, save, load, now_utc = lab.require, lab.sha256, lab.save, lab.load, lab.now_utc
STUDY = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010")
QUAR = STUDY / "data/malware/revision5-diverse/network-census-20261116"
REV5_SAMPLES = lab.REV5
TRIAGE_SAMPLES = HERE / "triage-cohort-samples"
lab.REV5 = TRIAGE_SAMPLES          # every archive lookup of the driver now reads this one folder
CAP = {"rekoobe": 6, "sliver": 6, "vshell": 6, "flylegitbot": 6}      # cap the near-duplicate families
N_BENIGN = 40
SEED = 4247


def chosen_malware():
    """The capped selection: <=CAP[family] per big family (mode-spread), all of the smaller families; deterministic."""
    acc = load(QUAR / "manifest.json")["accepted"]
    byfam = defaultdict(list)
    for r in acc:
        byfam[r["family"]].append(r)
    out = []
    for fam in sorted(byfam):
        bymode = defaultdict(list)
        for r in sorted(byfam[fam], key=lambda r: r["sha256"]):
            bymode[r["mode"]].append(r)
        modes = sorted(bymode)
        cap, i = CAP.get(fam, len(byfam[fam])), 0
        picked = []
        while len(picked) < cap and any(bymode[m] for m in modes):
            m = modes[i % len(modes)]
            if bymode[m]:
                picked.append(bymode[m].pop(0))
            i += 1
        out += [{"sha256": r["sha256"], "family": fam, "mode": "native_" + r["mode"], "category": r["category"],
                 "triage_class": r["triage_class"], "triage_flows": r["triage_flows"]} for r in picked]
    return out


def benign_specs(rng):
    """~N_BENIGN dataset benign tasks (network + CLI, with their fixtures), round-robin over projects + the lab's
    four network tools; mode spread follows the malware (amd64-static heavy)."""
    cases = load(M.PAYLOAD / "cases.json")
    by_project = {}
    for c in cases:
        if c["label"] != "benign":
            continue
        args = load(M.PAYLOAD / "arguments" / (c["sample"] + ".json"))
        by_project.setdefault(c["project"], []).append(
            {"kind": "benign", "name": "%s-%s-%s" % (c["program"], c["project"], c["sample"][-12:-4]),
             "program": c["program"], "project": c["project"], "mode": c["mode"], "network": bool(c.get("network")),
             "source": "archive", "archive": c["sample"], "args": args, "fixtures": M.fixture_paths(args)})
    dataset = M.round_robin(by_project, rng)[:N_BENIGN]
    tools = [dict(b, kind="benign", network=True) for b in lab.BENIGN
             if b["name"] in ("download-burst", "browse-public", "checkin-public", "dns-poll")]
    return tools + dataset


def specs():
    """Strict malware / non-malware alternation (M X M X ... ), so no two malware are adjacent: a run-stopping
    3-rejections-in-a-row can't come from clustered malware (e.g. an echobot host-storm next to a boot hang)."""
    rng = random.Random(SEED + 1)
    malware = [lab.spec_malware(m["sha256"], m["family"], m["mode"]) for m in chosen_malware()]
    rng.shuffle(malware)
    benign = benign_specs(rng)
    nulls = [{"kind": "null", "name": n[:-4], "source": "archive", "archive": n,
              "args": load(M.PAYLOAD / "arguments" / (n + ".json"))} for n in M.NULLS]
    other = benign + [{"kind": "none", "name": "background-only"} for _ in range(6)] + nulls
    rng.shuffle(other)
    order = []
    for i in range(max(len(malware), len(other))):
        if i < len(malware):
            order.append(malware[i])
        if i < len(other):
            order.append(other[i])
    return order


def build_samples():
    """AES zips of the capped Triage malware (as the dataset's transports) and copies of the dataset archives used."""
    TRIAGE_SAMPLES.mkdir(exist_ok=True)
    made = {}
    for m in chosen_malware():
        out = TRIAGE_SAMPLES / (m["sha256"] + ".zip")
        if not out.exists():
            elf = m["sha256"] + ".elf"
            require(sha256(QUAR / elf) == m["sha256"], "quarantined file differs: " + elf)
            subprocess.run(["7z", "a", "-tzip", "-mem=AES128", "-pinfected", str(out), elf], cwd=QUAR, check=True,
                           capture_output=True)
        lab.rsm.verify_archive(out, m["sha256"])
        made[out.name] = sha256(out)
    for s in specs():
        if s.get("source") == "archive" and s["kind"] != "malware":
            dst = TRIAGE_SAMPLES / s["archive"]
            if not dst.exists():
                shutil.copy2(REV5_SAMPLES / s["archive"], dst)
            require(sha256(dst) == sha256(REV5_SAMPLES / s["archive"]), "copy differs: " + s["archive"])
            made[dst.name] = sha256(dst)
    print(json.dumps({"malware_zips": sum(1 for k in made if len(k) == 68),
                      "benign_null_copies": sum(1 for k in made if len(k) != 68), "total": len(made)}, indent=1))
    return made


def freeze(out_root=None):
    out_root = Path(out_root or HERE / "runs")
    plan = specs()
    for name, (path, want) in lab.TOOLS.items():
        require(Path(path).is_file() and sha256(path) == want, "tool %s missing or changed" % name)
    for s in plan:
        if s.get("source") != "archive":
            continue
        path = TRIAGE_SAMPLES / s["archive"]
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
    for s in plan:                                   # benign fixtures (as run_session_main.freeze)
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
        s = dict(spec, sid="t%03d" % i, t_inject_s=round(rng_t.uniform(*lab.INJECT_RANGE), 3),
                 bg_seed=rng_t.randrange(1, 32768), marker="hz" + secrets.token_hex(6),
                 work="/tmp/" + secrets.token_hex(4))
        (attempt / "plans" / (s["sid"] + ".env")).write_text(M.plan_env(s))
        s["plan_sha256"] = sha256(attempt / "plans" / (s["sid"] + ".env"))
        sessions.append(s)
    counts = {}
    for s in sessions:
        counts[s["kind"]] = counts.get(s["kind"], 0) + 1
    chosen = chosen_malware()
    fam = {}
    for m in chosen:
        fam[m["family"]] = fam.get(m["family"], 0) + 1
    protocol = {
        "format": lab.FORMAT, "plan": "triage-cohort", "run_id": run_id, "frozen_utc": now_utc(),
        "duration_s": lab.DUR_S, "inject_range_s": list(lab.INJECT_RANGE), "window_s": 0.5, "sessions": sessions,
        "counts": counts, "order_rule": "strict malware / non-malware alternation (no two malware adjacent)",
        "malware_check_relaxation": "malware sessions: a capacity-only overflow of the host monitor's 64-slot "
                                    "connect-address set (HOSTMON_HEALTH lost=late=failed=0, capacity>0) is accepted "
                                    "-- the full syscall stream is present so the 18 host features are complete, and "
                                    "the overflowed unique-IP/port counters are not detector features (scanner "
                                    "families fritzfrog/xmrig). Event loss (lost>0), late/failed, packet drops and "
                                    "silent loss still reject; benign/null/background keep strict checks. Consistent "
                                    "with the flood batch; the paper rejected on event loss, never on capacity-only.",
        "malware_selection": {"source": "network-census-20261116 (Triage x86 Linux ELF with the sample's own network "
                                        "activity on Triage's internet sandbox); strict ELF mode (static-PIE rejected)",
                              "cap": CAP, "families": fam, "n": len(chosen),
                              "quarantine_manifest_sha256": sha256(QUAR / "manifest.json")},
        "expectations": {
            "selection_bias": "families chosen because they network -> network-view recall is optimistic; NOT the result",
            "the_question": "for the host-quiet C2/backdoor implants (rekoobe/sliver/vshell/adaptixc2/ladvix), does "
                            "the network view catch what the host view misses?",
            "host": "strong on the loud half (miners/scanners/DDoS bots), weak on the quiet implants",
            "network": "present for all (selected), faint for the quiet beacons against the sinkhole",
            "hybrid": "~ host overall; an edge only if a quiet subset is host-silent yet network-visible",
            "echobot": "200k+ flows on Triage -> may host-storm and be rejected (strict malware checks unchanged)",
            "primary_metric": "whether the network/hybrid ADDS over host on the C2/backdoor subset, not overall BA"},
        "guest": {"vm": "Ubuntu-Clean-24.04", "baseline": lab.base.BASELINE, "baseline_uuid": lab.base.BASELINE_UUID,
                  "original": lab.base.ORIGINAL, "original_uuid": lab.base.ORIGINAL_UUID, "user": lab.GUEST_USER},
        "sink": {"vm": lab.SINK_VM, "capture": "tcpdump -i enp0s3 -n -U --immediate-mode -B 65536 -Z root (full frames)",
                 "capture_dir": lab.SINK_CAP, "sinkhole": "on during the sessions", "dns_answer": lab.DNS_REDIRECT,
                 "redirect_conf": lab.REDIRECT_DNSMASQ_CONF, "redirect_conf_sha256": lab.REDIRECT_CONF_SHA256,
                 "after": "sinkhole off, original dnsmasq"},
        "files": {name: sha256(lab.GUEST / name) for name in lab.GUEST_FILES},
        "tools": {name: {"source": str(path), "sha256": want} for name, (path, want) in lab.TOOLS.items()},
        "fixtures": {name: sha256(attempt / "fixtures" / name) for name in sorted(set(tars.values()))},
        "fixture_guest_root": M.REV5_GUEST_ROOT, "samples_dir": str(TRIAGE_SAMPLES), "background_scale_pm": M.BG_SCALE_PM,
        "driver_sha256": sha256(lab.__file__), "main_driver_sha256": sha256(M.__file__),
        "triage_driver_sha256": sha256(__file__), "approval": None, "retries": False,
        "keep_going": "a rejected/failed session is recorded; %d in a row stop the run" % M.MAX_IN_A_ROW,
        "merge_with_any_dataset": False, "model_fitting": False,
        "limitations": ["chosen because they network -> network-view recall optimistic", "family labels are Triage's",
                        "near-duplicate families capped (effective diversity < 13)", "generated background",
                        "the Sink fakes services, no C2 protocol", "VirtualBox helpers stay visible in the guest",
                        "capture at the Sink, not the hardware switch", "separate cohort; never merged"]}
    save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "protocol_sha256": sha256(attempt / "protocol.json"), "counts": counts,
                      "malware_families": fam}, indent=1))
    return attempt


def triage_checks(sdir, protocol, s, capture):
    """Strict per-session checks (run_session_lab.technical_checks), then one malware-only tolerance: a capacity-only
    overflow of the host monitor's 64-slot connect-address set (HOSTMON_HEALTH lost=late=failed=0, capacity>0) does
    not reject -- the full syscall stream is present (lost=0), so the 18 ADFA host features are complete, and the
    overflowed unique-IP/port counters are not detector features (scanner families fritzfrog/xmrig hit this). Real
    event loss (lost>0 = corrupted features), late/failed, packet drops and silent loss still reject, for every kind.
    Benign/null/background keep the strict checks unchanged."""
    base = _ORIG_CHECKS(sdir, protocol, s, capture)
    if s["kind"] != "malware":
        return base
    kept = []
    for r in base["reasons"]:
        if ": health ['HOSTMON_HEALTH," in r:
            try:
                nums = [int(x) for x in r.split("HOSTMON_HEALTH,", 1)[1].rstrip("']").split(",")]
            except ValueError:
                nums = None
            if nums and len(nums) == 4 and nums[0] == 0 and nums[2] == 0 and nums[3] == 0:
                continue                                 # capacity-only overflow: syscall stream intact
        kept.append(r)
    return dict(base, reasons=kept, accepted=not kept, relaxed=(base["reasons"] != kept))


_ORIG_CHECKS = lab.technical_checks


def run_all(attempt, expected, approval):
    lab.technical_checks = triage_checks         # run_session looks this up as a module global at call time
    try:
        M.run_all(Path(attempt).resolve(), expected, approval)
    finally:
        lab.technical_checks = _ORIG_CHECKS


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
        run_all(a.attempt, a.protocol_sha256, a.approval)
    else:
        p.error("choose --build-samples, --freeze-only or --run-all")


if __name__ == "__main__":
    main()

"""Assemble the observation-length pilot payload: 5 malware + 5 long benign + 3 null, for 5-minute (600-window) runs.

Goal: measure whether a 5-minute observation reveals signal that the 20-second observation truncates. The 5 malware
are the ones that were still active at the 20 s cutoff AND at a rate that survives 5 minutes without overflowing the
kernel buffer (CatStorm/Chaos were excluded: they sustain ~100-190k syscalls/s -> 31-58M events in 5 min). Their
transports are REUSED VERBATIM from the frozen revision5 payload (same AES zips, member hash already verified there,
never executed on the host). The 3 null transports are likewise reused verbatim (they also verify the guest stays
quiet for the full 5 minutes, previously checked only to ~4 min). The 5 benign are long-running workloads
(benign_workloads_long) that stay active the whole 5 minutes and are then truncated at 300 s exactly like the malware,
so each run is a fair control.

Layout is the batch's: samples/<case>.zip + arguments/<case>.zip.json + fixtures/pilot/..., with cases.json. Reuses
build_v21_payload's plain_zip/sha256_bytes/interleave. No VM, no sample execution; only benign data/fixtures created.
"""

import json
import shutil
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import build_v21_payload as v21b          # noqa: E402  plain_zip / sha256_bytes / interleave
import benign_workloads_long as bwl       # noqa: E402  the 5 long workloads + fixtures

STUDY = ROOT.parents[2]
REV5_PAYLOAD = ROOT / "revision5-collection/20261025T100025568989Z/payload"

# 5 malware: late-active at 20 s AND sustainable over 5 min. Reused verbatim from the revision5 payload (flat layout;
# leaf name is <sha>.zip and the AES member hash, verified at the revision5 freeze). (leaf, mode, family-note).
MALWARE_CASES = [
    ("478053ea93052dd3f1477cf497443c0cb1b0e75361ba3927b929b707c18f35e2.zip", "native_amd64_static", "Gafgyt"),
    ("765b0ad71a4f15f380e9c567d25be85ca88979bc0d64407a637987bb0a3b21fc.zip", "native_amd64_static", "Prometei"),
    ("8124f4ac27a1afb25d2479da9bf5f06c52e3e9cf25d4d514ec386f05e264dd14.zip", "native_amd64_static", "CoinMiner"),
    ("87ec57bd8e639d5f96a17dfb73af5cc63cc528f45d4a3231e70f287e9ad38601.zip", "native_i386_static", "Katana"),
    ("47b6ecba4e77e4fce84fe768b11d8bde2936938c2ae07a35aa9aa8f7fe6fe192.zip", "native_i386_static", "Kaiji"),
]
# One null per mode present, reused verbatim.
NULL_SAMPLES = {
    "native_amd64_static": "null-native_amd64_static-start.zip",
    "native_i386_static": "null-native_i386_static-start.zip",
    "native_amd64_dynamic": "null-native_amd64_dynamic-start.zip",
}
# 5 long benign: (program, mode, binary path relative to STUDY). Static where possible for self-containment.
BENIGN = [
    ("openssl", "native_amd64_static",
     "data/versioned-collector/additional-study-review-20261022/amd64-network-builds/20261024T172720Z/bin/openssl"),
    ("sqlite3", "native_i386_static",
     "data/versioned-collector/cohort-expansion-100x100-v18-20261021/i386-heldout-amendment/20261021T201119747468Z"
     "/workload-preflight/20261021T202315585576Z/binaries/i386-sqlite3-sqlite3/sqlite3"),
    ("rsync", "native_amd64_dynamic",
     "data/versioned-collector/cohort-100x100-v18-20261021/redesign-native-x64/payload/samples/rsync"),
    ("ping", "native_i386_static",   # i386 musl ping: the revision5-proven binary that reached the Sink unprivileged
     "data/versioned-collector/additional-study-review-20261022/i386-network-builds/20261024T163419Z/bin/ping"),
    ("wget", "native_amd64_static",
     "data/versioned-collector/additional-study-review-20261022/amd64-network-builds/20261024T172720Z/bin/wget"),
]


def _interleave(cases):
    """Deterministic pilot order: one null per mode first (quiet checkpoints), then malware and benign alternated
    under a fixed seed so neither class clusters. Small and self-contained; the 20-s protocol's interleave is tuned
    to the revision5 case schema and not reused here."""
    import random
    nulls = sorted((c for c in cases if c["label"] == "null"), key=lambda c: c["mode"])
    mal = sorted((c for c in cases if c["label"] == "malware"), key=lambda c: c["sample"])
    ben = sorted((c for c in cases if c["label"] == "benign"), key=lambda c: c["sample"])
    rng = random.Random(42)
    rng.shuffle(mal)
    rng.shuffle(ben)
    interleaved = []
    for a, b in zip(mal, ben):
        interleaved += [a, b]
    interleaved += mal[len(ben):] + ben[len(mal):]
    return nulls + interleaved


def _reuse(out, name_in_rev5, label, mode, extra, manifest, cases):
    """Copy a transport zip + its arguments verbatim from the revision5 payload."""
    src_zip = REV5_PAYLOAD / "samples" / name_in_rev5
    src_arg = REV5_PAYLOAD / "arguments" / (name_in_rev5 + ".json")
    blob = src_zip.read_bytes()
    (out / "samples" / name_in_rev5).write_bytes(blob)
    (out / "arguments" / (name_in_rev5 + ".json")).write_bytes(src_arg.read_bytes())
    manifest["samples"][name_in_rev5] = v21b.sha256_bytes(blob)
    cases.append({"sample": name_in_rev5, "label": label, "mode": mode, "network": False, **extra})


def build(out_dir, guest_root):
    out = Path(out_dir)
    for sub in ("samples", "arguments", "fixtures/pilot"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    manifest = {"samples": {}, "arguments": {}, "benign_binaries": {}}
    cases = []
    fixdir = out / "fixtures/pilot"
    fixcache = {}

    # ---- malware: reuse verbatim; the leaf name (sha.zip) is the AES member hash, verified at the revision5 freeze.
    for leaf, mode, family in MALWARE_CASES:
        shutil.copyfile(REV5_PAYLOAD / "samples" / leaf, out / "samples" / leaf)
        shutil.copyfile(REV5_PAYLOAD / "arguments" / (leaf + ".json"), out / "arguments" / (leaf + ".json"))
        blob = (out / "samples" / leaf).read_bytes()
        manifest["samples"][leaf] = v21b.sha256_bytes(blob)
        cases.append({"sample": leaf, "label": "malware", "mode": mode, "network": False,
                      "family": family, "expected_member_sha256": leaf[:-4]})

    # ---- benign: plain-zip the authenticated binary; stage long-workload fixtures; resolve argv to guest paths.
    for program, mode, relpath in BENIGN:
        binary = (STUDY / relpath).read_bytes()
        spec = bwl.long_workload(program)
        paths = {role: bwl.materialize(role, kind, size, fixdir, fixcache)
                 for role, kind, size in spec["fixtures"]}
        guest_paths = {role: guest_root.rstrip("/") + "/fixtures/pilot/" + p.name for role, p in paths.items()}
        args = bwl.resolve_argv(spec, guest_paths, ".")
        name = "%s-%s-pilot.zip" % (mode, program)
        blob = v21b.plain_zip(program, binary)
        (out / "samples" / name).write_bytes(blob)
        (out / "arguments" / (name + ".json")).write_text(json.dumps(args))
        manifest["samples"][name] = v21b.sha256_bytes(blob)
        manifest["benign_binaries"][program] = {"mode": mode, "sha256": v21b.sha256_bytes(binary), "relpath": relpath}
        cases.append({"sample": name, "label": "benign", "mode": mode, "network": spec["network"],
                      "program": program, "rc_ok": spec["rc_ok"]})

    # ---- nulls: reuse verbatim, one per mode; spot=start so interleave places them as openers.
    for mode, sample in NULL_SAMPLES.items():
        _reuse(out, sample, "null", mode, {"spot": "start"}, manifest, cases)

    for a in (out / "arguments").iterdir():
        manifest["arguments"][a.name] = v21b.sha256_bytes(a.read_bytes())

    order = _interleave(cases)
    for i, c in enumerate(order, 1):
        c["position"] = i
    (out / "cases.json").write_text(json.dumps(order, indent=2))
    (out / "cases.txt").write_text("".join(c["sample"] + "\n" for c in order))
    manifest["counts"] = dict(Counter(c["label"] for c in order))
    manifest["by_mode_label"] = {str(k): v for k, v in sorted(
        Counter((x["mode"], x["label"]) for x in order).items())}
    (out / "payload_manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest, order


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        manifest, order = build(Path(d) / "payload", "/home/csci/Downloads/pilot5min-selftest")
        assert manifest["counts"] == {"malware": 5, "benign": 5, "null": 3}, manifest["counts"]
        assert len(order) == 13
        print("PASS build_pilot_payload: counts", manifest["counts"])
        print("by mode/label:", manifest["by_mode_label"])
        print("order:", [c["sample"][:40] for c in order])

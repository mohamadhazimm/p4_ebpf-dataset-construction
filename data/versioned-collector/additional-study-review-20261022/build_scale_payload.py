"""Scaled observation-length cohort payload: ~50 malware + ~50 long benign + 3 null, each observed 5 min (600 windows).

Scale-up of the 10-case pilot after it showed malware do 70-93% of their behaviour (and >90% of their network) after
the 20 s mark. Malware are reused VERBATIM from the frozen revision5 payload (scale_malware_selection.json: 50 of the
97 sustainable families, capped 3/family, never executed on the host). Benign are the validated long workloads
(benign_workloads_long.scaled_variants) weighted toward the host/network-busy programs (rsync/wget/ping). Same batch
layout and helpers as build_pilot_payload; no VM, no sample execution.
"""

import json
import shutil
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import build_v21_payload as v21b          # noqa: E402
import benign_workloads_long as bwl       # noqa: E402

STUDY = ROOT.parents[2]
REV5_PAYLOAD = ROOT / "revision5-collection/20261025T100025568989Z/payload"
MALWARE_SEL = ROOT / "scale_malware_selection.json"
N_BENIGN = 50

# program -> (mode, binary path relative to STUDY). Static where possible for self-containment.
BENIGN_BIN = {
    "openssl": ("native_amd64_static",
                "data/versioned-collector/additional-study-review-20261022/amd64-network-builds/20261024T172720Z/bin/openssl"),
    "sqlite3": ("native_i386_static",
                "data/versioned-collector/cohort-expansion-100x100-v18-20261021/i386-heldout-amendment/20261021T201119747468Z"
                "/workload-preflight/20261021T202315585576Z/binaries/i386-sqlite3-sqlite3/sqlite3"),
    "rsync":   ("native_amd64_dynamic",
                "data/versioned-collector/cohort-100x100-v18-20261021/redesign-native-x64/payload/samples/rsync"),
    "ping":    ("native_i386_static",
                "data/versioned-collector/additional-study-review-20261022/i386-network-builds/20261024T163419Z/bin/ping"),
    "wget":    ("native_amd64_static",
                "data/versioned-collector/additional-study-review-20261022/amd64-network-builds/20261024T172720Z/bin/wget"),
}
NULL_SAMPLES = {
    "native_amd64_static": "null-native_amd64_static-start.zip",
    "native_i386_static": "null-native_i386_static-start.zip",
    "native_amd64_dynamic": "null-native_amd64_dynamic-start.zip",
}


def _interleave(cases):
    import random
    nulls = sorted((c for c in cases if c["label"] == "null"), key=lambda c: c["mode"])
    mal = sorted((c for c in cases if c["label"] == "malware"), key=lambda c: c["sample"])
    ben = sorted((c for c in cases if c["label"] == "benign"), key=lambda c: c["sample"])
    rng = random.Random(42)
    rng.shuffle(mal)
    rng.shuffle(ben)
    inter = []
    for a, b in zip(mal, ben):
        inter += [a, b]
    inter += mal[len(ben):] + ben[len(mal):]
    return nulls + inter


def build(out_dir, guest_root):
    out = Path(out_dir)
    for sub in ("samples", "arguments", "fixtures/pilot"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    manifest = {"samples": {}, "arguments": {}, "benign_binaries": {}}
    cases = []
    fixdir = out / "fixtures/pilot"
    fixcache = {}

    # ---- malware: reuse verbatim from the revision5 payload (leaf <sha>.zip = the AES member hash).
    malware = json.loads(MALWARE_SEL.read_text())
    for m in malware:
        leaf = m["sha"] + ".zip"
        shutil.copyfile(REV5_PAYLOAD / "samples" / leaf, out / "samples" / leaf)
        shutil.copyfile(REV5_PAYLOAD / "arguments" / (leaf + ".json"), out / "arguments" / (leaf + ".json"))
        blob = (out / "samples" / leaf).read_bytes()
        manifest["samples"][leaf] = v21b.sha256_bytes(blob)
        cases.append({"sample": leaf, "label": "malware", "mode": "native_" + m["mode"], "network": False,
                      "family": m["fam"], "expected_member_sha256": m["sha"]})

    # ---- benign: scaled long-workload variants; plain-zip the binary, stage fixtures, resolve argv to guest paths.
    variants = bwl.scaled_variants()[:N_BENIGN]
    for name, program, params in variants:
        mode, relpath = BENIGN_BIN[program]
        binary = (STUDY / relpath).read_bytes()
        spec = bwl.variant_workload(program, params)
        paths = {role: bwl.materialize(role, kind, size, fixdir, fixcache)
                 for role, kind, size in spec["fixtures"]}
        guest_paths = {role: guest_root.rstrip("/") + "/fixtures/pilot/" + p.name for role, p in paths.items()}
        args = bwl.resolve_argv(spec, guest_paths, ".")
        sample = "%s-%s.zip" % (mode, name)
        blob = v21b.plain_zip(program, binary)
        (out / "samples" / sample).write_bytes(blob)
        (out / "arguments" / (sample + ".json")).write_text(json.dumps(args))
        manifest["samples"][sample] = v21b.sha256_bytes(blob)
        manifest["benign_binaries"][name] = {"program": program, "mode": mode,
                                              "sha256": v21b.sha256_bytes(binary), "params": params}
        cases.append({"sample": sample, "label": "benign", "mode": mode, "network": spec["network"],
                      "program": program, "variant": name, "rc_ok": spec["rc_ok"]})

    # ---- nulls: reuse verbatim, one per mode present.
    for mode, sample in NULL_SAMPLES.items():
        blob = (REV5_PAYLOAD / "samples" / sample).read_bytes()
        (out / "samples" / sample).write_bytes(blob)
        shutil.copyfile(REV5_PAYLOAD / "arguments" / (sample + ".json"), out / "arguments" / (sample + ".json"))
        manifest["samples"][sample] = v21b.sha256_bytes(blob)
        cases.append({"sample": sample, "label": "null", "mode": mode, "network": False, "spot": "start"})

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
        manifest, order = build(Path(d) / "payload", "/home/csci/Downloads/scale5min-selftest")
        print("counts:", manifest["counts"])
        print("by mode/label:", manifest["by_mode_label"])
        print("benign programs:", dict(Counter(c.get("program") for c in order if c["label"] == "benign")))
        assert manifest["counts"]["null"] == 3 and manifest["counts"]["benign"] == 50
        print("total cases:", len(order), "| unique:", len({c["sample"] for c in order}))

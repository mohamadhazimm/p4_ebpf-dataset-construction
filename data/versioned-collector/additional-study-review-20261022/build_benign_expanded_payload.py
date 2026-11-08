"""Benign-only payload for the expanded 5-min benign cohort: ~45 expanded benign variants + 3 null, each observed 5 min
(600 windows). NO malware -- the ~100 malware are already collected (scale+topup+finish) on the same .22/300 s/quiet
baseline and are paired with this benign at analysis time (the cohort spans attempts, like the paper's 240-row set).

Benign binaries are shipped as plain zips (benign_host_gen / lowrate_gen / procps top,vmstat,free / findutils find /
coreutils sort / i386 wget,curl), fixtures staged, argv resolved to guest paths -- same layout/helpers as
build_scale_payload (imported). Nulls reused verbatim from the revision5 payload. No VM, no sample execution here.
find/sort fixture sizes come from benign_workloads_expanded (confirm with --verify before the real freeze).
"""

import json
import shutil
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import build_v21_payload as v21b                 # noqa: E402  sha256_bytes / plain_zip
import benign_workloads_expanded as be           # noqa: E402  variants / workload / BIN / fixtures

STUDY = ROOT.parents[2]
REV5_PAYLOAD = ROOT / "revision5-collection/20261025T100025568989Z/payload"
NULL_SAMPLES = {
    "native_amd64_static": "null-native_amd64_static-start.zip",
    "native_i386_static": "null-native_i386_static-start.zip",
    "native_amd64_dynamic": "null-native_amd64_dynamic-start.zip",
}
# exec member name inside each benign zip (what the runner execs; argv[0] is set by the runner)
EXEC_NAME = {"hostgen": "benign_host_gen", "lowrate": "lowrate_gen"}


def _interleave(cases):
    """3 nulls as opening quiet checkpoints, then the benign variants seed-42 shuffled."""
    import random
    nulls = sorted((c for c in cases if c["label"] == "null"), key=lambda c: c["mode"])
    ben = [c for c in cases if c["label"] == "benign"]
    random.Random(42).shuffle(ben)
    return nulls + ben


def build(out_dir, guest_root):
    out = Path(out_dir)
    for sub in ("samples", "arguments", "fixtures/pilot"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    manifest = {"samples": {}, "arguments": {}, "benign_binaries": {}}
    cases = []
    fixdir = out / "fixtures/pilot"
    fixcache = {}

    for name, program, params in be.expanded_variants():
        spec = be.workload(program, params)
        binpath = STUDY / be.BIN[spec["binary"]][1]
        binary = binpath.read_bytes()
        exec_name = EXEC_NAME.get(spec["binary"], spec["binary"])   # benign_host_gen/lowrate_gen or top/find/...
        paths = {role: be.materialize(kind, size, fixdir, fixcache) for role, kind, size in spec["fixtures"]}
        guest_paths = {role: guest_root.rstrip("/") + "/fixtures/pilot/" + p.name for role, p in paths.items()}
        args = be.resolve_argv_guest(spec, guest_paths) if hasattr(be, "resolve_argv_guest") \
            else be.bl.resolve_argv(spec, guest_paths, ".")
        sample = "%s-%s.zip" % (spec["mode"], name)
        blob = v21b.plain_zip(exec_name, binary)
        (out / "samples" / sample).write_bytes(blob)
        (out / "arguments" / (sample + ".json")).write_text(json.dumps(args))
        manifest["samples"][sample] = v21b.sha256_bytes(blob)
        manifest["benign_binaries"][name] = {"program": program, "group": spec["group"], "mode": spec["mode"],
                                              "binary": exec_name, "sha256": v21b.sha256_bytes(binary), "params": params}
        cases.append({"sample": sample, "label": "benign", "mode": spec["mode"], "network": spec["network"],
                      "program": spec["group"], "variant": name, "rc_ok": spec["rc_ok"]})

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
    manifest["by_group"] = {k: v for k, v in sorted(
        Counter(c["program"] for c in order if c["label"] == "benign").items())}
    (out / "payload_manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest, order


def _self_test():
    """Structural check with a TINY grid so no heavy fixtures are built (safe while the malware collect runs)."""
    import tempfile
    # shrink the grids for the self-test only
    # tiny but distinct under the //1000 naming (find/wget/curl names are "<n/1000>k")
    be.FIND_COUNTS[:] = [1000, 2000]
    be.SORT_MBS[:] = [1, 2]
    be.WGET_URLS[:] = [1000, 2000]
    be.CURL_URLS[:] = [1000, 2000]
    be.TOP_DELAYS[:] = [1, 2]
    be.VMSTAT_DELAYS[:] = [1, 2]
    be.FREE_DELAYS[:] = [1, 2]
    be.GEN_TREE_FILES = 20
    with tempfile.TemporaryDirectory() as d:
        manifest, order = build(Path(d) / "payload", "/home/csci/Downloads/benx5min-selftest")
        print("counts:", manifest["counts"])
        print("by group:", manifest["by_group"])
        print("by mode/label:", manifest["by_mode_label"])
        assert manifest["counts"]["null"] == 3, manifest["counts"]
        assert len({c["sample"] for c in order}) == len(order), "duplicate samples"
        # every arguments file references the guest root, none stale
        stale = [a.name for a in (Path(d) / "payload/arguments").glob("*.json")
                 if "/home/csci/Downloads/" in a.read_text() and "benx5min-selftest" not in a.read_text()]
        assert not stale, "stale guest-root: " + ",".join(stale)
        # benign member hashes match the on-disk binaries
        import zipfile, hashlib, io
        for name, program, params in be.expanded_variants():
            spec = be.workload(program, params)
            exec_name = EXEC_NAME.get(spec["binary"], spec["binary"])
            sample = "%s-%s.zip" % (spec["mode"], name)
            z = zipfile.ZipFile(io.BytesIO((Path(d) / "payload/samples" / sample).read_bytes()))
            member = z.read(exec_name)
            on_disk = (STUDY / be.BIN[spec["binary"]][1]).read_bytes()
            assert hashlib.sha256(member).hexdigest() == hashlib.sha256(on_disk).hexdigest(), sample
    print("PASS build_benign_expanded_payload self-test (tiny grid): %d cases, null 3, member hashes, no stale root"
          % len(order))


if __name__ == "__main__":
    _self_test()

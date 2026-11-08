"""Benign-only payload for the PACED-wget i386 follow-up: 5 paced wget variants + 3 null, each observed 5 min.

Applies the lesson from the benign-expanded run (curl-i386 overflowed the .22 4M cap and wget-i386-600k hit the
post-processing deadline because --limit-rate caps bandwidth, not request RATE). wget's `--wait=SECONDS` paces the
GET list at a fixed request rate, so each variant (a) stays under the cap, (b) spreads its GETs across the FULL 300 s
(no idle tail -- unlike the high-rate wget variants that finished early), and (c) spans a request-rate spectrum
(~0.5-10 req/s). These are MORE variants inside the existing 'wget' held-out group (not a new program); curl stays out
(curl 7.81 has no request-rate knob). Reuses be.workload("wget",...) + be.materialize + bl.resolve_argv unchanged;
only --wait is inserted into the argv. Nulls reused verbatim from the revision5 payload. No VM, no sample execution.
"""
import json
import shutil
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import build_v21_payload as v21b                 # noqa: E402  sha256_bytes / plain_zip
import benign_workloads_expanded as be           # noqa: E402  workload / BIN / materialize
import benign_workloads_long as bl               # noqa: E402  resolve_argv

STUDY = ROOT.parents[2]
REV5_PAYLOAD = ROOT / "revision5-collection/20261025T100025568989Z/payload"
NULL_SAMPLES = {
    "native_amd64_static": "null-native_amd64_static-start.zip",
    "native_i386_static": "null-native_i386_static-start.zip",
    "native_amd64_dynamic": "null-native_amd64_dynamic-start.zip",
}
# (name, wait_seconds, urls) -- urls = round(285/wait) so each finishes ~285 s (active nearly the whole 300 s window,
# never killed at the 300 s timeout). Spans ~0.5 req/s (w2000ms) to ~10 req/s (w100ms).
WGETP = [("wgetp-w%dms" % int(w * 1000), w, int(round(285 / w))) for w in (0.1, 0.25, 0.5, 1.0, 2.0)]


def _paced_spec(urls, wait):
    """Base i386 wget GET-list spec with --wait inserted after -q (everything else identical to be.workload)."""
    spec = be.workload("wget", {"urls": urls})            # i386 wget, Sink GET list, group 'wget'
    spec = dict(spec)
    spec["argv"] = ["-q", "--wait=%g" % wait] + list(spec["argv"][1:])
    return spec


def _interleave(cases):
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

    for name, wait, urls in WGETP:
        spec = _paced_spec(urls, wait)
        binpath = STUDY / be.BIN[spec["binary"]][1]
        binary = binpath.read_bytes()
        exec_name = spec["binary"]                         # "wget"
        paths = {role: be.materialize(kind, size, fixdir, fixcache) for role, kind, size in spec["fixtures"]}
        guest_paths = {role: guest_root.rstrip("/") + "/fixtures/pilot/" + p.name for role, p in paths.items()}
        args = bl.resolve_argv(spec, guest_paths, ".")
        sample = "%s-%s.zip" % (spec["mode"], name)
        blob = v21b.plain_zip(exec_name, binary)
        (out / "samples" / sample).write_bytes(blob)
        (out / "arguments" / (sample + ".json")).write_text(json.dumps(args))
        manifest["samples"][sample] = v21b.sha256_bytes(blob)
        manifest["benign_binaries"][name] = {"program": "wget", "group": "wget", "mode": spec["mode"],
                                              "binary": exec_name, "sha256": v21b.sha256_bytes(binary),
                                              "params": {"wait": wait, "urls": urls}}
        cases.append({"sample": sample, "label": "benign", "mode": spec["mode"], "network": True,
                      "program": "wget", "variant": name, "rc_ok": spec["rc_ok"]})

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
    import tempfile, zipfile, hashlib, io
    with tempfile.TemporaryDirectory() as d:
        manifest, order = build(Path(d) / "payload", "/home/csci/Downloads/wgetp-selftest")
        print("counts:", manifest["counts"], "| by_group:", manifest["by_group"],
              "| by_mode_label:", manifest["by_mode_label"])
        assert manifest["counts"]["null"] == 3 and manifest["counts"]["benign"] == 5, manifest["counts"]
        assert len({c["sample"] for c in order}) == len(order), "duplicate samples"
        assert set(c["program"] for c in order if c["label"] == "benign") == {"wget"}
        # every benign arg carries --wait and references the guest root (none stale)
        for c in order:
            if c["label"] != "benign":
                continue
            args = json.load(open(Path(d) / "payload/arguments" / (c["sample"] + ".json")))
            assert any(a.startswith("--wait=") for a in args), (c["sample"], args)
            assert any("/home/csci/Downloads/wgetp-selftest/" in a for a in args), args
        stale = [a.name for a in (Path(d) / "payload/arguments").glob("*.json")
                 if "/home/csci/Downloads/" in a.read_text() and "wgetp-selftest" not in a.read_text()]
        assert not stale, "stale guest-root: " + ",".join(stale)
        # benign member hash == on-disk i386 wget
        on_disk = (STUDY / be.BIN["wget"][1]).read_bytes()
        for c in order:
            if c["label"] != "benign":
                continue
            z = zipfile.ZipFile(io.BytesIO((Path(d) / "payload/samples" / c["sample"]).read_bytes()))
            assert hashlib.sha256(z.read("wget")).hexdigest() == hashlib.sha256(on_disk).hexdigest(), c["sample"]
    print("PASS build_wgetp_payload self-test: 5 paced wget (all --wait, group 'wget') + 3 null, member hashes, no stale root")


if __name__ == "__main__":
    _self_test()

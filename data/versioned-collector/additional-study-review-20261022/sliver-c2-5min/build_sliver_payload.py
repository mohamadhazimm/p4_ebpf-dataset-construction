"""Payload for the Sliver C2 testbed: 12 live-C2 implants + the sinkhole run's benign network clients + 3 null,
5 min each. Our own Sliver implants (sealed lab, both ends ours) supply the command phase the sinkhole run lacked.

MALICIOUS (12): our Sliver implants (beacons mtls/http/https/wg + sessions mtls/wg, ×a,b), linux amd64 dynamic,
  target 10.0.0.1 high ports (not redirected by the sinkhole). Grouped by transport+mode (6 groups).
BENIGN (28) + NULL (3): reused verbatim from build_sinkhole_c2_payload, so the benign side is identical to the
  sinkhole run and the two are directly comparable (the sinkhole is on during this collect for benign realism).

Layout is the batch's: samples/<case>.zip + arguments/<case>.zip.json + fixtures/sinkholec2/... + cases.json.
No VM, no sample execution.
"""
import io
import json
import shutil
import sys
import zipfile
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import build_sinkhole_c2_payload as bsc  # noqa: E402  BENIGN/BINARIES/NULL_SAMPLES/_interleave/elf_mode/v21b

v21b = bsc.v21b
IMPLANTS = HERE / "implants"
MANIFEST = json.loads((HERE / "implant_manifest.json").read_text())
MODE = "native_amd64_dynamic"


def build(out_dir, guest_root, only_implants=None, include_benign=True, null_modes=None, benign_modes=None):
    out = Path(out_dir)
    for sub in ("samples", "arguments", "fixtures/sinkholec2"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    manifest = {"samples": {}, "arguments": {}, "benign_binaries": {}, "implants": {}}
    cases = []

    # Sliver implants (our own), one case each
    for name in sorted(only_implants if only_implants is not None else MANIFEST):
        info = MANIFEST[name]
        binary = (IMPLANTS / name).read_bytes()
        assert bsc.elf_mode(binary) == MODE, (name, bsc.elf_mode(binary))
        assert info["sha256"] == v21b.sha256_bytes(binary)
        sample = "sliver-%s-%s.zip" % (info["transport"], info["mode"]) if False else "%s.zip" % name
        blob = v21b.plain_zip(name, binary)
        (out / "samples" / sample).write_bytes(blob)
        (out / "arguments" / (sample + ".json")).write_text(json.dumps([]))
        manifest["samples"][sample] = v21b.sha256_bytes(blob)
        manifest["implants"][sample] = {"name": name, "transport": info["transport"], "c2_mode": info["mode"],
                                        "sha256": info["sha256"]}
        cases.append({"sample": sample, "label": "malware", "mode": MODE, "network": True,
                      "family": "sliver-%s-%s" % (info["transport"], info["mode"]),
                      "transport": info["transport"], "c2_mode": info["mode"]})

    # benign network clients, identical to the sinkhole run
    fixroot = guest_root.rstrip("/") + "/fixtures/sinkholec2/"
    for variant, program, mode, argv, fixtures, expectation, note in (bsc.BENIGN if include_benign else []):
        if benign_modes is not None and mode not in benign_modes:
            continue
        for fname, text in fixtures.items():
            (out / "fixtures/sinkholec2" / fname).write_text(text)
        args = [fixroot + a[3:-1] if a.startswith("{F:") and a.endswith("}") else a for a in argv]
        binary = (bsc.STUDY / bsc.BINARIES[(program, mode)]).read_bytes()
        exec_name = bsc.EXEC_NAME.get(program, program)
        sample = "%s-%s-%s.zip" % (mode, program, variant)
        blob = v21b.plain_zip(exec_name, binary)
        (out / "samples" / sample).write_bytes(blob)
        (out / "arguments" / (sample + ".json")).write_text(json.dumps(args))
        manifest["samples"][sample] = v21b.sha256_bytes(blob)
        manifest["benign_binaries"][sample] = {"program": program, "mode": mode,
                                               "binary": bsc.BINARIES[(program, mode)],
                                               "sha256": v21b.sha256_bytes(binary)}
        cases.append({"sample": sample, "label": "benign", "mode": mode, "network": True, "program": program,
                      "variant": variant, "destination": note, "expectation": expectation})

    for mode, sample in bsc.NULL_SAMPLES.items():
        if null_modes is not None and mode not in null_modes:
            continue
        shutil.copyfile(bsc.REV5_PAYLOAD / "samples" / sample, out / "samples" / sample)
        shutil.copyfile(bsc.REV5_PAYLOAD / "arguments" / (sample + ".json"), out / "arguments" / (sample + ".json"))
        manifest["samples"][sample] = v21b.sha256_bytes((out / "samples" / sample).read_bytes())
        cases.append({"sample": sample, "label": "null", "mode": mode, "network": False, "spot": "start"})

    for a in (out / "arguments").iterdir():
        manifest["arguments"][a.name] = v21b.sha256_bytes(a.read_bytes())
    order = bsc._interleave(cases)
    for i, c in enumerate(order, 1):
        c["position"] = i
    (out / "cases.json").write_text(json.dumps(order, indent=2))
    (out / "cases.txt").write_text("".join(c["sample"] + "\n" for c in order))
    manifest["counts"] = dict(Counter(c["label"] for c in order))
    manifest["by_mode_label"] = {str(k): v for k, v in sorted(Counter((x["mode"], x["label"]) for x in order).items())}
    manifest["by_group"] = {k: v for k, v in sorted(Counter(c.get("family") or c.get("program") or "null"
                                                            for c in order).items())}
    (out / "payload_manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest, order


def self_test():
    import tempfile
    with tempfile.TemporaryDirectory(prefix="hazim-sliver-") as d:
        manifest, order = build(Path(d) / "payload", "/home/csci/Downloads/sliver-TEST")
        assert manifest["counts"] == {"malware": 12, "benign": 28, "null": 3}, manifest["counts"]
        assert len({c["sample"] for c in order}) == len(order) == 43, "duplicate samples"
        imp = [c for c in order if c["label"] == "malware"]
        assert all(c["mode"] == MODE for c in imp)
        groups = Counter(c["family"] for c in imp)
        assert len(groups) == 6 and all(v == 2 for v in groups.values()), groups
        for c in imp:
            blob = (Path(d) / "payload/samples" / c["sample"]).read_bytes()
            z = zipfile.ZipFile(io.BytesIO(blob))
            (name,) = z.namelist()
            assert bsc.elf_mode(z.read(name)) == MODE
            assert v21b.sha256_bytes(z.read(name)) == MANIFEST[name]["sha256"]
        for c in order:
            if c["label"] == "benign":
                args = json.loads((Path(d) / "payload/arguments" / (c["sample"] + ".json")).read_text())
                assert "10.0.0.1" not in " ".join(args), ("benign must not target the Sink", args)
        print("PASS build_sliver_payload: counts", manifest["counts"])
        print("malicious groups:", dict(groups))
        print("by mode/label:", manifest["by_mode_label"])


if __name__ == "__main__":
    self_test()

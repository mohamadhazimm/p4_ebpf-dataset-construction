"""Payload of the sensor-visibility test: the 7 dataset malware that used the network on Triage's internet sandbox
but stayed silent in our lab (5 Tsunami, 2 DeskRAT), plus one null program as a quiet control.

The transports are the revision5 payload's own files, copied byte for byte (AES zips, password "infected"; the
member hash was verified at the revision5 freeze and is checked again here by streaming the member through 7z into
memory: nothing is written to disk or executed on the host). start.sh is the small launcher of the B runs (nothing of
ours stays inside the guest while the sample runs). Layout is the production batch's: samples/<case>.zip,
arguments/<case>.zip.json, cases.json.
"""
import hashlib
import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ASR = HERE.parent
sys.path.insert(0, str(ASR))
REV5_PAYLOAD = ASR / "revision5-collection/20261025T100025568989Z/payload"
START = HERE / "start.sh"

# (sha256, mode, family); from dataset/features.csv, split "test" for all seven
MALWARE = [
    ("0d762c8cbba56cd827c0dc710688d7410840940b9994020b8e365b63d3ff316c", "native_amd64_static", "Tsunami"),
    ("3e16c3bc39182471cac0c89b9883bd102d23d4bb938eb648c7d88b8649e857a9", "native_i386_static", "Tsunami"),
    ("7d22fabcc98916294775e10101526492c105b583ccc9cf3e2edad9187dab4f14", "native_i386_static", "Tsunami"),
    ("86947b00a3d61b82b6f752876404953ff3c39952f2b261988baf63fbbbd6d6ae", "native_i386_static", "Tsunami"),
    ("9e28f942262805b5fb59f46568fed53fd4b7dbf6faf666bedaf6ff22dd416572", "native_amd64_static", "Tsunami"),
    ("6ed2afc550805fc1eef3bfedf1c486b2c22bd3f57a59691eaa3ffc5e6d83fd96", "native_amd64_static", "DeskRAT"),
    ("f0b98f9570a3763cb6eb31c99588de98c6ca03d1e2b0f80ceb29060473d04af2", "native_amd64_static", "DeskRAT"),
]
NULL = ("null-native_amd64_static-start.zip", "native_amd64_static")
# Positive control of the B runs: the lab's benign low-rate poller (lowrate_gen, sha256 37f8c12f..., as collected in
# lowrate21-collect) asking the Sink's web server every 5 s for 58 s. If its requests appear in the B recording
# for the whole minute, a silent sample in B is silent by its own choice, not because the launch or the recording failed.
CONTROL_SRC = ASR / "lowrate21-collect/20261106T070056187569Z/payload/samples/lr_poll_2s.zip"
CONTROL = ("ctl-poll-5s-58s.zip", "native_amd64_static", ["poll", "5000", "58000", "10.0.0.1", "80"])
CONTROL_SHA256 = "37f8c12f5adec83bbe42d9e8e93166fabec52da0bb264de2b3b66a0e66e0d435"


def sha256_bytes(blob):
    return hashlib.sha256(blob).hexdigest()


def member_sha256(zip_path):
    """SHA-256 of the archive's single member, streamed through 7z into memory (no file written, nothing run)."""
    listing = subprocess.run(["7z", "l", "-slt", "-pinfected", str(zip_path)], capture_output=True, text=True,
                             check=True).stdout
    names = [line.split(" = ", 1)[1] for line in listing.splitlines() if line.startswith("Path = ")][1:]
    if len(names) != 1:
        raise ValueError("%s: expected one member, found %d" % (zip_path.name, len(names)))
    blob = subprocess.run(["7z", "x", "-so", "-pinfected", str(zip_path)], capture_output=True, check=True).stdout
    return names[0], sha256_bytes(blob)


def build(out_dir, check_members=True):
    out = Path(out_dir)
    for sub in ("samples", "arguments"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    manifest = {"samples": {}, "arguments": {}, "members": {}}
    cases = []
    for sha, mode, family in MALWARE:
        leaf = sha + ".zip"
        shutil.copyfile(REV5_PAYLOAD / "samples" / leaf, out / "samples" / leaf)
        shutil.copyfile(REV5_PAYLOAD / "arguments" / (leaf + ".json"), out / "arguments" / (leaf + ".json"))
        if json.loads((out / "arguments" / (leaf + ".json")).read_text()) != []:
            raise ValueError(leaf + ": malware cases take no arguments")
        if check_members:
            name, digest = member_sha256(out / "samples" / leaf)
            if digest != sha:
                raise ValueError("%s: member %s hashes to %s" % (leaf, name, digest))
            manifest["members"][leaf] = {"name": name, "sha256": digest}
        cases.append({"sample": leaf, "label": "malware", "mode": mode, "family": family, "network": False,
                      "expected_member_sha256": sha})
    leaf, mode = NULL
    shutil.copyfile(REV5_PAYLOAD / "samples" / leaf, out / "samples" / leaf)
    shutil.copyfile(REV5_PAYLOAD / "arguments" / (leaf + ".json"), out / "arguments" / (leaf + ".json"))
    cases.append({"sample": leaf, "label": "null", "mode": mode, "network": False})
    leaf, mode, args = CONTROL
    shutil.copyfile(CONTROL_SRC, out / "samples" / leaf)
    (out / "arguments" / (leaf + ".json")).write_text(json.dumps(args))
    if check_members:
        name, digest = member_sha256(out / "samples" / leaf)
        if name != "lowrate_gen" or digest != CONTROL_SHA256:
            raise ValueError("control member differs: %s %s" % (name, digest))
        manifest["members"][leaf] = {"name": name, "sha256": digest}
    cases.append({"sample": leaf, "label": "benign", "mode": mode, "network": True, "program": "lowrate_gen",
                  "control": "positive", "arguments": args})
    shutil.copyfile(START, out / "start.sh")
    (out / "start.sh").chmod(0o755)
    for p in sorted((out / "samples").iterdir()):
        manifest["samples"][p.name] = sha256_bytes(p.read_bytes())
    for p in sorted((out / "arguments").iterdir()):
        manifest["arguments"][p.name] = sha256_bytes(p.read_bytes())
    manifest["start_sh"] = sha256_bytes((out / "start.sh").read_bytes())
    order = cases[-2:] + cases[:-2]             # the null and the positive control first, then the seven samples
    for i, c in enumerate(order, 1):
        c["position"] = i
    (out / "cases.json").write_text(json.dumps(order, indent=2))
    manifest["counts"] = dict(Counter(c["label"] for c in order))
    manifest["by_mode_label"] = {str(k): v for k, v in sorted(Counter((c["mode"], c["label"]) for c in order).items())}
    (out / "payload_manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest, order


if __name__ == "__main__":
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        manifest, order = build(Path(d) / "payload")
        assert manifest["counts"] == {"null": 1, "benign": 1, "malware": 7}, manifest["counts"]
        print("PASS build_visibility_payload:", manifest["counts"], manifest["by_mode_label"])
        print({k: v["name"] for k, v in manifest["members"].items()})

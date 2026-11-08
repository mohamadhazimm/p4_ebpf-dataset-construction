"""Assemble the .21 quiet-collection payload from the frozen malware selection + benign binding.

Produces a guest payload tree (samples/ + arguments/ + workspace/ + fixtures/) in the batch's expected layout:
  - samples/<case>.zip   transport the batch extracts with `7z x -pinfected`
  - arguments/<case>.zip.json   the target argv (guest-root-absolute fixture paths rewritten to the v21 root)
  - workspace/...   redesign fixture seed (amd64 benign)
  - fixtures/{training,validation}/...   i386-held-out fixtures (i386 benign)
Malware transports reuse the 87 already-AES-zipped source archives verbatim and wrap the 10 raw-ELF sources into
AES "infected" zips. Benign/null transports wrap each ELF (pulled from the already-guest-validated redesign/holdout
payloads, or the new musl builds) into a plain zip that `7z -pinfected` extracts. Nothing is re-derived: only the
guest-root PREFIX of reused fixture arguments is rewritten. The musl Sink tasks are candidates confirmed at the
benign-only preflight. No VM operation, no sample execution, no malware written as a runnable host file.
"""

import argparse
import hashlib
import io
import json
import os
import random
import re
import subprocess
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
REDESIGN = STUDY / "data/versioned-collector/cohort-100x100-v18-20261021/redesign-native-x64"
HOLDOUT = (STUDY / "data/versioned-collector/cohort-expansion-100x100-v18-20261021"
           / "i386-heldout-amendment/20261021T201119747468Z/collection-readiness/20261021T203401085156Z")
MATCHED = ROOT / "matched45-readiness/20261022T072823231146Z"
REDESIGN_PREFIX = "/home/csci/Downloads/cohort-native-x64-v18-20261021/"
HOLDOUT_PREFIX = "/home/csci/Downloads/native-heldout-release-20261021T203401085156Z/"
SEED = 42


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def plain_zip(member_name, data):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo(member_name)
        info.external_attr = 0o755 << 16
        archive.writestr(info, data)
    return buffer.getvalue()


def aes_zip(member_name, data, workdir):
    """AES 'infected' zip via 7z (matches the malware cohort convention)."""
    tmp = workdir / "wrap"
    tmp.mkdir(parents=True, exist_ok=True)
    member = tmp / member_name
    member.write_bytes(data)
    out = tmp / "out.zip"
    out.unlink(missing_ok=True)
    subprocess.run(["7z", "a", "-tzip", "-pinfected", "-mem=AES256", str(out), str(member)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(tmp))
    blob = out.read_bytes()
    member.unlink(); out.unlink()
    return blob


def extract_member(path):
    done = subprocess.run(["7z", "x", "-so", "-pinfected", str(path)], capture_output=True, timeout=180)
    if done.returncode != 0:
        raise RuntimeError("7z extract failed: " + str(path))
    return done.stdout


def redesign_binary(program):
    return (REDESIGN / "payload/samples" / program).read_bytes()


def holdout_binary(payload_path):
    with __import__("tarfile").open(HOLDOUT / "payload.tgz") as archive:
        return archive.extractfile(payload_path).read()


def rewrite(args, prefix, root):
    # Replace the guest-root prefix ANYWHERE in each arg (handles bare paths and key=path forms like dd's if=/...).
    return [a.replace(prefix, root.rstrip("/") + "/") if isinstance(a, str) else a for a in args]


def interleave(malware, benign, nulls):
    """Seed-42 interleave: opening nulls (one/mode), then shuffled malware/benign pairs per (mode), closing nulls."""
    generator = random.Random(SEED)
    modes = ["native_amd64_dynamic", "native_amd64_static", "native_i386_static"]
    order = []
    nulls_by_mode = {m: [n for n in nulls if n["mode"] == m] for m in modes}
    for m in modes:  # opening null (spot=start) per mode
        order += [n for n in nulls_by_mode[m] if n["spot"] == "start"]
    for m in modes:
        mal = sorted([c for c in malware if c["mode"] == m], key=lambda c: c["member_sha256"])
        ben = sorted([c for c in benign if c["mode"] == m], key=lambda c: c["sample"])
        generator.shuffle(mal); generator.shuffle(ben)
        pairs = []
        for i in range(max(len(mal), len(ben))):
            block = ([mal[i]] if i < len(mal) else []) + ([ben[i]] if i < len(ben) else [])
            generator.shuffle(block)
            pairs += block
        mid = len(pairs) // 2
        order += pairs[:mid] + [n for n in nulls_by_mode[m] if n["spot"] == "middle"] + pairs[mid:]
    for m in modes:  # closing null (spot=end) per mode
        order += [n for n in nulls_by_mode[m] if n["spot"] == "end"]
    return order


def build(out_dir, malware_sel, benign_bind, guest_root, workdir):
    out = Path(out_dir)
    for sub in ("samples", "arguments"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    manifest = {"samples": {}, "arguments": {}}
    cases = []

    # Malware
    for c in malware_sel["cases"]:
        name = c["member_sha256"] + ".zip"
        src = STUDY / c["source_path"]
        if c["transport_ready"]:
            blob = src.read_bytes()
            member = extract_member(src)
            if sha256_bytes(member) != c["member_sha256"]:
                raise RuntimeError("malware member hash mismatch: " + name)
        else:
            data = src.read_bytes()
            if sha256_bytes(data) != c["member_sha256"]:
                raise RuntimeError("raw-ELF malware hash mismatch: " + name)
            blob = aes_zip(c["member_sha256"], data, workdir)
        (out / "samples" / name).write_bytes(blob)
        (out / "arguments" / (name + ".json")).write_text(json.dumps([]))
        manifest["samples"][name] = sha256_bytes(blob)
        cases.append({"sample": name, "label": "malware", "mode": c["mode"], "family": c["family"],
                      "member_sha256": c["member_sha256"], "split": c["split"], "network": False})

    # Benign
    for c in benign_bind["cases"]:
        name = c["sample"] if c["sample"].endswith(".zip") else c["sample"] + ".zip"
        program = c["program"]
        if c["suite"] == "redesign":
            data = redesign_binary(program)
            args = rewrite(c["arguments"], REDESIGN_PREFIX, guest_root)
        elif c["suite"] == "holdout":
            data = holdout_binary(c["payload_path"])
            args = rewrite(c.get("collection_arguments") or c["arguments"], HOLDOUT_PREFIX, guest_root)
        elif c["suite"] == "musl":
            data = Path(c["binary"]).read_bytes()
            args = list(c["arguments"])
        else:
            raise RuntimeError("unknown benign suite: " + c["suite"])
        blob = plain_zip(program, data)
        (out / "samples" / name).write_bytes(blob)
        (out / "arguments" / (name + ".json")).write_text(json.dumps(args))
        manifest["samples"][name] = sha256_bytes(blob)
        cases.append({"sample": name, "label": "benign", "mode": c["mode"], "program": program,
                      "project": c["project"], "suite": c["suite"], "split": c["split"],
                      "network": bool(c["network"]), "needs_guest_validation": bool(c.get("needs_guest_validation")),
                      "expected_returncodes": c.get("expected_returncodes") or [0],
                      "output_globs": c.get("output_globs", []), "require_stdout": c.get("require_stdout")})

    # Nulls: reuse matched45's self-contained null transport zip + its args (one per mode), 3 transports/mode.
    m45 = json.loads((MATCHED / "manifest.json").read_text())
    null_src = {}
    with __import__("tarfile").open(MATCHED / "payload.tgz") as archive:
        for nc in m45["cases"]:
            if nc["label"] != "null" or nc["mode"] in null_src:
                continue
            blob = archive.extractfile("samples/" + nc["sample"]).read()
            null_src[nc["mode"]] = (blob, nc.get("collection_arguments") or nc.get("argument_template") or [])
    for nc in benign_bind["nulls"]:
        name = "null-%s-%s.zip" % (nc["mode"], nc["spot"])
        blob, args = null_src[nc["mode"]]
        (out / "samples" / name).write_bytes(blob)
        (out / "arguments" / (name + ".json")).write_text(json.dumps(args))
        manifest["samples"][name] = sha256_bytes(blob)
        cases.append({"sample": name, "label": "null", "mode": nc["mode"], "spot": nc["spot"], "network": False})

    # Fixtures: redesign workspace seed + holdout fixtures subtree
    subprocess.run(["cp", "-a", str(REDESIGN / "payload/workspace-seed"), str(out / "workspace")], check=True)
    with __import__("tarfile").open(HOLDOUT / "payload.tgz") as archive:
        members = [m for m in archive.getmembers() if m.name.startswith("fixtures/")]
        archive.extractall(out, members=members, filter="data")

    for a in (out / "arguments").iterdir():
        manifest["arguments"][a.name] = sha256_bytes(a.read_bytes())

    order = interleave([c for c in cases if c["label"] == "malware"],
                       [c for c in cases if c["label"] == "benign"],
                       [c for c in cases if c["label"] == "null"])
    for i, c in enumerate(order, 1):
        c["position"] = i
    (out / "cases.json").write_text(json.dumps(order, indent=2))
    (out / "cases.txt").write_text("".join(c["sample"] + "\n" for c in order))
    manifest["counts"] = dict(Counter(c["label"] for c in order))
    manifest["by_mode_label"] = {f"{c}": n for c, n in sorted(
        Counter((x["mode"], x["label"]) for x in order).items())}
    manifest["network_benign"] = sum(1 for c in order if c["label"] == "benign" and c["network"])
    manifest["guest_root"] = guest_root
    (out / "payload_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    return manifest, order


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--malware", required=True)
    parser.add_argument("--benign", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--guest-root", default="/home/csci/Downloads/v21-collection")
    args = parser.parse_args()
    workdir = Path(args.out).parent / ("_wrap-" + datetime.now(timezone.utc).strftime("%H%M%S%f"))
    workdir.mkdir(parents=True, exist_ok=True)
    manifest, order = build(args.out, json.loads(Path(args.malware).read_text()),
                            json.loads(Path(args.benign).read_text()), args.guest_root, workdir)
    subprocess.run(["rm", "-rf", str(workdir)], check=False)
    print(json.dumps({"counts": manifest["counts"], "by_mode_label": manifest["by_mode_label"],
                      "network_benign": manifest["network_benign"], "samples": len(manifest["samples"]),
                      "positions": len(order)}, indent=2))


if __name__ == "__main__":
    main()

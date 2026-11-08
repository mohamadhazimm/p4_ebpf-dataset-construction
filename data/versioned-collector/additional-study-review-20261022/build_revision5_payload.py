"""Assemble the matched-cohort (revision5-matched) quiet-collection payload: 105 malware + 105 benign + 9 null.

Guest payload tree in the batch's layout (samples/<case>.zip + arguments/<case>.zip.json + fixtures/rev5/...), emitting
the same cases.json schema collect_v21's audit/traffic-gate consume. Reuses build_v21_payload's zip/interleave helpers
and the SHARED guest-safe workload registry (benign_workloads) so the host-preflighted args/fixtures are exactly what
the guest runs. Malware: 87-ish source AES-zips reused verbatim, raw-ELF sources wrapped into AES "infected" zips, both
by member-hash check -- NEVER executed. Benign: each authenticated build (resolved by sha256 -> inventory locator)
wrapped in a plain zip; its activity-tuned fixtures staged under fixtures/rev5 and referenced by absolute guest paths;
network cases carry the v21-proven Sink argv. Nulls: matched45's self-contained null transport per mode. No VM, no
sample execution, no malware written as a runnable host file.
"""

import argparse
import json
import sys
import tarfile
from collections import Counter, OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import build_v21_payload as v21b   # noqa: E402  plain_zip / aes_zip / extract_member / sha256_bytes / interleave / MATCHED
import benign_workloads as bw      # noqa: E402  shared guest-safe workload registry

STUDY = ROOT.parents[2]
RELEASE = (STUDY / "data/versioned-collector/cohort-expansion-100x100-v18-20261021/i386-heldout-amendment"
           / "20261021T201119747468Z/collection-readiness/20261021T203401085156Z")
MODE_MAP = {"amd64_static": "native_amd64_static", "amd64_dynamic": "native_amd64_dynamic",
            "i386_static": "native_i386_static"}
# v21-proven Sink argv per network program; index 0 == task_variant "a", 1 == "b". All target the internal Sink 10.0.0.1.
NETWORK_TASKS = {
    "curl": [["--noproxy", "*", "--max-time", "6", "--fail", "-s", "-o", "http.out", "http://10.0.0.1/"],
             ["--noproxy", "*", "--max-time", "6", "-sk", "-o", "tls.out", "https://10.0.0.1/"]],
    "wget": [["--no-proxy", "--timeout=6", "--tries=1", "-O", "wget.out", "http://10.0.0.1/"],
             ["--no-proxy", "--timeout=6", "--tries=1", "-O", "wget2.out", "http://10.0.0.1/data"]],
    "openssl": [["s_client", "-connect", "10.0.0.1:443", "-servername", "sink.local"],
                ["s_client", "-connect", "10.0.0.1:443", "-tls1_3"]],
    "ping": [["-n", "-c", "3", "-w", "6", "10.0.0.1"], ["-n", "-c", "2", "-i", "0.5", "-w", "6", "10.0.0.1"]],
    "ftp": [["-4", "-n", "-i", "-e", "10.0.0.1"], ["-4", "-n", "-p", "10.0.0.1"]],
    "telnet": [["-E", "10.0.0.1", "80"], ["-E", "10.0.0.1", "443"]],
    "whois": [["-h", "10.0.0.1", "-p", "43", "example.test"]],
}


def resolve_binary(sha, invmap):
    loc = invmap[sha]
    if loc.startswith("payload.tgz:"):
        with tarfile.open(RELEASE / "payload.tgz") as archive:
            return archive.extractfile(loc.split(":", 1)[1]).read()
    return (STUDY / loc).read_bytes()


def build(out_dir, malware_sel, benign_sel, invmap, guest_root, workdir):
    out = Path(out_dir)
    for sub in ("samples", "arguments", "fixtures/rev5"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    manifest = {"samples": {}, "arguments": {}}
    cases = []
    fixdir = out / "fixtures/rev5"
    fixcache = {}

    # ---- malware: reuse transport-ready AES zips, wrap raw-ELF sources; member hash must match; never executed
    for c in malware_sel["cases"]:
        member = c["sha256"]
        src = STUDY / c["source_path"]
        data = src.read_bytes()
        if v21b.sha256_bytes(data) == member:                       # raw ELF source -> wrap
            blob = v21b.aes_zip(member, data, workdir)
        else:                                                        # AES-zip transport -> reuse verbatim after check
            if v21b.sha256_bytes(v21b.extract_member(src)) != member:
                raise RuntimeError("malware member hash mismatch: " + member)
            blob = data
        name = member + ".zip"
        (out / "samples" / name).write_bytes(blob)
        (out / "arguments" / (name + ".json")).write_text(json.dumps([]))
        manifest["samples"][name] = v21b.sha256_bytes(blob)
        cases.append({"sample": name, "label": "malware", "mode": MODE_MAP[c["mode"]], "family": c["family"],
                      "member_sha256": member, "split": c["split"], "network": False})

    # ---- benign: authenticated build + activity-tuned fixtures (compute) or v21-proven Sink argv (network)
    for c in benign_sel:
        if "program" not in c:
            continue
        program, abin, variant = c["program"], c["activity_bin"], c["task_variant"]
        data = resolve_binary(c["sha256"], invmap)
        if v21b.sha256_bytes(data) != c["sha256"]:
            raise RuntimeError("benign binary hash mismatch: %s %s" % (program, c["sha256"][:12]))
        # include a sha8 so two distinct builds of the same program (e.g. inetutils ftp glibc vs musl) stay distinct
        name = "%s-%s-%s-%s-%s-%s.zip" % (c["mode"], c["split"], program, abin, variant, c["sha256"][:8])
        record = {"sample": name, "label": "benign", "mode": MODE_MAP[c["mode"]], "program": program,
                  "project": c["project"], "split": c["split"], "network": bool(c["network"]),
                  "activity_bin": abin}
        if c["network"]:
            tasks = NETWORK_TASKS[program]
            args = list(tasks[0 if variant == "a" else 1 if variant == "b" else "abcdefg".index(variant)])
            record.update(needs_guest_validation=True, expected_returncodes=None)
        else:
            spec = bw.workload(program, abin)
            paths = OrderedDict((role, bw.materialize(kind, size, fixdir, fixcache))
                                for role, kind, size in spec["fixtures"])
            guest_paths = {role: guest_root.rstrip("/") + "/fixtures/rev5/" + p.name for role, p in paths.items()}
            args = bw.resolve_argv(spec, guest_paths, ".")
            record["expected_returncodes"] = spec["rc_ok"]
        blob = v21b.plain_zip(program, data)
        (out / "samples" / name).write_bytes(blob)
        (out / "arguments" / (name + ".json")).write_text(json.dumps(args))
        manifest["samples"][name] = v21b.sha256_bytes(blob)
        cases.append(record)

    # ---- nulls: matched45 self-contained null transport per mode, 3 spots/mode
    m45 = json.loads((v21b.MATCHED / "manifest.json").read_text())
    null_src = {}
    with tarfile.open(v21b.MATCHED / "payload.tgz") as archive:
        for nc in m45["cases"]:
            if nc["label"] != "null" or nc["mode"] in null_src:
                continue
            null_src[nc["mode"]] = (archive.extractfile("samples/" + nc["sample"]).read(),
                                    nc.get("collection_arguments") or nc.get("argument_template") or [])
    for mode in ("native_amd64_dynamic", "native_amd64_static", "native_i386_static"):
        for spot in ("start", "middle", "end"):
            name = "null-%s-%s.zip" % (mode, spot)
            blob, args = null_src[mode]
            (out / "samples" / name).write_bytes(blob)
            (out / "arguments" / (name + ".json")).write_text(json.dumps(args))
            manifest["samples"][name] = v21b.sha256_bytes(blob)
            cases.append({"sample": name, "label": "null", "mode": mode, "spot": spot, "network": False})

    for a in (out / "arguments").iterdir():
        manifest["arguments"][a.name] = v21b.sha256_bytes(a.read_bytes())

    order = v21b.interleave([c for c in cases if c["label"] == "malware"],
                            [c for c in cases if c["label"] == "benign"],
                            [c for c in cases if c["label"] == "null"])
    for i, c in enumerate(order, 1):
        c["position"] = i
    (out / "cases.json").write_text(json.dumps(order, indent=2))
    (out / "cases.txt").write_text("".join(c["sample"] + "\n" for c in order))
    manifest["counts"] = dict(Counter(c["label"] for c in order))
    manifest["by_mode_label"] = {str(k): v for k, v in sorted(
        Counter((x["mode"], x["label"]) for x in order).items())}
    manifest["network_benign"] = sum(1 for c in order if c["label"] == "benign" and c["network"])
    manifest["guest_root"] = guest_root
    (out / "payload_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    return manifest, order


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--malware", required=True)
    parser.add_argument("--benign", required=True)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--guest-root", default="/home/csci/Downloads/revision5-matched")
    args = parser.parse_args()
    from datetime import datetime, timezone
    import subprocess
    workdir = Path(args.out).parent / ("_wrap-" + datetime.now(timezone.utc).strftime("%H%M%S%f"))
    workdir.mkdir(parents=True, exist_ok=True)
    invmap = {r["sha256"]: r["locator"] for r in json.loads(Path(args.inventory).read_text())}
    manifest, order = build(args.out, json.loads(Path(args.malware).read_text()),
                            json.loads(Path(args.benign).read_text()), invmap, args.guest_root, workdir)
    subprocess.run(["rm", "-rf", str(workdir)], check=False)
    print(json.dumps({"counts": manifest["counts"], "by_mode_label": manifest["by_mode_label"],
                      "network_benign": manifest["network_benign"], "samples": len(manifest["samples"]),
                      "positions": len(order)}, indent=2))


if __name__ == "__main__":
    main()

"""Collect BENIGN programs rebuilt with the malware's toolchains (committee follow-up, 2026-11-13).

Why: in the dataset the static benign programs start with glibc 2.35's start-up (rseq, getrandom, ...), most static
malware with other toolchains' start-ups, and five yes/no start-up flags alone separate the classes about as well as
the host detector (committee-eval-20261113/REPORT.md section 2.4a). This collection gives benign programs whose
toolchain mix matches the static malware's (old static glibc, Go, uClibc 0.9.30.1 + GCC 4.1.2, UPX, musl, glibc 2.35),
so the host view can be measured without that cue.

Cases: the 87 of committee-eval-20261113/toolchain/benign-build/proposed_cases.json (built and host-checked there):
79 new builds with the dataset's own tasks (benign_workloads.py fixtures and arguments; Go tools the same task kind),
2 UPX-packed dataset builds (sha256sum; curl with the dataset's own network task to the Sink), and 6 of the dataset's
own cases reused verbatim as controls (b2sum, md5sum light; wget, openssl, curl, wget network). Plus the three nulls.
Same runner, schema, 20-s settings, quiet baseline snapshot and production batch as the dataset's later batches
(collect_lowrate21.py); the installed runner .22 is .21 plus a retained-event cap, features unchanged. Benign only;
network tasks talk only to the Sink. One batch, no retries or replacements; the original snapshot is restored.

  /usr/bin/python3 collect_toolchain21.py --build-only
  /usr/bin/python3 collect_toolchain21.py --run --approval "<verbatim>"
  /usr/bin/python3 collect_toolchain21.py --validate toolchain21-collect/<attempt>
"""
import argparse
import fcntl
import hashlib
import io
import json
import random
import re
import shutil
import signal
import subprocess
import sys
import tarfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import benign_workloads as bw    # noqa: E402  the dataset's own workload registry
import build_v21_payload as v21b  # noqa: E402  plain_zip / sha256_bytes
import collect_lowrate21 as lr   # noqa: E402  use_installed_runner (.21 or .22 pin)
import collect_v19 as frozen     # noqa: E402
import collect_v21 as v21        # noqa: E402

digest, save, stamp = frozen.digest, frozen.save, frozen.stamp
BB = ROOT / "committee-eval-20261113/toolchain/benign-build"
PROPOSED = BB / "proposed_cases.json"
REV5 = ROOT / "revision5-collection/20261025T100025568989Z"
REV5_PAYLOAD = REV5 / "payload"
REV5_ROOT = json.load(open(REV5 / "protocol.json"))["guest_root"]
FIX_RE = re.compile(re.escape(REV5_ROOT) + r"/fixtures/rev5/([^/\s]+)")
SINK = "10.0.0.1"
NULL_SAMPLES = ["null-native_amd64_dynamic-start.zip", "null-native_amd64_static-start.zip",
                "null-native_i386_static-start.zip"]
# the dataset cases reused as controls (variant a for the network tasks)
REUSE = {"tcm-x64-055": "amd64_static-training-b2sum-light-light-e15680a2.zip",
         "tcm-x64-056": "amd64_static-training-md5sum-light-light-86b0951f.zip",
         "tcm-x64-057": "amd64_static-validation-wget-net-a-0a23aee0.zip",
         "tcm-x64-058": "amd64_static-training-openssl-net-a-21ba90cb.zip",
         "tcm-i386-085": "i386_static-training-curl-net-a-ab7a2b71.zip",
         "tcm-i386-086": "i386_static-validation-wget-net-a-72b6617b.zip"}
# the UPX-packed dataset curl runs the dataset's own curl network task (arguments of this case)
NET_ARGS_FROM = {"tcm-x64-054": "amd64_static-training-curl-net-a-d912f186.zip"}
_IP = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def require(ok, msg):
    if not ok:
        raise ValueError(msg)


def rev5_args(sample, out, guest_root, copied):
    """A revision5 case's arguments with the guest root rewritten, copying the fixtures they name."""
    args = json.load(open(REV5_PAYLOAD / "arguments" / (sample + ".json")))
    new = []
    for a in args:
        if REV5_ROOT in a:
            names = FIX_RE.findall(a)
            require(names and a.count(REV5_ROOT) == len(names), "non-fixture guest path in " + sample)
            for name in names:
                src, dst = REV5_PAYLOAD / "fixtures/rev5" / name, out / "fixtures/rev5" / name
                require(src.exists(), "missing fixture " + name)
                if name not in copied:
                    (shutil.copytree if src.is_dir() else shutil.copy2)(src, dst)
                    copied.add(name)
            a = a.replace(REV5_ROOT, guest_root.rstrip("/"))
        new.append(a)
    return new


def build_payload(out, guest_root):
    out = Path(out)
    for sub in ("samples", "arguments", "fixtures/rev5", "fixtures/tcm"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    proposed = json.load(open(PROPOSED))
    rev5_cases = {c["sample"]: c for c in json.load(open(REV5_PAYLOAD / "cases.json"))}
    rev5_manifest = json.load(open(REV5_PAYLOAD / "payload_manifest.json"))
    manifest = {"samples": {}, "arguments": {}, "binaries": {}, "proposed_sha256": digest(PROPOSED)}
    cases, copied, cache = [], set(), {}
    for c in proposed:
        cid = c["case_id"]
        mode = "native_" + c["mode"]
        network = bool(c.get("network_task"))
        if cid in REUSE:
            src = REUSE[cid]
            rc = rev5_cases[src]
            require(rc["program"] == c["program"] and rc["mode"] == mode, "reuse mapping wrong for " + cid)
            blob = (REV5_PAYLOAD / "samples" / src).read_bytes()
            expected = rev5_manifest.get("samples", {}).get(src)
            require(expected is None or expected == v21b.sha256_bytes(blob), "revision5 transport changed: " + src)
            sample = "%s-%s" % (cid, src)
            args = rev5_args(src, out, guest_root, copied)
            network = bool(rc["network"])
            exp = rc.get("expected_returncodes") if not network else None
            source = "dataset case " + src
        else:
            binary = (BB / c["binary"]).read_bytes()
            require(hashlib.sha256(binary).hexdigest() == c["binary_sha256"], "binary changed: " + cid)
            blob = v21b.plain_zip(c["program"], binary)
            sample = "%s-%s.zip" % (cid, re.sub(r"[^A-Za-z0-9_.-]", "_", c["program"]))
            if cid in NET_ARGS_FROM:
                args = rev5_args(NET_ARGS_FROM[cid], out, guest_root, copied)
                network, exp = True, None
            else:
                paths = {role: bw.materialize(kind, size, out / "fixtures/tcm", cache)
                         for role, kind, size in c["fixtures"]}
                guest = {role: guest_root.rstrip("/") + "/fixtures/tcm/" + p.name for role, p in paths.items()}
                args = bw.resolve_argv(c, guest, ".")
                exp = c["expected_exit_codes"]
            manifest["binaries"][sample] = c["binary_sha256"]
            source = c["binary"]
        ips = [m for a in args for m in _IP.findall(a)]
        require(all(ip == SINK for ip in ips), "case %s names an address other than the Sink: %s" % (cid, ips))
        (out / "samples" / sample).write_bytes(blob)
        (out / "arguments" / (sample + ".json")).write_text(json.dumps(args))
        manifest["samples"][sample] = v21b.sha256_bytes(blob)
        cases.append({"sample": sample, "label": "benign", "mode": mode, "network": network, "case_id": cid,
                      "program": c["program"], "project": c["project"], "toolchain_class": c["toolchain_class"],
                      "toolchain": c["toolchain"], "kind": c["kind"], "activity_bin": c.get("activity_bin"),
                      "split_suggestion": c.get("split_suggestion"), "expected_returncodes": exp, "source": source})
    for sample in NULL_SAMPLES:
        blob = (REV5_PAYLOAD / "samples" / sample).read_bytes()
        (out / "samples" / sample).write_bytes(blob)
        shutil.copyfile(REV5_PAYLOAD / "arguments" / (sample + ".json"), out / "arguments" / (sample + ".json"))
        manifest["samples"][sample] = v21b.sha256_bytes(blob)
        cases.append({"sample": sample, "label": "null", "mode": rev5_cases[sample]["mode"], "network": False,
                      "expected_returncodes": [0]})
    for a in (out / "arguments").iterdir():
        manifest["arguments"][a.name] = v21b.sha256_bytes(a.read_bytes())
    nulls = [c for c in cases if c["label"] == "null"]
    ben = [c for c in cases if c["label"] == "benign"]
    random.Random(42).shuffle(ben)
    order = nulls + ben
    for i, c in enumerate(order, 1):
        c["position"] = i
    (out / "cases.json").write_text(json.dumps(order, indent=2))
    (out / "cases.txt").write_text("".join(c["sample"] + "\n" for c in order))
    manifest["counts"] = dict(Counter(c["label"] for c in order))
    manifest["by_mode_class"] = {str(k): v for k, v in sorted(Counter((c["mode"], c.get("toolchain_class") or "null")
                                                                      for c in order).items())}
    manifest["fixtures_copied"] = sorted(copied)
    (out / "payload_manifest.json").write_text(json.dumps(manifest, indent=2))
    return order


def package(attempt, guest_root):
    payload = attempt / "payload"
    order = build_payload(payload, guest_root)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for p in sorted(payload.rglob("*")):
            tar.add(p, arcname=str(p.relative_to(payload)), recursive=False)
    pbytes = buf.getvalue()
    (attempt / "payload.tgz").write_bytes(pbytes)
    setup = v21.build_setup(guest_root, pbytes)
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    (attempt / "setup_guest.sh").write_text(setup)
    shutil.copyfile(payload / "cases.txt", attempt / "cases.txt")
    return order, pbytes


def run(approval):
    require(approval and approval.strip(), "verbatim approval required")
    runner = lr.use_installed_runner()
    v21.verify_production()
    run_id = stamp()
    attempt = ROOT / "toolchain21-collect" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/toolchain21-" + run_id
    snapshot = "clean-toolchain21-" + run_id
    order, pbytes = package(attempt, guest_root)
    module = frozen.helper()
    protocol = {"format": "toolchain21-collect-v1", "schema": v21.SCHEMA, "guest_root": guest_root,
                "new_snapshot": snapshot, "settings": v21.SETTINGS, "baseline": v21.BASELINE,
                "original": module.ORIGINAL, "approval": approval, "runner": runner,
                "payload_sha256": hashlib.sha256(pbytes).hexdigest(), "cases": order,
                "sources": {"collect_toolchain21.py": digest(Path(__file__)), "proposed_cases.json": digest(PROPOSED)},
                "note": "benign programs rebuilt with the malware's toolchains, 20-s observation, capture only"}
    save(attempt / "protocol.json", protocol)
    destination = attempt / "run"
    destination.mkdir()
    save(destination / "authorization.json", {"approval": approval,
                                              "authorized_utc": datetime.now(timezone.utc).isoformat()})

    def interrupted(_s, _f):
        raise KeyboardInterrupt("stop + restore original")
    prev = signal.signal(signal.SIGTERM, interrupted)
    touched = False
    try:
        with (Path(module.__file__).parent / "readiness.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            before = v21.preflight(module, protocol)
            save(destination / "initial_vm_state.json", before)
            require(not v21.snapshot_present(module, snapshot), "child already exists")
            touched = True
            frozen.run_logged(v21.stage_command(attempt, module, snapshot), destination / "stage.log", 1800)
            frozen.run_logged(v21.batch_command(module, attempt, protocol, snapshot, attempt / "runs",
                                                attempt / "cases.txt"), destination / "collection.log", 4 * 3600)
            reached = "Batch complete" in (destination / "collection.log").read_text()
            save(destination / "result.json", {"status": "passed", "reached_batch_complete": reached})
            print(json.dumps({"attempt": str(attempt), "reached_batch_complete": reached}, indent=2))
    except BaseException as e:
        save(destination / "result.json", {"status": "failed_preserved", "error": type(e).__name__ + ": " + str(e)})
        raise
    finally:
        try:
            if touched:
                frozen.restore(module, destination)
        finally:
            signal.signal(signal.SIGTERM, prev)
    return attempt


def validate(attempt):
    """Per case: retrieved, quality accepted, target exec observed, 40 windows, no eBPF loss or overflow, and the
    task's behaviour: compute cases end with an expected exit code, network cases reach the Sink."""
    attempt = Path(attempt).resolve()
    protocol = json.load(open(attempt / "protocol.json"))
    sys.path.insert(0, str(ROOT.parents[4] / "p4-ebpf-malware-detection" / "features"))
    import switch_model as sm  # noqa: E402
    rows = []
    for c in protocol["cases"]:
        runs = sorted((attempt / "runs" / c["sample"] / "output").glob("run_*"))
        rec = {"sample": c["sample"], "label": c["label"], "toolchain_class": c.get("toolchain_class"),
               "mode": c["mode"]}
        if not runs or not (runs[-1] / "run.json").exists():
            rows.append(dict(rec, status="not_retrieved"))
            continue
        d = json.load(open(runs[-1] / "run.json"))
        rec.update(rc=d.get("return_code"), quality=d.get("collection_quality_status"),
                   exec=(d.get("target_exec") or {}).get("status"), windows=d.get("windows"),
                   lost=d.get("ebpf_lost_event_count"), overflow=d.get("ebpf_events_overflow"))
        technical = (rec["quality"] == "accepted" and rec["exec"] == "observed" and rec["windows"] == 40
                     and not rec["lost"] and not rec["overflow"])
        if c["network"]:
            sink = 0
            for _, _, frame in sm.read_pcap(str(runs[-1] / "packet_capture.pcap")):
                p = sm.parse_flow_packet(frame)
                if p and SINK in (p[0], p[1]):
                    sink += 1
            rec["sink_packets"] = sink
            behaviour = sink > 8  # more than the eight frames of the collector's two capture probes
        else:
            behaviour = rec["rc"] in (c.get("expected_returncodes") or [0])
        rec["status"] = "accepted" if technical and behaviour else ("behaviour_mismatch" if technical else "rejected")
        rows.append(rec)
    summary = Counter(r["status"] for r in rows)
    by_class = Counter((r.get("toolchain_class") or "null", r["status"]) for r in rows)
    out = attempt / ("validation-%s.json" % stamp())
    save(out, {"summary": dict(summary), "by_class": {str(k): v for k, v in sorted(by_class.items())}, "cases": rows})
    print(json.dumps({"summary": dict(summary), "by_class": {str(k): v for k, v in sorted(by_class.items())},
                      "report": str(out)}, indent=1))
    for r in rows:
        if r["status"] != "accepted":
            print(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--build-only", action="store_true", help="build and check the payload; no VM operation")
    ap.add_argument("--validate")
    ap.add_argument("--approval")
    a = ap.parse_args()
    if a.build_only:
        attempt = ROOT / "toolchain21-collect" / ("build-only-" + stamp())
        attempt.mkdir(parents=True, exist_ok=False)
        order, pbytes = package(attempt, "/home/csci/Downloads/toolchain21-build-only")
        print("built", attempt, "cases", len(order), "payload MB %.1f" % (len(pbytes) / 1e6))
        print(json.dumps(json.load(open(attempt / "payload" / "payload_manifest.json"))["by_mode_class"], indent=1))
    elif a.run:
        run(a.approval)
    elif a.validate:
        validate(a.validate)
    else:
        print("use --build-only, --run --approval '<verbatim>', or --validate ATTEMPT")


if __name__ == "__main__":
    main()

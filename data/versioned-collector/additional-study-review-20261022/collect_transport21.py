"""Encrypted-traffic collection (thesis committee, item 3): the same benign client workloads over plain HTTP,
TLS 1.1, TLS 1.2, TLS 1.3 (HTTP/1.1 in each) and QUIC (HTTP/3), in the sealed lab, against our own server on the
Sink. Only the transport changes between cases of one program and workload, so the shift that encryption causes
in the host and network features can be measured against the run-to-run spread.

Programs (both benign, both ours, both talking only to 10.0.0.1):
- `transport21/bin/labtransport client` (Go, static): http, tls11, tls12, tls13, quic;
- `transport21/transport_client.py` (Python standard library, launched through flood_gen's `pyexec` exactly as the
  Python attack tools Slowloris and GoldenEye were): http, tls11, tls12, tls13. This also gives benign Python
  network programs, which the committee asked for to neutralize the "Python interpreter" cue.
Workloads: poll (a new connection every 1 s, GET 4 KiB), session (one kept-alive connection, GET 1 KiB every
100 ms), bulk (a new connection per GET of 1 MiB, 0.5 s apart); 16 s of activity in the 20-s observation.
Two repeats of each, plus the three nulls. Server: `labtransport server -addr 10.0.0.1` on the Sink for the
whole batch (plain 9080, TLS 1.1/1.2/1.3 on 9441/9442/9443, QUIC on 9444/udp), self-signed certificate; it logs
the negotiated version of every request. INetSim, dnsmasq and the sinkhole are not touched.

Same runner, schema, 20-s settings, quiet baseline and production batch as the dataset's later batches
(collect_toolchain21.py); one batch, no retries or replacements; the original snapshot is restored and the Sink
server stopped on every exit.

  /usr/bin/python3 collect_transport21.py --build-only
  /usr/bin/python3 collect_transport21.py --run --approval "<verbatim>"
  /usr/bin/python3 collect_transport21.py --validate transport21-collect/<attempt>
"""
import argparse
import fcntl
import hashlib
import io
import json
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import build_v21_payload as v21b  # noqa: E402  plain_zip / sha256_bytes
import collect_lowrate21 as lr   # noqa: E402  use_installed_runner (.21 or .22 pin)
import collect_v19 as frozen     # noqa: E402
import collect_v21 as v21        # noqa: E402

# Importing collect_pilot (directly or through collect_sinkhole_c2) would switch these to its 300-s settings.
assert v21.SETTINGS[:2] == ["--timeout", "20"], "collector settings are not the 20-s ones: %s" % v21.SETTINGS[:2]

digest, save, stamp = frozen.digest, frozen.save, frozen.stamp
T21 = ROOT / "transport21"
LABT = T21 / "bin" / "labtransport"
PYCLIENT = T21 / "transport_client.py"
FLOOD_GEN = ROOT / "flood_gen"
REV5 = ROOT / "revision5-collection/20261025T100025568989Z"
REV5_PAYLOAD = REV5 / "payload"
NULL_SAMPLES = ["null-native_amd64_dynamic-start.zip", "null-native_amd64_static-start.zip",
                "null-native_i386_static-start.zip"]
SINK = "10.0.0.1"
SINK_VM, SINK_USER = "Sink", "remnux"
SINK_LAB = "/home/remnux/hazim-transport21"
PORTS = {"http": 9080, "tls11": 9441, "tls12": 9442, "tls13": 9443, "quic": 9444}
MODES = {"go": ["http", "tls11", "tls12", "tls13", "quic"], "py": ["http", "tls11", "tls12", "tls13"]}
WORKLOADS = ["poll", "session", "bulk"]
REPEATS = 2
DURATION_S = 16
_IP = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def require(ok, msg):
    if not ok:
        raise ValueError(msg)


def cases():
    out = []
    for program, modes in MODES.items():
        for mode in modes:
            for workload in WORKLOADS:
                for r in range(1, REPEATS + 1):
                    name = "t21-%s-%s-%s-r%d" % (program, mode, workload, r)
                    if program == "go":
                        argv = ["client", mode, workload, SINK, "-duration", "%ds" % DURATION_S]
                    else:
                        argv = ["pyexec", "transport_client.py", mode, workload, SINK, str(DURATION_S)]
                    out.append({"name": name, "program": program, "transport": mode, "workload": workload,
                                "repeat": r, "argv": argv})
    return out


def _assert_safe():
    for c in cases():
        for tok in c["argv"]:
            for ip in _IP.findall(tok):
                require(ip == SINK, "%s names an address other than the Sink: %s" % (c["name"], ip))
        require(c["transport"] in PORTS and c["workload"] in WORKLOADS, "bad case " + c["name"])
        if c["program"] == "py":
            require(c["argv"][:2] == ["pyexec", "transport_client.py"], "bad pyexec target " + c["name"])


def build_payload(out, guest_root):
    out = Path(out)
    for sub in ("samples", "arguments"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    labt, pyc, gen = LABT.read_bytes(), PYCLIENT.read_bytes(), FLOOD_GEN.read_bytes()
    manifest = {"samples": {}, "arguments": {},
                "inputs": {"labtransport": hashlib.sha256(labt).hexdigest(),
                           "transport_client.py": hashlib.sha256(pyc).hexdigest(),
                           "flood_gen": hashlib.sha256(gen).hexdigest()}}
    rev5_cases = {c["sample"]: c for c in json.load(open(REV5_PAYLOAD / "cases.json"))}
    order = []
    for c in cases():
        sample = c["name"] + ".zip"
        if c["program"] == "go":
            blob = v21b.plain_zip("labtransport", labt)
            mode = "native_amd64_static"
        else:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                z.writestr("flood_gen", gen)                       # the ELF the batch launches
                z.writestr("transport_client.py", pyc)             # pyexec execs /usr/bin/python3 on it
            blob = buf.getvalue()
            mode = "native_amd64_static"                           # the sample artifact is flood_gen
        (out / "samples" / sample).write_bytes(blob)
        (out / "arguments" / (sample + ".json")).write_text(json.dumps(c["argv"]))
        manifest["samples"][sample] = v21b.sha256_bytes(blob)
        order.append(dict(c, sample=sample, label="benign", mode=mode, network=True))
    nulls = []
    for sample in NULL_SAMPLES:
        blob = (REV5_PAYLOAD / "samples" / sample).read_bytes()
        (out / "samples" / sample).write_bytes(blob)
        shutil.copyfile(REV5_PAYLOAD / "arguments" / (sample + ".json"), out / "arguments" / (sample + ".json"))
        manifest["samples"][sample] = v21b.sha256_bytes(blob)
        nulls.append({"sample": sample, "label": "null", "mode": rev5_cases[sample]["mode"], "network": False,
                      "expected_returncodes": [0]})
    for a in (out / "arguments").iterdir():
        manifest["arguments"][a.name] = v21b.sha256_bytes(a.read_bytes())
    random.Random(42).shuffle(order)
    order = nulls + order
    for i, c in enumerate(order, 1):
        c["position"] = i
    (out / "cases.json").write_text(json.dumps(order, indent=2))
    (out / "cases.txt").write_text("".join(c["sample"] + "\n" for c in order))
    manifest["counts"] = dict(Counter((c.get("program") or "null") for c in order))
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


# ----------------------------------------------------------------------------------------------- the Sink side
# Copies of collect_sinkhole_c2's helpers (importing that module would load collect_pilot's 300-s settings).

def _with_password(module, fn):
    fd, name = tempfile.mkstemp(prefix="hz-sinkpw-")
    secret = b""
    try:
        os.fchmod(fd, 0o600)
        secret = module.credentials().encode()
        os.write(fd, secret)
        os.close(fd)
        return fn(name)
    finally:
        try:
            with open(name, "r+b") as stream:
                stream.write(b"\0" * max(len(secret), 64))
                stream.flush()
                os.fsync(stream.fileno())
        except OSError:
            pass
        os.unlink(name)


def sink_run(module, argv, timeout_ms=120000, sudo=False):
    info = module.isolated(SINK_VM)
    require(info["VMState"] == '"running"', "Sink is not running")
    exe, rest = ("/usr/bin/sudo", ["-n", *argv]) if sudo else (argv[0], list(argv[1:]))
    return _with_password(module, lambda pw: module.vbox(
        "guestcontrol", SINK_VM, "run", "--username", SINK_USER, "--passwordfile", pw, "--exe", exe,
        "--wait-stdout", "--wait-stderr", "--timeout", str(timeout_ms), "--", *rest, check=False))


def sink_bash(module, script, timeout_ms=120000):
    return sink_run(module, ["/bin/bash", "-c", script], timeout_ms=timeout_ms)


def sink_copyto(module, local, remote):
    return _with_password(module, lambda pw: module.vbox(
        "guestcontrol", SINK_VM, "copyto", "--username", SINK_USER, "--passwordfile", pw, str(local), remote,
        check=False))


def sink_copyfrom(module, remote, local):
    return _with_password(module, lambda pw: module.vbox(
        "guestcontrol", SINK_VM, "copyfrom", "--username", SINK_USER, "--passwordfile", pw, remote, str(local),
        check=False))


def server_listening(module):
    """Ports of the test server that are listening on the Sink (TCP 9080/9441-9443, UDP 9444)."""
    r = sink_bash(module, "ss -Hltnu 2>/dev/null")
    text = r.stdout or ""
    found = {}
    for mode, port in PORTS.items():
        found[mode] = ("%s:%d" % (SINK, port)) in text
    return found


def server_start(module, run_id, record):
    want = digest(LABT)
    r = sink_bash(module, "mkdir -p %s && pkill -x labtransport; echo ok" % SINK_LAB)
    require("ok" in (r.stdout or ""), "Sink lab directory: %s" % (r.stderr or "")[:200])
    cp = sink_copyto(module, LABT, SINK_LAB + "/labtransport")
    require(cp.returncode == 0, "copy to the Sink failed: %s" % (cp.stderr or "")[:200])
    r = sink_run(module, ["/usr/bin/sha256sum", SINK_LAB + "/labtransport"])
    got = (r.stdout or "").split()[0] if r.stdout else ""
    require(got == want, "server binary hash on the Sink: %s, expected %s" % (got, want))
    log = "%s/server-%s.log" % (SINK_LAB, run_id)
    r = sink_bash(module, "cd %s && chmod 755 labtransport && setsid bash -c 'nohup ./labtransport server -addr %s "
                          "> %s 2>&1 & echo $! > server.pid' && sleep 3 && cat server.pid" % (SINK_LAB, SINK, log))
    pid = (r.stdout or "").strip()
    listening = server_listening(module)
    record.update({"server_sha256": want, "server_pid": pid, "server_log": log, "listening_at_start": listening,
                   "started_utc": datetime.now(timezone.utc).isoformat()})
    require(all(listening.values()), "test server not listening on every port: %s" % listening)


def server_stop(module, record, local_log):
    r = sink_bash(module, "cd %s && (kill $(cat server.pid) 2>/dev/null; sleep 1; pkill -x labtransport; true) && "
                          "(pgrep -x labtransport || echo stopped)" % SINK_LAB)
    record["stopped"] = "stopped" in (r.stdout or "")
    record["listening_after_stop"] = server_listening(module)
    if record.get("server_log"):
        cp = sink_copyfrom(module, record["server_log"], local_log)
        record["log_fetched"] = cp.returncode == 0
        if cp.returncode == 0:
            record["log_sha256"] = digest(local_log)
    record["stopped_utc"] = datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------------------------------- the run

def run(approval):
    require(approval and approval.strip(), "verbatim approval required")
    for p in (LABT, PYCLIENT, FLOOD_GEN):
        require(p.is_file(), "missing " + str(p))
    _assert_safe()
    runner = lr.use_installed_runner()
    v21.verify_production()
    require(v21.SETTINGS[:2] == ["--timeout", "20"], "settings changed")
    run_id = stamp()
    attempt = ROOT / "transport21-collect" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/transport21-" + run_id
    snapshot = "clean-transport21-" + run_id
    order, pbytes = package(attempt, guest_root)
    module = frozen.helper()
    protocol = {"format": "transport21-collect-v1", "schema": v21.SCHEMA, "guest_root": guest_root,
                "new_snapshot": snapshot, "settings": v21.SETTINGS, "baseline": v21.BASELINE,
                "original": module.ORIGINAL, "approval": approval, "runner": runner,
                "payload_sha256": hashlib.sha256(pbytes).hexdigest(), "cases": order,
                "server": {"binary_sha256": digest(LABT), "ports": PORTS, "host": SINK, "lab_dir": SINK_LAB},
                "sources": {"collect_transport21.py": digest(Path(__file__)), "labtransport": digest(LABT),
                            "transport_client.py": digest(PYCLIENT), "flood_gen": digest(FLOOD_GEN),
                            "labtransport_src_main.go": digest(T21 / "src" / "main.go"),
                            "labtransport_go.sum": digest(T21 / "src" / "go.sum")},
                "note": "benign clients over plain/TLS1.1/TLS1.2/TLS1.3/QUIC to our own server on the Sink; "
                        "20-s observation; capture only; no malware"}
    save(attempt / "protocol.json", protocol)
    destination = attempt / "run"
    destination.mkdir()
    save(destination / "authorization.json", {"approval": approval,
                                              "authorized_utc": datetime.now(timezone.utc).isoformat()})

    def interrupted(_s, _f):
        raise KeyboardInterrupt("stop + restore original")
    prev = signal.signal(signal.SIGTERM, interrupted)
    touched = False
    server = {}
    try:
        with (Path(module.__file__).parent / "readiness.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            before = v21.preflight(module, protocol)
            save(destination / "initial_vm_state.json", before)
            require(not v21.snapshot_present(module, snapshot), "child already exists")
            server_start(module, run_id, server)
            save(destination / "server.json", server)
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
            if server:
                server_stop(module, server, destination / "server.log")
                # a new file: save() refuses to overwrite, and server.json holds the start record
                save(destination / "server_stop.json", server)
        finally:
            try:
                if touched:
                    frozen.restore(module, destination)
            finally:
                signal.signal(signal.SIGTERM, prev)
    return attempt


def client_summary(out_dir):
    for name in ("sample.stdout.log", "stdout.log"):
        p = out_dir / name
        if p.exists():
            for line in reversed(p.read_text(errors="replace").splitlines()):
                line = line.strip()
                if line.startswith("{") and '"Mode"' in line:
                    try:
                        return json.loads(line)
                    except ValueError:
                        return None
    return None


def validate(attempt):
    """Per case: retrieved, quality accepted, target exec observed, 40 windows, no eBPF loss or overflow; and the
    behaviour: the client's own summary shows only successful requests over the intended version, and the capture
    has traffic with the Sink beyond the collector's eight probe frames. Nulls: exit 0."""
    attempt = Path(attempt).resolve()
    protocol = json.load(open(attempt / "protocol.json"))
    sys.path.insert(0, str(ROOT.parents[4] / "p4-ebpf-malware-detection" / "features"))
    import switch_model as sm  # noqa: E402
    expect = {"http": "plain/HTTP/1.1", "tls11": "TLS1.1/HTTP/1.1", "tls12": "TLS1.2/HTTP/1.1",
              "tls13": "TLS1.3/HTTP/1.1", "quic": "TLS1.3/HTTP/3.0"}
    expect_py = {"http": "plain/HTTP/1.1", "tls11": "TLSv1.1/HTTP/1.1", "tls12": "TLSv1.2/HTTP/1.1",
                 "tls13": "TLSv1.3/HTTP/1.1"}
    rows = []
    for c in protocol["cases"]:
        runs = sorted((attempt / "runs" / c["sample"] / "output").glob("run_*"))
        rec = {"sample": c["sample"], "label": c["label"], "program": c.get("program"),
               "transport": c.get("transport"), "workload": c.get("workload")}
        if not runs or not (runs[-1] / "run.json").exists():
            rows.append(dict(rec, status="not_retrieved"))
            continue
        d = json.load(open(runs[-1] / "run.json"))
        rec.update(rc=d.get("return_code"), quality=d.get("collection_quality_status"),
                   exec=(d.get("target_exec") or {}).get("status"), windows=d.get("windows"),
                   lost=d.get("ebpf_lost_event_count"), overflow=d.get("ebpf_events_overflow"))
        technical = (rec["quality"] == "accepted" and rec["exec"] == "observed" and rec["windows"] == 40
                     and not rec["lost"] and not rec["overflow"])
        if c["label"] == "null":
            behaviour = rec["rc"] in (c.get("expected_returncodes") or [0])
        else:
            s = client_summary(runs[-1])
            want = (expect if c["program"] == "go" else expect_py)[c["transport"]]
            rec["client"] = {k: s.get(k) for k in ("OK", "Failed", "Connections", "Bytes", "Versions")} if s else None
            sink = 0
            for _, _, frame in sm.read_pcap(str(runs[-1] / "packet_capture.pcap")):
                p = sm.parse_flow_packet(frame)
                if p and SINK in (p[0], p[1]):
                    sink += 1
            rec["sink_packets"] = sink
            behaviour = bool(s and s.get("OK", 0) > 0 and s.get("Failed", 1) == 0
                             and set((s.get("Versions") or {}).keys()) == {want} and sink > 8)
        rec["status"] = "accepted" if technical and behaviour else ("behaviour_mismatch" if technical else "rejected")
        rows.append(rec)
    summary = Counter(r["status"] for r in rows)
    by = Counter(((r.get("program") or "null"), r.get("transport") or "-", r["status"]) for r in rows)
    out = attempt / ("validation-%s.json" % stamp())
    server_log = attempt / "run" / "server.log"
    srv = Counter()
    if server_log.exists():
        for line in server_log.read_text(errors="replace").splitlines():
            try:
                e = json.loads(line)
            except ValueError:
                continue
            if "port" in e:
                srv[(e["port"], e.get("proto"), e.get("tls"))] += 1
    save(out, {"summary": dict(summary), "by_program_transport": {str(k): v for k, v in sorted(by.items())},
               "server_requests": {str(k): v for k, v in sorted(srv.items())}, "cases": rows})
    print(json.dumps({"summary": dict(summary), "server_requests": {str(k): v for k, v in sorted(srv.items())},
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
        _assert_safe()
        attempt = ROOT / "transport21-collect" / ("build-only-" + stamp())
        attempt.mkdir(parents=True, exist_ok=False)
        order, pbytes = package(attempt, "/home/csci/Downloads/transport21-build-only")
        print("built", attempt, "cases", len(order), "payload MB %.1f" % (len(pbytes) / 1e6))
        print(json.dumps(json.load(open(attempt / "payload" / "payload_manifest.json"))["counts"]))
    elif a.run:
        run(a.approval)
    elif a.validate:
        validate(a.validate)
    else:
        print("use --build-only, --run --approval '<verbatim>', or --validate ATTEMPT")


if __name__ == "__main__":
    main()

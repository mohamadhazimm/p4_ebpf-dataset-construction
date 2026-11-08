"""E5: run each workload twice, over HTTP and over HTTPS to the Sink, everything else equal.

    /usr/bin/python3 e5_tls_pairs.py build
    /usr/bin/python3 e5_tls_pairs.py run <attempt> --approval "<verbatim>"

Benign clients use tls_client.py (unverified TLS); the two tools use their own HTTPS modes (slowloris
--https, goldeneye -n). Reuses the collector, settings and VM machinery of collect_realtools21. Capture
only, one batch, restore the original snapshot afterward. Pairs share a base name with -http / -https.
"""
import argparse
import hashlib
import io
import json
import signal
import subprocess
import sys
import tarfile
import zipfile
import fcntl
import re
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
import collect_v21 as v21        # noqa: E402
import collect_v19 as frozen     # noqa: E402

save, stamp, require = frozen.save, frozen.stamp, frozen.require
FLOOD_GEN = ROOT / "flood_gen"
FLOOD_GEN_SHA = "1bc8630d60d7330b7089879cb2a684d2bbc59b8f47e980c1b7ff92155fefdd6d"
SLOWLORIS = ROOT / "realtools" / "slowloris.py"
GOLDENEYE = ROOT / "realtools" / "goldeneye.py"
TLS_CLIENT = HERE / "e5_tls" / "tls_client.py"
SINK = "10.0.0.1"
_IP = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


def pairs():
    """(base, tool, http_argv, https_argv). http/https argv feed flood_gen; the staged tool is `tool`."""
    out = []
    for shape in ("poll", "pool", "session", "upload", "download"):
        out.append(("benign_" + shape, "tls_client.py",
                    ["pyexec", "tls_client.py", "http", shape, SINK],
                    ["pyexec", "tls_client.py", "https", shape, SINK]))
    for n in ("300", "800"):
        out.append(("slowloris_" + n, "slowloris.py",
                    ["pyexec", "slowloris.py", SINK, "-p", "80", "-s", n],
                    ["pyexec", "slowloris.py", SINK, "-p", "443", "-s", n, "--https"]))
    for m in ("get", "post"):
        out.append(("goldeneye_" + m, "goldeneye.py",
                    ["pyexec", "goldeneye.py", "http://%s/" % SINK, "-w", "10", "-s", "500", "-m", m],
                    ["pyexec", "goldeneye.py", "https://%s/" % SINK, "-w", "10", "-s", "500", "-m", m, "-n"]))
    return out


def cases():
    out = []
    for base, tool, http_argv, https_argv in pairs():
        label = "benign" if base.startswith("benign_") else "attack"
        out.append({"sample": base + "-http.zip", "base": base, "label": label, "scheme": "http", "tool": tool, "argv": http_argv})
        out.append({"sample": base + "-https.zip", "base": base, "label": label, "scheme": "https", "tool": tool, "argv": https_argv})
    return out


def assert_safe(case_list):
    tools = {"tls_client.py", "slowloris.py", "goldeneye.py"}
    for c in case_list:
        require(c["tool"] in tools and c["argv"][0] == "pyexec" and c["argv"][1] == c["tool"], "bad pyexec " + c["sample"])
        for tok in c["argv"]:
            for ip in _IP.findall(tok):
                require(ip == SINK or ip.startswith("10.0."), "non-lab address in " + c["sample"])
            if tok.startswith("http") and "://" in tok:
                require(tok in ("http://%s/" % SINK, "https://%s/" % SINK), "bad url " + c["sample"])


def sha256(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def build():
    require(sha256(FLOOD_GEN) == FLOOD_GEN_SHA, "flood_gen changed")
    v21.verify_production()
    case_list = cases()
    assert_safe(case_list)
    run_id = stamp()
    attempt = HERE / "e5-attempts" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/e5-tls-" + run_id
    payload = attempt / "payload"
    (payload / "samples").mkdir(parents=True)
    (payload / "arguments").mkdir()
    gen = FLOOD_GEN.read_bytes()
    tool_bytes = {"tls_client.py": TLS_CLIENT.read_bytes(), "slowloris.py": SLOWLORIS.read_bytes(), "goldeneye.py": GOLDENEYE.read_bytes()}
    for c in case_list:
        with zipfile.ZipFile(payload / "samples" / c["sample"], "w") as z:
            z.writestr("flood_gen", gen)
            z.writestr(c["tool"], tool_bytes[c["tool"]])
        (payload / "arguments" / (c["sample"] + ".json")).write_text(json.dumps(c["argv"]))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for p in sorted(payload.rglob("*")):
            tar.add(p, arcname=str(p.relative_to(payload)), recursive=False)
    data = buf.getvalue()
    (attempt / "payload.tgz").write_bytes(data)
    setup = v21.build_setup(guest_root, data)
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(c["sample"] + "\n" for c in case_list))
    save(attempt / "protocol.json", {"format": "e5-tls-pairs-v1", "kind": "e5", "schema": v21.SCHEMA,
         "guest_root": guest_root, "new_snapshot": "clean-e5-tls-" + run_id, "baseline": v21.BASELINE,
         "baseline_uuid": v21.BASELINE_UUID, "original_uuid": v21.ORIGINAL_UUID, "settings": v21.SETTINGS,
         "payload_sha256": sha256(attempt / "payload.tgz"), "driver_sha256": sha256(__file__),
         "tls_client_sha256": sha256(TLS_CLIENT), "cases": case_list, "approval": None})
    print(json.dumps({"attempt": str(attempt), "cases": len(case_list)}))


def run(attempt, approval):
    require(approval and approval.strip(), "verbatim approval required")
    attempt = Path(attempt).resolve()
    protocol = json.loads((attempt / "protocol.json").read_text())
    require(sha256(attempt / "payload.tgz") == protocol["payload_sha256"], "payload changed since build")
    assert_safe(protocol["cases"])
    v21.verify_production()
    destination = attempt / "run"
    destination.mkdir()
    save(destination / "authorization.json", {"approval": approval, "authorized_utc": datetime.now(timezone.utc).isoformat()})
    module = frozen.helper()
    snapshot = protocol["new_snapshot"]

    def interrupted(_s, _f):
        raise KeyboardInterrupt("stop + restore original")
    previous = signal.signal(signal.SIGTERM, interrupted)
    touched = False
    try:
        with (Path(module.__file__).parent / "readiness.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            save(destination / "initial_vm_state.json", v21.preflight(module, protocol))
            require(not v21.snapshot_present(module, snapshot), "child snapshot already exists")
            touched = True
            frozen.run_logged(v21.stage_command(attempt, module, snapshot), destination / "stage.log", 1800)
            frozen.run_logged(v21.batch_command(module, attempt, protocol, snapshot, attempt / "dry-run",
                                                attempt / "cases.txt", dry_run=True), destination / "dry-run.log", 1800)
            validated = v21.validate_dry_run(destination / "dry-run.log", protocol)
            frozen.run_logged(v21.batch_command(module, attempt, protocol, snapshot, attempt / "runs", attempt / "cases.txt"),
                              destination / "collection.log", 3 * 3600)
            reached = "Batch complete" in (destination / "collection.log").read_text()
            save(destination / "result.json", {"status": "passed", "dry_run_validated": validated, "reached_batch_complete": reached})
            print(json.dumps({"attempt": str(attempt), "dry_run_validated": validated, "reached_batch_complete": reached}))
    except BaseException as error:
        save(destination / "result.json", {"status": "failed_preserved", "error": type(error).__name__ + ": " + str(error)})
        raise
    finally:
        try:
            if touched:
                frozen.restore(module, destination)
        finally:
            signal.signal(signal.SIGTERM, previous)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("build")
    r = sub.add_parser("run")
    r.add_argument("attempt")
    r.add_argument("--approval", required=True)
    a = ap.parse_args()
    build() if a.command == "build" else run(a.attempt, a.approval)


if __name__ == "__main__":
    main()

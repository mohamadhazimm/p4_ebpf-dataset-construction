"""Capture benign LOW-RATE background traffic (lowrate_gen) through the real .21 collector, with the same
runner, schema, settings, quiet baseline snapshot and production batch as the dataset's flood21 runs, so
the new runs become rows of the same format. Benign only: every case talks only to the Sink (10.0.0.1),
at most a few operations per second, and exits on its own after 19 s (status 0, inside the 20-s
observation). Periods follow common device and daemon behavior (polls, keepalives, DNS, NTP, TLS
heartbeats every 1 to 16 s), not values fitted to any test set.

One batch, no retries or replacements; the original snapshot is restored and powered off at the end.
A case counts only if the collector accepted it and the receipt shows that every activity got answers
(checked offline, see score_lowrate21.py). Usage: python3 collect_lowrate21.py --run --approval "<verbatim>".
"""
import argparse, io, json, re, signal, subprocess, sys, tarfile, zipfile, fcntl
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import collect_v21 as v21        # noqa: E402
import collect_v19 as frozen     # noqa: E402

digest, save, stamp = frozen.digest, frozen.save, frozen.stamp
LOWRATE_GEN = ROOT / "lowrate_gen"   # native amd64 static ELF (gcc -static, as flood_gen), see lowrate_gen.c
SINK = "10.0.0.1"
DURATION = "19000"

CASES = [
    ("lr_poll_1s",    ["poll", "1000", DURATION, SINK, "80"]),
    ("lr_poll_2s",    ["poll", "2000", DURATION, SINK, "80"]),
    ("lr_poll_5s",    ["poll", "5000", DURATION, SINK, "80"]),
    ("lr_poll_10s",   ["poll", "10000", DURATION, SINK, "80"]),
    ("lr_keep_1s",    ["keepalive", "1000", DURATION, SINK, "80"]),
    ("lr_keep_3s",    ["keepalive", "3000", DURATION, SINK, "80"]),
    ("lr_keep_10s",   ["keepalive", "10000", DURATION, SINK, "80"]),
    ("lr_dns_1s",     ["dns", "1000", DURATION, SINK]),
    ("lr_dns_4s",     ["dns", "4000", DURATION, SINK]),
    ("lr_dns_10s",    ["dns", "10000", DURATION, SINK]),
    ("lr_ntp_2s",     ["ntp", "2000", DURATION, SINK]),
    ("lr_ntp_8s",     ["ntp", "8000", DURATION, SINK]),
    ("lr_tls_3s",     ["tlspoll", "3000", DURATION, SINK, "443"]),
    ("lr_tls_10s",    ["tlspoll", "10000", DURATION, SINK, "443"]),
    ("lr_tlskeep_5s", ["tlskeep", "5000", DURATION, SINK, "443"]),
    ("lr_device_a",   ["device", "a", DURATION, SINK]),
    ("lr_device_b",   ["device", "b", DURATION, SINK]),
    ("lr_device_c",   ["device", "c", DURATION, SINK]),
]
_IP = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _assert_targets_safe():
    for name, argv in CASES:
        ips = [t for t in argv if _IP.match(t)]
        assert ips == [SINK], "%s must name exactly the Sink, got %s" % (name, ips)


def build_payload(attempt, guest_root):
    payload = attempt / "payload"
    (payload / "samples").mkdir(parents=True)
    (payload / "arguments").mkdir()
    gen = LOWRATE_GEN.read_bytes()
    for name, argv in CASES:
        with zipfile.ZipFile(payload / "samples" / (name + ".zip"), "w") as z:
            z.writestr("lowrate_gen", gen)                    # single ELF member; batch finds it
        (payload / "arguments" / (name + ".zip.json")).write_text(json.dumps(argv))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for p in sorted(payload.rglob("*")):
            tar.add(p, arcname=str(p.relative_to(payload)), recursive=False)
    pbytes = buf.getvalue()
    (attempt / "payload.tgz").write_bytes(pbytes)
    setup = v21.build_setup(guest_root, pbytes)
    subprocess.run(["bash", "-n"], input=setup, text=True, check=True)
    (attempt / "setup_guest.sh").write_text(setup)
    (attempt / "cases.txt").write_text("".join(n + ".zip\n" for n, _ in CASES))
    return pbytes


V22_SHA = "b6d7abb91fd35d10514a85f354818e51786e2247a5f2354c051f7fdbbd8190f6"
V22_NOTE = (".22 = .21 plus a cap on the number of retained eBPF events (overflow counted and rejected); "
            "features and their computation unchanged, so 20-s runs below the cap match .21 rows")


def use_installed_runner():
    """Pin whichever accepted runner is installed: .21 as is, or .22 with the same overrides the
    observation-length pilot uses (schema and runner hash; the 20-s settings stay)."""
    observed = digest(frozen.STUDY / "src/malware_runner.py")
    if observed == v21.PINNED["src/malware_runner.py"]:
        return {"runner": ".21", "sha256": observed}
    if observed == V22_SHA:
        v21.SCHEMA = "2026-11-05.22"
        v21.PINNED = dict(v21.PINNED, **{"src/malware_runner.py": V22_SHA})
        return {"runner": ".22", "sha256": observed, "note": V22_NOTE}
    raise SystemExit("src/malware_runner.py is neither .21 nor .22 (%s); refusing" % observed)


def run(approval):
    frozen.require(approval and approval.strip(), "verbatim approval required")
    frozen.require(LOWRATE_GEN.is_file(), "lowrate_gen binary missing")
    _assert_targets_safe()
    runner = use_installed_runner()
    v21.verify_production()
    run_id = stamp()
    attempt = ROOT / "lowrate21-collect" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/lowrate21-" + run_id
    snapshot = "clean-lowrate21-" + run_id
    build_payload(attempt, guest_root)
    protocol = {"format": "lowrate21-collect-v1", "schema": v21.SCHEMA, "guest_root": guest_root,
                "new_snapshot": snapshot, "settings": v21.SETTINGS,
                "binary": {"lowrate_gen": digest(LOWRATE_GEN), "lowrate_gen.c": digest(ROOT / "lowrate_gen.c")},
                "cases": [{"sample": n + ".zip", "name": n, "argv": a} for n, a in CASES],
                "baseline": v21.BASELINE, "original": None, "approval": approval, "runner": runner,
                "note": "benign low-rate lowrate_gen through the real .21 collector; capture only"}
    module = frozen.helper()
    protocol["original"] = module.ORIGINAL
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
            frozen.require(not v21.snapshot_present(module, snapshot), "child already exists")
            touched = True
            frozen.run_logged(v21.stage_command(attempt, module, snapshot), destination / "stage.log", 1800)
            frozen.run_logged(v21.batch_command(module, attempt, protocol, snapshot, attempt / "runs", attempt / "cases.txt"),
                              destination / "collection.log", 2 * 3600)
            reached = "Batch complete" in (destination / "collection.log").read_text()
            save(destination / "result.json", {"status": "passed", "reached_batch_complete": reached,
                 "cases": [n for n, _ in CASES]})
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--build-only", action="store_true", help="build and check the payload; no VM operation")
    ap.add_argument("--approval")
    a = ap.parse_args()
    if a.build_only:
        _assert_targets_safe()
        attempt = ROOT / "lowrate21-collect" / ("build-only-" + stamp())
        attempt.mkdir(parents=True, exist_ok=False)
        build_payload(attempt, "/home/csci/Downloads/lowrate21-build-only")
        print("built", attempt)
    elif a.run:
        run(a.approval)
    else:
        print("use --build-only, or --run --approval '<verbatim>'")


if __name__ == "__main__":
    main()

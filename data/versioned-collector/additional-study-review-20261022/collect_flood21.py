"""Capture RATE-CAPPED flood_gen workloads through the REAL .21 collector (same runner/schema/
settings as the revision5 cohort), so the resulting 169-feature records are scorable by the
revision5-trained host/P4/hybrid models. Rate-capped (<=~200k packets / <~1M syscalls per run) to
stay inside the .21 eBPF envelope proven clean by the integrity battery (250k UDP, 0 lost), so the
collector does NOT overflow. Flow-shape is rate-independent, so these remain detector-equivalent floods.

Reuses collect_v21's tested VM primitives (verify_production, build_setup, stage/batch command builders)
+ collect_v19 helpers (helper/run_logged/restore/state). NO Sink-only traffic gate (a fan-out flood is
not Sink-only by design); technical acceptance (quality=no-overflow, 40x169 finite) is checked offline.

SAFETY: floods target ONLY the sealed 10.0.x.y subnet (die at gateway); bulk targets ONLY the Sink;
guest intnet-only; BASELINE-child per sample (the batch restores around each); ORIGINAL restore+poweroff
at end. No model trained here, no merge. Usage: python3 collect_flood21.py --run --approval "<verbatim>".
"""
import argparse, io, json, os, signal, subprocess, sys, tarfile, zipfile, fcntl
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import collect_v21 as v21        # noqa: E402
import collect_v19 as frozen     # noqa: E402

STUDY = frozen.STUDY
digest, save, load, stamp = frozen.digest, frozen.save, frozen.load, frozen.stamp
FLOOD_GEN = ROOT / "flood_gen"   # native amd64 static ELF, built+verified this session

# Diverse flow-shape set for a publishable network-side n: 18 floods across 6 attack-shapes +
# 11 network-active benign across 4 legit-shapes + 2 nulls, all rate-capped through the real .21
# collector. Floods are SYN-only / UDP-unidirectional / abnormal-concurrency (shape-distinct from
# benign); benign are handshaked request/response. Fan-out floods hit the sealed 10.0.x.y /16 (die at
# the gateway); everything else hits the Sink 10.0.0.1 only.
CASES = [
    # --- floods (attack-shaped) ---
    ("syn_fan_40k",   ["synflood", "40000", "23"]),
    ("syn_fan_100k",  ["synflood", "100000", "23"]),
    ("syn_fan_150k",  ["synflood", "150000", "23"]),
    ("syn_sink_40k",  ["synsink", "40000", "80", "10.0.0.1"]),
    ("syn_sink_100k", ["synsink", "100000", "80", "10.0.0.1"]),
    ("syn_sink_150k", ["synsink", "150000", "80", "10.0.0.1"]),
    ("udp_fan_60k",   ["udpflood", "60000", "65001"]),
    ("udp_fan_150k",  ["udpflood", "150000", "65001"]),
    ("udp_fan_250k",  ["udpflood", "250000", "65001"]),
    ("udp_sink_60k",  ["udpdirect", "60000", "65003", "10.0.0.1"]),
    ("udp_sink_150k", ["udpdirect", "150000", "65003", "10.0.0.1"]),
    ("udp_sink_250k", ["udpdirect", "250000", "65003", "10.0.0.1"]),
    ("slowloris_128", ["slowloris", "128", "10.0.0.1", "80"]),
    ("slowloris_256", ["slowloris", "256", "10.0.0.1", "80"]),
    ("slowloris_512", ["slowloris", "512", "10.0.0.1", "80"]),
    ("httpflood_5k",  ["httpflood", "5000", "10.0.0.1", "80"]),
    ("httpflood_10k", ["httpflood", "10000", "10.0.0.1", "80"]),
    ("httpflood_20k", ["httpflood", "20000", "10.0.0.1", "80"]),
    # --- network-active benign (legit-shaped) ---
    ("bulkup_200",   ["bulkup", "200", "10.0.0.1", "80"]),
    ("bulkup_400",   ["bulkup", "400", "10.0.0.1", "80"]),
    ("bulkup_700",   ["bulkup", "700", "10.0.0.1", "80"]),
    ("session_300",  ["session", "300", "10.0.0.1", "80"]),
    ("session_600",  ["session", "600", "10.0.0.1", "80"]),
    ("session_1000", ["session", "1000", "10.0.0.1", "80"]),
    ("beacon_50",    ["beacon", "50", "10.0.0.1", "80", "200"]),
    ("beacon_100",   ["beacon", "100", "10.0.0.1", "80", "150"]),
    ("dns_2k",       ["dns", "2000", "10.0.0.1"]),
    ("dns_5k",       ["dns", "5000", "10.0.0.1"]),
    ("dns_10k",      ["dns", "10000", "10.0.0.1"]),
    # --- nulls ---
    ("null1", ["null"]),
    ("null2", ["null"]),
]

import re as _re
_IP = _re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _assert_targets_safe():
    # every dotted-IP argv token must be the Sink (our box); fan-out floods carry no IP literal
    # (subnet default 10.0.x.y, sealed). Nothing may name the guest or an external address.
    for name, argv in CASES:
        for tok in argv:
            if _IP.match(tok):
                assert tok == "10.0.0.1", "%s targets non-Sink IP %s" % (name, tok)


def build_payload(attempt, guest_root):
    payload = attempt / "payload"
    (payload / "samples").mkdir(parents=True)
    (payload / "arguments").mkdir()
    gen = FLOOD_GEN.read_bytes()
    for name, argv in CASES:
        zf = payload / "samples" / (name + ".zip")
        with zipfile.ZipFile(zf, "w") as z:
            z.writestr("flood_gen", gen)                      # single ELF member; batch finds it
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


def run(approval):
    frozen.require(approval and approval.strip(), "verbatim approval required")
    frozen.require(FLOOD_GEN.is_file(), "flood_gen binary missing")
    _assert_targets_safe()
    v21.verify_production()
    run_id = stamp()
    attempt = ROOT / "flood21-collect" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/flood21-" + run_id
    snapshot = "clean-flood21-" + run_id
    build_payload(attempt, guest_root)
    protocol = {"format": "flood21-collect-v1", "schema": v21.SCHEMA, "guest_root": guest_root,
                "new_snapshot": snapshot, "settings": v21.SETTINGS,
                "cases": [{"sample": n + ".zip", "name": n, "argv": a} for n, a in CASES],
                "baseline": v21.BASELINE, "original": None, "approval": approval,
                "note": "rate-capped flood_gen through the real .21 collector; no Sink-only traffic gate; capture only"}
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
    ap.add_argument("--approval")
    a = ap.parse_args()
    if a.run:
        run(a.approval)
    else:
        print("use --run --approval '<verbatim>'")


if __name__ == "__main__":
    main()

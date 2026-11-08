"""Capture REAL published DDoS tools + socket-flood volumetrics through the REAL .21 collector, so the
resulting 169-feature records are scorable by the ADFA-90 host / P4 / hybrid models.

Application-layer floods use the published tools Slowloris (gkbrk) and GoldenEye (jseidl), run via flood_gen's
`pyexec` mode (flood_gen is an ELF so it passes the batch's arch gate; it execs python3 on the tool staged beside
it, so the traced image BECOMES the real tool). Volumetric SYN/UDP floods use flood_gen's unprivileged
connect()/sendto() method -- there is no unprivileged named tool for raw floods (hping3 needs root), and this is
the technique an unprivileged IoT bot (and our captured live Kaiten) uses.

SAFETY: floods hit ONLY the sealed 10.0.x.y /16 (fan-out, die at gateway) or the Sink 10.0.0.1; samples run
unprivileged as csci; BASELINE-child per case; ORIGINAL restore+poweroff at end. No model, no merge, capture only.
Usage: python3 collect_realtools21.py --run --approval "<verbatim>"
"""
import argparse, io, json, re, signal, subprocess, sys, tarfile, zipfile, fcntl
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import collect_v21 as v21        # noqa: E402
import collect_v19 as frozen     # noqa: E402

save, stamp = frozen.save, frozen.stamp
FLOOD_GEN = ROOT / "flood_gen"
SLOWLORIS = ROOT / "realtools" / "slowloris.py"
GOLDENEYE = ROOT / "realtools" / "goldeneye.py"

# (name, py_tool_or_None, argv-to-flood_gen)
CASES = [
    # volumetric SYN/UDP floods (flood_gen unprivileged socket method)
    ("syn_fan_40k",   None, ["synflood", "40000", "23"]),
    ("syn_fan_100k",  None, ["synflood", "100000", "23"]),
    ("syn_fan_150k",  None, ["synflood", "150000", "23"]),
    ("syn_sink_40k",  None, ["synsink", "40000", "80", "10.0.0.1"]),
    ("syn_sink_100k", None, ["synsink", "100000", "80", "10.0.0.1"]),
    ("udp_fan_60k",   None, ["udpflood", "60000", "65001"]),
    ("udp_fan_250k",  None, ["udpflood", "250000", "65001"]),
    ("udp_sink_60k",  None, ["udpdirect", "60000", "65003", "10.0.0.1"]),
    ("udp_sink_150k", None, ["udpdirect", "150000", "65003", "10.0.0.1"]),
    ("udp_sink_250k", None, ["udpdirect", "250000", "65003", "10.0.0.1"]),
    # application-layer floods: REAL Slowloris (varied socket counts)
    ("slowloris_150",  "slowloris.py", ["pyexec", "slowloris.py", "10.0.0.1", "-p", "80", "-s", "150"]),
    ("slowloris_300",  "slowloris.py", ["pyexec", "slowloris.py", "10.0.0.1", "-p", "80", "-s", "300"]),
    ("slowloris_500",  "slowloris.py", ["pyexec", "slowloris.py", "10.0.0.1", "-p", "80", "-s", "500"]),
    ("slowloris_800",  "slowloris.py", ["pyexec", "slowloris.py", "10.0.0.1", "-p", "80", "-s", "800"]),
    ("slowloris_1000", "slowloris.py", ["pyexec", "slowloris.py", "10.0.0.1", "-p", "80", "-s", "1000"]),
    # application-layer floods: REAL GoldenEye (varied workers/sockets/method)
    ("goldeneye_g5",   "goldeneye.py", ["pyexec", "goldeneye.py", "http://10.0.0.1/", "-w", "5", "-s", "300", "-m", "get"]),
    ("goldeneye_g10",  "goldeneye.py", ["pyexec", "goldeneye.py", "http://10.0.0.1/", "-w", "10", "-s", "500", "-m", "get"]),
    ("goldeneye_g15",  "goldeneye.py", ["pyexec", "goldeneye.py", "http://10.0.0.1/", "-w", "15", "-s", "800", "-m", "get"]),
    ("goldeneye_p10",  "goldeneye.py", ["pyexec", "goldeneye.py", "http://10.0.0.1/", "-w", "10", "-s", "500", "-m", "post"]),
    ("goldeneye_r10",  "goldeneye.py", ["pyexec", "goldeneye.py", "http://10.0.0.1/", "-w", "10", "-s", "500", "-m", "random"]),
]

_IP = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_ALLOWED_PY = {"slowloris.py", "goldeneye.py"}


def _assert_safe():
    for name, tool, argv in CASES:
        for tok in argv:
            for ip in _IP.findall(tok):
                assert ip == "10.0.0.1" or ip.startswith("10.0."), "%s targets non-lab IP %s" % (name, ip)
            if tok.startswith("http"):
                assert tok in ("http://10.0.0.1/",), "%s bad URL %s" % (name, tok)
        if argv[0] == "pyexec":
            assert argv[1] in _ALLOWED_PY and tool == argv[1], "%s bad pyexec target" % name
            assert tool is not None
        else:
            assert tool is None


def build_payload(attempt, guest_root):
    payload = attempt / "payload"
    (payload / "samples").mkdir(parents=True)
    (payload / "arguments").mkdir()
    gen = FLOOD_GEN.read_bytes()
    tools = {"slowloris.py": SLOWLORIS.read_bytes(), "goldeneye.py": GOLDENEYE.read_bytes()}
    for name, tool, argv in CASES:
        with zipfile.ZipFile(payload / "samples" / (name + ".zip"), "w") as z:
            z.writestr("flood_gen", gen)                 # ELF entrypoint (passes the batch arch gate)
            if tool:
                z.writestr(tool, tools[tool])            # real tool staged beside it; pyexec execs python3 on it
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
    (attempt / "cases.txt").write_text("".join(n + ".zip\n" for n, _, _ in CASES))
    return pbytes


def run(approval):
    frozen.require(approval and approval.strip(), "verbatim approval required")
    for p in (FLOOD_GEN, SLOWLORIS, GOLDENEYE):
        frozen.require(p.is_file(), "missing " + p.name)
    _assert_safe()
    v21.verify_production()
    run_id = stamp()
    attempt = ROOT / "realtools-collect" / run_id
    attempt.mkdir(parents=True, exist_ok=False)
    guest_root = "/home/csci/Downloads/realtools-" + run_id
    snapshot = "clean-realtools21-" + run_id
    build_payload(attempt, guest_root)
    protocol = {"format": "realtools21-collect-v1", "schema": v21.SCHEMA, "guest_root": guest_root,
                "new_snapshot": snapshot, "settings": v21.SETTINGS, "baseline": v21.BASELINE, "original": None,
                "tools": {"slowloris": SLOWLORIS.name, "goldeneye": GOLDENEYE.name},
                "cases": [{"name": n, "tool": t, "argv": a} for n, t, a in CASES], "approval": approval,
                "note": "real published tools (Slowloris/GoldenEye via flood_gen pyexec) + unprivileged volumetric; capture only"}
    module = frozen.helper()
    protocol["original"] = module.ORIGINAL
    save(attempt / "protocol.json", protocol)
    destination = attempt / "run"; destination.mkdir()
    save(destination / "authorization.json", {"approval": approval, "authorized_utc": datetime.now(timezone.utc).isoformat()})

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
                 "cases": [n for n, _, _ in CASES]})
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
        _assert_safe()
        print("cases:", len(CASES), "(volumetric %d, slowloris %d, goldeneye %d)" %
              (sum(1 for _, t, _ in CASES if t is None),
               sum(1 for _, t, _ in CASES if t == "slowloris.py"),
               sum(1 for _, t, _ in CASES if t == "goldeneye.py")))
        print("safety assert: PASS")


if __name__ == "__main__":
    main()

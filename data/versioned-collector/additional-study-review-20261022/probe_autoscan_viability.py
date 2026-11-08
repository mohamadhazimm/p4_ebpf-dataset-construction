"""VIABILITY pass over the autonomous-scanner candidates (sealed VM; scan SYNs die at the gateway).

Reuses probe_net_strong_viability's TESTED VM choreography + reg-only IRC controller + measurement
(host syscalls via in-kernel bpftrace, true enp0s3 NIC deltas, tcpdump flow capture). This driver only
SELECTS the samples and freezes the plan; the run is the engine's run_campaign. Selection = the
"autonomous_scanner_candidate" tier of a static strings recon (same markers as the offline recon),
scanned fresh from the three quarantine dirs (autoscan-incoming + net-strong-incoming + triage-netstrong),
so already-collected samples moved aside are excluded automatically. Each sample is staged as a zip into
the attempt and run autonomously, or (when it carries a public non-resolver candidate C2 IP) with that IP
aliased to the guest's lo + the reg-only multi-port IRC controller (registration/keepalive ONLY; NO attack
command -- the bot's own launch scanner is the flood). flood = tx_packets > FLOOD_TX.

SAFETY (inherited, unchanged): guest intnet-only on sealed malnet; C2 only on an in-guest lo alias; the
controller never sends an attack command; BASELINE restore + poweroff after EACH sample; ORIGINAL restore
at end. No model, no merge, no production change.  Usage: --freeze-only ; then --run --attempt <dir> --approval "<verbatim>".
"""
import argparse, glob, json, math, os, re, shutil, subprocess, sys, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import probe_net_strong_viability as eng   # noqa: E402  (tested engine: choreography, controller, measurement)

STUDY = eng.STUDY
DIRS = [STUDY / "data/malware/revision5-diverse/autoscan-incoming",
        STUDY / "data/malware/revision5-diverse/net-strong-incoming",
        STUDY / "data/malware/revision5-diverse/triage-netstrong"]
MANIFESTS = [STUDY / "data/malware/revision5-diverse/autoscan-incoming/autoscan_candidates.json",
             STUDY / "data/malware/revision5-diverse/net-strong-incoming/net_strong_candidates.json",
             STUDY / "data/malware/revision5-diverse/triage-netstrong/triage_netstrong_candidates.json"]
HEX = re.compile(r"[0-9a-f]{64}")
IPRE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# static markers (identical to the offline recon)
MIRAI_CREDS = [b"xc3511", b"vizxv", b"7ujMko0", b"GM8182", b"klv123", b"klv1234", b"zlxx", b"juantech",
               b"888888", b"54321", b"anko", b"jvbzd", b"hi3518", b"ikwb", b"dreambox", b"realtek",
               b"root", b"admin", b"support", b"guest"]
SCANNER = [b"/dev/watchdog", b"/bin/busybox", b"TSource Engine Query", b"REPORT %s:%s", b"scanner",
           b"/proc/net/tcp", b"assword", b"ogin:", b"enable\x00", b"shell\x00", b"telnet"]
PACKER = [b"UPX!", b"This file is packed", b"$Info:"]


def raw_of(path):
    if path.endswith(".zip"):
        try:
            return subprocess.run(["7z", "x", "-so", "-pinfected", path], capture_output=True, timeout=120).stdout
        except Exception:
            return b""
    return open(path, "rb").read()


def entropy(b):
    if not b:
        return 0.0
    import collections
    c = collections.Counter(b); n = len(b); e = 0.0
    for v in c.values():
        p = v / n; e -= p * math.log2(p)
    return e


def analyze(raw):
    """returns (is_autonomous_scanner_candidate, public_non_resolver_c2_ips)."""
    ent = entropy(raw[:2_000_000])
    text = b"\n".join(re.findall(rb"[\x20-\x7e]{4,}", raw))
    printable_ratio = len(text) / max(len(raw), 1)
    packed = any(m in raw for m in PACKER) or ent > 7.2 or printable_ratio < 0.02
    rare_cred = sum(1 for c in MIRAI_CREDS[:16] if c in text)
    scan = sum(1 for m in SCANNER if m in text)
    is_scanner = (not packed) and (rare_cred >= 2 or scan >= 3)
    ips = []
    for m in {x.decode() for x in IPRE.findall(text)}:
        if eng.valid_public(m) and m not in eng.RESOLVERS:
            ips.append(m)
    return is_scanner, sorted(ips)[:6]


def modes():
    sm = {}
    for mp in MANIFESTS:
        if mp.is_file():
            for r in json.load(open(mp)).get("kept", []):
                if r.get("sha256") and r.get("mode"):
                    sm[r["sha256"].lower()] = r["mode"]
    return sm


def build_samples():
    sm = modes()
    out = []
    for d in DIRS:
        for p in sorted(glob.glob(str(d) + "/*.zip") + glob.glob(str(d) + "/*.elf")):
            m = HEX.search(os.path.basename(p))
            if not m:
                continue
            sha = m.group(0)
            is_scanner, c2 = analyze(raw_of(p))
            if not is_scanner:
                continue
            kind = "malware_c2" if c2 else "malware"
            out.append({"name": ("c2_" if c2 else "auto_") + sha[:10], "kind": kind, "sha256": sha,
                        "family": "autoscan", "mode": sm.get(sha, "amd64-static"), "c2_ips": c2, "_src": p})
    return out


def pick_diverse(samples, n):
    """Deterministic diverse subset: round-robin across (source-dir, mode) groups."""
    import collections
    groups = collections.OrderedDict()
    for s in sorted(samples, key=lambda x: (os.path.dirname(x["_src"]), x["mode"], x["sha256"])):
        key = (os.path.basename(os.path.dirname(s["_src"])), s["mode"])
        groups.setdefault(key, []).append(s)
    keys = list(groups.keys())
    out, i = [], 0
    while len(out) < n and any(groups[k] for k in keys):
        k = keys[i % len(keys)]
        if groups[k]:
            out.append(groups[k].pop(0))
        i += 1
    return out


def freeze(tag="autoscan", limit=None):
    eng.v21.verify_production()
    helper = eng.exp.helper_module()
    attempt = ROOT / "autoscan-viability" / (tag + "-" + eng.stamp())
    attempt.mkdir(parents=True, exist_ok=False)
    (attempt / "orchestrate.py").write_text(eng.ORCH_SRC)
    (attempt / "controller.py").write_text(eng.REG_CONTROLLER_SRC)
    subprocess.run(["python3", "-c", "import ast,sys; [ast.parse(open(p).read()) for p in sys.argv[1:]]",
                    str(attempt / "orchestrate.py"), str(attempt / "controller.py")], check=True)
    samples = build_samples()
    if limit:
        samples = pick_diverse(samples, limit)
    eng.frozen.require(len(samples) > 0, "no autonomous-scanner candidates selected")
    sdir = attempt / "samples"; sdir.mkdir()
    for s in samples:
        z = sdir / (s["sha256"] + ".zip")
        if s["_src"].endswith(".zip"):
            shutil.copy2(s["_src"], z)
        else:
            with zipfile.ZipFile(z, "w") as zf:
                zf.write(s["_src"], arcname=s["sha256"])
        s["zip"] = "samples/" + s["sha256"] + ".zip"
        del s["_src"]
    protocol = {"format": "autoscan-viability-v1", "source": "autoscan", "window_seconds": eng.WINDOW,
                "flood_tx_threshold": eng.FLOOD_TX, "c2_ports": eng.C2_PORTS, "samples": samples,
                "baseline_snapshot": eng.v21.BASELINE, "original_snapshot": helper.ORIGINAL,
                "orchestrator_sha256": eng.digest(attempt / "orchestrate.py"),
                "controller_sha256": eng.digest(attempt / "controller.py"),
                "driver_sha256": eng.digest(Path(__file__)), "approval": None,
                "safety": ["guest intnet-only on sealed malnet; scan SYNs die at the gateway (never leave host); "
                           "bot C2 only on in-guest lo alias; reg-only controller sends NO attack command; "
                           "BASELINE restore + poweroff after each sample; ORIGINAL restore at end."]}
    eng.save(attempt / "protocol.json", protocol)
    print(json.dumps({"attempt": str(attempt), "samples": len(samples),
                      "by_mode": {m: sum(1 for s in samples if s["mode"] == m) for m in sorted({s["mode"] for s in samples})},
                      "by_kind": {k: sum(1 for s in samples if s["kind"] == k) for k in sorted({s["kind"] for s in samples})}},
                     indent=2))
    return attempt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--freeze-only", action="store_true")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--attempt")
    ap.add_argument("--approval")
    ap.add_argument("--limit", type=int)
    a = ap.parse_args()
    if a.run:
        eng.run_campaign(a.attempt, a.approval)
    else:
        freeze(tag=("autoscan-derisk%d" % a.limit) if a.limit else "autoscan", limit=a.limit)


if __name__ == "__main__":
    main()

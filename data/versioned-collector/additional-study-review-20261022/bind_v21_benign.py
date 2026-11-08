"""Bind the ~97 v21 benign plan to concrete, already-guest-validated transports + the new musl Sink tasks.

Non-network benign reuse the frozen, guest-validated packaged transports/binaries/fixtures/arguments from two
suites that share the "absolute guest-root fixture path" convention:
  - redesign-native-x64 (amd64 dynamic + static), workloads.json + payload/{samples,arguments,workspace-seed}
  - i386-held-out amendment (i386 static), payload.tgz (samples/binaries/fixtures/arguments)
Each selected case carries its source suite, transport, binary, arguments (guest-root-absolute), fixture files and
expected-output check. Only the guest-root PREFIX is rewritten for v21 at payload-build time; nothing is re-derived.

The ~a-third network-active benign are the new static-musl i386 Sink clients (i386-network-builds/.../bin). Because
redesign's whois/ftp used loopback FIXTURE services (not enp0s3), amd64 network here is limited to curl/wget (HTTP to
the Sink) plus ping/traceroute/telnet to 10.0.0.1; the musl i386 Sink tasks are CANDIDATES validated at the benign-only
preflight (the first VM phase) -- any the Sink does not actually answer on enp0s3 are dropped before the final freeze.

A single global project-held-out split (whole upstream projects to validation, ~30%, seed 42) is applied across all
modes, so a project shared between amd64 and i386 (e.g. curl) stays on one side. This writes benign_binding.json and
prints only aggregate counts. No VM operation, no sample execution.
"""

import argparse
import json
import random
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
REDESIGN = STUDY / "data/versioned-collector/cohort-100x100-v18-20261021/redesign-native-x64"
HOLDOUT = (STUDY / "data/versioned-collector/cohort-expansion-100x100-v18-20261021"
           / "i386-heldout-amendment/20261021T201119747468Z/collection-readiness/20261021T203401085156Z")
MUSL_BIN = ROOT / "i386-network-builds/20261024T163419Z/bin"
AMD64_MUSL_BIN = ROOT / "amd64-network-builds/20261024T172720Z/bin"
OUT_DIR = ROOT / "v21-collection-selection"

TARGET = {"native_amd64_dynamic": 11, "native_amd64_static": 55, "native_i386_static": 31}
SEED = 42
VALIDATION_FRACTION = 0.30
SINK = "10.0.0.1"

# amd64 network programs that genuinely hit the Sink over enp0s3 (HTTP), from redesign's validated set.
REDESIGN_SINK_NETWORK = {"curl", "wget"}
# amd64 "network" programs that actually used loopback fixture services -> NOT enp0s3-active; treat as non-network here.
REDESIGN_LOOPBACK_ONLY = {"whois", "ftp", "inetd", "telnet", "ping", "traceroute", "git-daemon"}

# Programs excluded from benign selection after the first benign-only preflight: git-daemon/xargs exit oddly
# (loopback service -15 / rc123), and the redesign loopback-only service programs do not reach enp0s3.
EXCLUDE_PROGRAMS = {"git-daemon", "xargs", "inetd", "top", "whois", "ftp", "ping", "telnet", "traceroute"}

# Static-musl i386 Sink tasks CONFIRMED to reach the Sink on enp0s3 in the first benign-only preflight
# (curl/wget/openssl/ping/telnet/ftp/whois). traceroute/tftp/logger were dropped: they produced no in-window
# enp0s3 Sink traffic (INetSim does not usefully answer TFTP/syslog; traceroute probes did not land in-window).
MUSL_SINK_TASKS = [
    ("curl", ["--noproxy", "*", "--max-time", "6", "--fail", "-s", "-o", "http.out", f"http://{SINK}/"], ["http.out"]),
    ("curl", ["--noproxy", "*", "--max-time", "6", "--fail", "-s", "-o", "root.out", f"http://{SINK}/index.html"], ["root.out"]),
    ("curl", ["--noproxy", "*", "--max-time", "6", "-sk", "-o", "tls.out", f"https://{SINK}/"], ["tls.out"]),
    ("wget", ["--no-proxy", "--timeout=6", "--tries=1", "-O", "wget.out", f"http://{SINK}/"], ["wget.out"]),
    ("wget", ["--no-proxy", "--timeout=6", "--tries=1", "-O", "wget2.out", f"http://{SINK}/data"], ["wget2.out"]),
    ("openssl", ["s_client", "-connect", f"{SINK}:443", "-servername", "sink.local"], None),
    ("openssl", ["s_client", "-connect", f"{SINK}:443", "-tls1_3"], None),
    ("ping", ["-n", "-c", "3", "-w", "6", SINK], None),
    ("ping", ["-n", "-c", "2", "-i", "0.5", "-w", "6", SINK], None),
    ("telnet", ["-E", SINK, "80"], None),
    ("ftp", ["-4", "-n", "-i", "-e", SINK], None),
    ("ftp", ["-4", "-n", "-p", SINK], None),
    ("whois", ["-h", SINK, "-p", "43", "example.test"], None),
    ("curl", ["--noproxy", "*", "--max-time", "6", "-s", "-o", "post.out", "-d", "probe=1", f"http://{SINK}/submit"], ["post.out"]),
    ("wget", ["--no-proxy", "--timeout=6", "--tries=1", "-O", "wget3.out", f"http://{SINK}/status"], ["wget3.out"]),
    ("openssl", ["s_client", "-connect", f"{SINK}:443", "-no_ign_eof"], None),
    ("ping", ["-n", "-c", "4", "-w", "6", SINK], None),
    ("curl", ["--noproxy", "*", "--max-time", "6", "-s", "-o", "hdr.out", "-D", "hdr.txt", f"http://{SINK}/headers"], ["hdr.out"]),
    ("telnet", ["-E", SINK, "443"], None),
]


# Candidate static-musl amd64 Sink tasks (validated at the benign-only preflight) to give amd64-static genuine
# enp0s3 network-active benign and break the shortcut in the largest mode. curl/wget/openssl only (HTTP/HTTPS).
AMD64_MUSL_SINK_TASKS = [
    ("curl", ["--noproxy", "*", "--max-time", "6", "--fail", "-s", "-o", "http.out", f"http://{SINK}/"], ["http.out"]),
    ("curl", ["--noproxy", "*", "--max-time", "6", "-sk", "-o", "tls.out", f"https://{SINK}/"], ["tls.out"]),
    ("curl", ["--noproxy", "*", "--max-time", "6", "-s", "-o", "post.out", "-d", "probe=1", f"http://{SINK}/submit"], ["post.out"]),
    ("wget", ["--no-proxy", "--timeout=6", "--tries=1", "-O", "wget.out", f"http://{SINK}/"], ["wget.out"]),
    ("wget", ["--no-proxy", "--timeout=6", "--tries=1", "-O", "wget2.out", f"http://{SINK}/data"], ["wget2.out"]),
    ("openssl", ["s_client", "-connect", f"{SINK}:443", "-servername", "sink.local"], None),
    ("openssl", ["s_client", "-connect", f"{SINK}:443", "-tls1_3"], None),
    ("curl", ["--noproxy", "*", "--max-time", "6", "-s", "-o", "hdr.out", "-D", "hdr.txt", f"http://{SINK}/headers"], ["hdr.out"]),
    ("wget", ["--no-proxy", "--timeout=6", "--tries=1", "-O", "wget3.out", f"http://{SINK}/status"], ["wget3.out"]),
]


def load_redesign():
    data = json.loads((REDESIGN / "payload/workloads.json").read_text())
    cases = data["cases"] if isinstance(data, dict) else data
    out = []
    for c in cases:
        if c.get("workload_status") == "failed":
            continue
        mode = "native_amd64_" + c["mode"]
        program = c["program"]
        network = bool(c.get("network_case")) and program in REDESIGN_SINK_NETWORK
        loopback = program in REDESIGN_LOOPBACK_ONLY
        out.append({"suite": "redesign", "program": program, "project": c["project"], "mode": mode,
                    "network": network, "loopback_only": loopback, "sample": c["sample"],
                    "arguments": c.get("arguments", []), "require_stdout": c.get("require_stdout"),
                    "output_globs": c.get("output_globs", []), "expected_returncodes": c.get("expected_returncodes", [0])})
    return out


def load_holdout():
    m = json.loads((HOLDOUT / "manifest.json").read_text())
    out = []
    for c in m["cases"]:
        if c.get("label") != "benign" or c.get("arch") != "i386":
            continue
        out.append({"suite": "holdout", "program": c["program"], "project": c["project"],
                    "mode": "native_i386_static", "network": False, "loopback_only": False,
                    "sample": c["sample"], "arguments": c.get("arguments", []),
                    "collection_arguments": c.get("collection_arguments", []),
                    "fixture_root": c.get("fixture_root"), "payload_path": c.get("payload_path")})
    return out


def musl_cases(tasks, mode, prefix, binary_dir):
    out = []
    for i, (program, args, outputs) in enumerate(tasks, 1):
        out.append({"suite": "musl", "program": program, "project": program, "mode": mode,
                    "network": True, "loopback_only": False, "task": i,
                    "sample": f"{prefix}-{program}-t{i}.zip", "arguments": args, "output_globs": outputs or [],
                    "binary": str(binary_dir / program), "needs_guest_validation": True})
    return out


def pick(pool, count, prefer_network=0):
    """Deterministic pick of `count` distinct-program cases, including up to prefer_network network cases."""
    pool = [c for c in pool if c["program"] not in EXCLUDE_PROGRAMS]
    net = sorted((c for c in pool if c["network"]), key=lambda c: (c["program"], c["sample"]))
    non = sorted((c for c in pool if not c["network"]), key=lambda c: (c["project"], c["program"], c["sample"]))
    chosen, seen = [], set()
    for c in net:
        if len([x for x in chosen if x["network"]]) >= prefer_network:
            break
        if c["program"] not in seen:
            chosen.append(c); seen.add(c["program"])
    for c in non:
        if len(chosen) >= count:
            break
        if c["program"] not in seen:
            chosen.append(c); seen.add(c["program"])
    return chosen[:count]


def assign_split(cases):
    projects = sorted({c["project"] for c in cases})
    by_project = Counter(c["project"] for c in cases)
    generator = random.Random(SEED)
    generator.shuffle(projects)
    target = round(len(cases) * VALIDATION_FRACTION)
    validation, total = set(), 0
    for project in projects:
        if total >= target:
            break
        if total + by_project[project] <= target + 3 and len(validation) < len(projects) - 1:
            validation.add(project); total += by_project[project]
    for c in cases:
        c["split"] = "validation" if c["project"] in validation else "training"
    return sorted(validation)


def build():
    redesign = load_redesign()
    holdout = load_holdout()
    dyn = pick([c for c in redesign if c["mode"] == "native_amd64_dynamic"], TARGET["native_amd64_dynamic"], prefer_network=2)
    amd64_musl = musl_cases(AMD64_MUSL_SINK_TASKS, "native_amd64_static", "amd64-musl", AMD64_MUSL_BIN)
    static = pick([c for c in redesign if c["mode"] == "native_amd64_static"],
                  TARGET["native_amd64_static"] - len(amd64_musl), prefer_network=0)
    i386_musl = musl_cases(MUSL_SINK_TASKS, "native_i386_static", "i386-musl", MUSL_BIN)[: max(0, TARGET["native_i386_static"] - 8)]
    i386_non = pick(holdout, TARGET["native_i386_static"] - len(i386_musl), prefer_network=0)
    benign = dyn + amd64_musl + static + i386_musl + i386_non
    validation_projects = assign_split(benign)
    for position, c in enumerate(sorted(benign, key=lambda c: (c["mode"], not c["network"], c["project"], c["program"], c.get("task", 0))), 1):
        c["position"] = position
    nulls = [{"label": "null", "mode": mode, "spot": spot} for mode in TARGET for spot in ("start", "middle", "end")]
    return benign, nulls, validation_projects


def summarize(benign):
    net = Counter(c["mode"] for c in benign if c["network"])
    return {"total": len(benign), "by_mode": dict(Counter(c["mode"] for c in benign)),
            "network_by_mode": dict(net), "network_total": sum(net.values()),
            "network_share_pct": round(100 * sum(net.values()) / len(benign)),
            "by_mode_split": {f"{m}/{s}": n for (m, s), n in sorted(Counter((c["mode"], c["split"]) for c in benign).items())},
            "by_suite": dict(Counter(c["suite"] for c in benign)),
            "needs_guest_validation": sum(1 for c in benign if c.get("needs_guest_validation")),
            "distinct_projects": len({c["project"] for c in benign})}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    benign, nulls, validation_projects = build()
    summary = summarize(benign)
    summary["validation_projects"] = validation_projects
    summary["nulls"] = len(nulls)
    if args.write:
        OUT_DIR.mkdir(exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        attempt = OUT_DIR / ("benign-binding-" + stamp)
        attempt.mkdir()
        (attempt / "benign_binding.json").write_text(json.dumps(
            {"format": "v21-benign-binding-v1", "targets": TARGET, "seed": SEED,
             "validation_projects": validation_projects, "cases": benign, "nulls": nulls,
             "summary": summary}, indent=2, sort_keys=True) + "\n")
        summary["written"] = str(attempt / "benign_binding.json")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

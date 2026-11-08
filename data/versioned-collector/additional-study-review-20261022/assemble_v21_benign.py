"""Assemble the ~97 mode-matched benign plan for the .21 quiet collection (step 3, local only).

Mode-matches the frozen malware selection (11 amd64-dynamic / 55 amd64-static / 31 i386-static), with about a
third of the cases network-active against the internal Sink only, and a benign-project-held-out validation split
(whole upstream projects reserved for validation, distinct from training). Programs are drawn from the already
validated workload suites -- matched45, redesign-native-x64, and the i386-held-out amendment -- plus the newly
built static-musl i386 network tools. Network programs get several distinct Sink tasks (each task is a case; all
tasks of one program stay on the same split side; independence is counted by program, not task).

This writes a benign PLAN (program / mode / project / network / task / split / source pointer). The actual
transport packaging and the in-guest validation of the new i386-musl network tasks happen in the collection
driver's benign-only preflight (the first, separately approved VM phase). No VM operation here.
"""

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT_DIR = ROOT / "v21-collection-selection"

# Each program drawn from a validated suite. (program, project, suite). suite in {matched45, redesign, holdout}.
# Network programs are listed separately with their Sink task counts.
DYNAMIC_NONNET = [  # amd64 dynamic, non-network (redesign/matched45 validated)
    ("git", "git", "redesign"), ("jq", "jq", "redesign"), ("tar", "tar", "redesign"),
    ("xz", "xz-utils", "redesign"), ("zstd", "zstd", "redesign"), ("rsync", "rsync", "redesign"),
    ("nice", "coreutils", "matched45"), ("zip", "zip", "redesign")]
DYNAMIC_NET = [  # amd64 dynamic, network (program, project, Sink tasks)
    ("curl", "curl", 1), ("wget", "wget", 1), ("openssl", "openssl", 1)]
STATIC_NET_AMD64 = [  # amd64 static, musl network (redesign compatible-static, guest-validated)
    ("ping", "inetutils", 1), ("ftp", "inetutils", 1), ("traceroute", "inetutils", 1),
    ("telnet", "inetutils", 1), ("whois", "whois", 1)]
STATIC_NONNET_AMD64 = [  # amd64 static non-network, 50 distinct programs/projects (redesign+matched45)
    ("env", "coreutils"), ("printf", "coreutils"), ("timeout", "coreutils"), ("shred", "coreutils"),
    ("sum", "coreutils"), ("tee", "coreutils"), ("sync", "coreutils"), ("test", "coreutils"),
    ("mv", "coreutils"), ("rm", "coreutils"), ("id", "coreutils"), ("who", "coreutils"),
    ("groups", "coreutils"), ("users", "coreutils"), ("dircolors", "coreutils"),
    ("lessecho", "less"), ("lesskey", "less"), ("lemon", "sqlite3-tool"),
    ("b2sum", "coreutils-b2"), ("sha1sum", "coreutils-sha"),
    ("bison", "bison"), ("flex", "flex"), ("m4", "m4"), ("gawk", "gawk"),
    ("diff", "diffutils"), ("cmp", "diffutils"), ("sdiff", "diffutils"),
    ("find", "findutils"), ("xargs", "findutils"), ("locate", "findutils"),
    ("grep", "grep"), ("egrep", "grep"), ("sed", "sed"),
    ("gzip", "gzip"), ("bzip2", "bzip2"), ("xxhsum", "xxhash"), ("lz4", "lz4"),
    ("brotli", "brotli"), ("diffstat", "diffstat"), ("dos2unix", "dos2unix"),
    ("ncompress", "ncompress"), ("byacc", "byacc"), ("indent", "indent"), ("bmake", "bmake"),
    ("expat", "expat"), ("elfedit", "binutils"), ("readelf", "binutils"), ("size", "binutils"),
    ("strings", "binutils"), ("nm", "binutils")]
STATIC_NONNET_I386 = [  # i386 static non-network (matched45 + holdout), distinct projects
    ("echo", "coreutils"), ("printenv", "coreutils"), ("pwd", "coreutils"), ("link", "coreutils"),
    ("unlink", "coreutils"), ("uuidgen", "util-linux"), ("mkfifo", "coreutils"),
    ("blkid", "util-linux-blkid"), ("badblocks", "e2fsprogs"), ("resize2fs", "e2fsprogs"),
    ("dumpe2fs", "e2fsprogs"), ("bc", "bc"), ("dc", "bc"), ("ed", "ed"), ("file", "file"),
    ("make", "make-dfsg"), ("cpio", "cpio"), ("shar", "sharutils"), ("unshar", "sharutils"),
    ("sqlite3", "sqlite3"), ("tput", "ncurses"), ("infocmp", "ncurses"), ("tic", "ncurses"),
    ("xzdec", "xz-utils"), ("lzmadec", "xz-utils"), ("uuencode", "sharutils-uu"),
    ("uudecode", "sharutils-uu")]
NET_I386_MUSL = [  # new static-musl i386 network tools; tasks validated at the benign-only preflight
    ("curl", "curl", 3), ("wget", "wget", 2), ("openssl", "openssl", 2), ("ftp", "inetutils", 2),
    ("ping", "inetutils", 2), ("telnet", "inetutils", 2), ("traceroute", "inetutils", 2),
    ("whois", "whois", 2), ("tftp", "inetutils", 1), ("logger", "inetutils", 1)]

TARGET = {"native_amd64_dynamic": 11, "native_amd64_static": 55, "native_i386_static": 31}
# Whole benign projects reserved for validation (distinct from training); ~27% to match the malware split.
VALIDATION_PROJECTS = {
    "native_amd64_dynamic": set(),  # dynamic malware is training-only, so dynamic benign is training-only too
    "native_amd64_static": {"binutils", "diffutils", "findutils", "gzip", "bzip2", "xxhash", "whois"},
    "native_i386_static": {"ncurses", "sharutils", "sharutils-uu", "bc", "whois", "inetutils"}}


def assemble():
    cases = []

    def add(program, project, mode, network, suite, tasks=1, new=False):
        for task in range(1, tasks + 1):
            cases.append({"program": program, "project": project, "mode": mode, "network": network,
                          "suite": suite, "task": task, "tasks": tasks,
                          "needs_guest_validation": new,
                          "split": "validation" if project in VALIDATION_PROJECTS[mode] else "training"})

    # amd64 dynamic: 3 network + 8 non-network = 11
    for program, project, tasks in DYNAMIC_NET:
        add(program, project, "native_amd64_dynamic", True, "redesign", tasks)
    for program, project, suite in DYNAMIC_NONNET:
        add(program, project, "native_amd64_dynamic", False, suite)
    # amd64 static: 5 musl-network + 50 non-network = 55
    for program, project, tasks in STATIC_NET_AMD64:
        add(program, project, "native_amd64_static", True, "redesign", tasks)
    for program, project in STATIC_NONNET_AMD64:
        add(program, project, "native_amd64_static", False, "redesign")
    # i386 static: musl-network (multi-task) + non-network = 31
    for program, project, tasks in NET_I386_MUSL:
        add(program, project, "native_i386_static", True, "i386-musl", tasks, new=True)
    for program, project in STATIC_NONNET_I386:
        add(program, project, "native_i386_static", False, "holdout")

    # Trim each mode to its target, keeping all network cases and dropping non-network tail deterministically.
    final = []
    for mode in TARGET:
        mode_cases = [c for c in cases if c["mode"] == mode]
        net = [c for c in mode_cases if c["network"]]
        non = [c for c in mode_cases if not c["network"]]
        keep_non = non[: max(0, TARGET[mode] - len(net))]
        final.extend(net + keep_non)
    for position, case in enumerate(sorted(final, key=lambda c: (c["mode"], not c["network"], c["project"], c["program"], c["task"])), 1):
        case["position"] = position
    return final


def nulls():
    # 3 per mode (start / middle / end), 9 total, matching the three native modes.
    out = []
    for mode in TARGET:
        for spot in ("start", "middle", "end"):
            out.append({"label": "null", "mode": mode, "spot": spot})
    return out


def summarize(cases):
    by_mode = Counter(c["mode"] for c in cases)
    net = Counter(c["mode"] for c in cases if c["network"])
    by_split = Counter((c["mode"], c["split"]) for c in cases)
    projects = defaultdict(set)
    for c in cases:
        projects[c["mode"]].add(c["project"])
    val_projects = defaultdict(set)
    for c in cases:
        if c["split"] == "validation":
            val_projects[c["mode"]].add(c["project"])
    return {"total": len(cases),
            "by_mode": dict(by_mode),
            "network_by_mode": dict(net),
            "network_total": sum(net.values()),
            "network_share_pct": round(100 * sum(net.values()) / len(cases)),
            "by_mode_split": {f"{m}/{s}": n for (m, s), n in sorted(by_split.items())},
            "distinct_projects_per_mode": {m: len(p) for m, p in projects.items()},
            "validation_projects": {m: sorted(p) for m, p in val_projects.items()},
            "needs_guest_validation": sum(1 for c in cases if c["needs_guest_validation"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    cases = assemble()
    summary = summarize(cases)
    summary["nulls"] = len(nulls())
    if args.write:
        OUT_DIR.mkdir(exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        attempt = OUT_DIR / ("benign-" + stamp)
        attempt.mkdir()
        manifest = {"format": "v21-benign-plan-v1", "targets": TARGET,
                    "validation_projects": {m: sorted(p) for m, p in VALIDATION_PROJECTS.items()},
                    "cases": cases, "nulls": nulls(), "summary": summary}
        (attempt / "benign_plan.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        summary["written"] = str(attempt / "benign_plan.json")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

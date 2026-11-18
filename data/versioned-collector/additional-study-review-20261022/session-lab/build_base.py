#!/usr/bin/env python3
"""Session-lab base dataset: every session-lab run collected under the main settings, pooled under one acceptance rule
into one dataset (two views) and scored the way the paper scores Table V.

Runs, in collection order:
  main    the dataset's programs (99 malware families' samples, 105 benign tasks); stopped at its 10:00 UTC deadline
  tpilot  Triage pilot: one sample of each of 13 Triage network-active families, 13 benign
  floods  the paper's attack types in the busy-background lab, 8 network-active benign, 3 nulls
  triage  Triage cohort: 54 malware (13 families, near-duplicates capped), 44 benign, controls
  rest    the main plan's unreached sessions, its never-booted sessions, the pilot's nine dataset malware again
All share the session length (180 s), windows (0.5 s), injection range (40-100 s), the 4x background, the guest
baseline and the monitor binaries; their guest scripts differ only in the Python-tool staging the flood batch added
(inert for program sessions). The first pilot (1x background) is left out.

Acceptance, one rule for every run:
  relaxed (primary)  a session's own checks, except that a capacity-only overflow of the host monitor's 64-slot
                     connect-address set (HOSTMON_HEALTH lost=late=failed=0, capacity>0) does not reject a malware or
                     attack session: the rule the flood and Triage batches declared before they ran (the syscall stream
                     is complete; the overflowed counters are not detector features)
  strict             no tolerance (a sensitivity check)
Views:
  sessions  every accepted program session: each run was balanced by design; a program collected in two runs is two
            rows of one group, so the grouped CV never splits them
  unique    one row per program: its first accepted session in collection order; at most 10 per malware family
Scores: grouped 5-fold CV (malware family / attack instance / benign project-or-shape held out) over 10 fold
assignments, threshold 0.5, the paper's four detectors, program rows 20 s and 80 s from the injection; recall per
stratum; detector minus host per assignment; baselines (activity, lifetime, injection time, batch, mode) next to a
random-feature reference; the C2-implant subset (the pre-registered Triage question) against all benign.

  /usr/bin/python3 build_base.py --out base/<name> [--runs main,tpilot,floods,triage,rest] [--spans 20s,80s]
                                 [--skip-scores]
"""
import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import compare_session_lab as CS   # noqa: E402
import flood_score as FS           # noqa: E402
C, lab = CS.C, CS.lab

RUNS = {"main": "20261115T214153675625Z", "tpilot": "20261116T100129450384Z", "floods": "20261116T124104912903Z",
        "triage": "20261116T153432251861Z", "rest": "20261116T223142789936Z"}
ORDER = ["main", "tpilot", "floods", "triage", "rest"]          # collection order
SPANS = {"20s": 40, "80s": 160}
CAP = 10
C2_FAMILIES = {"adaptixc2", "flylegitbot", "gobrat", "ladvix", "moobot", "rekoobe", "sliver", "vshell"}
RELEASE = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection/dataset/features.csv")
META = ["execution_id", "run", "attempt", "sid", "kind", "stratum", "label", "group", "family", "project", "program",
        "name", "mode", "sha256", "archive", "t_inject_s", "in_unique", "accepted_relaxed", "accepted_strict"]


def capacity_only(reason):
    if ": health ['HOSTMON_HEALTH," not in reason:
        return False
    try:
        lost, cap, late, failed = [int(x) for x in reason.split("HOSTMON_HEALTH,", 1)[1].rstrip("']").split(",")]
    except ValueError:
        return False
    return lost == 0 and late == 0 and failed == 0 and cap > 0


def acceptance(sdir, s):
    """(relaxed, strict) acceptance from the session's own records."""
    recheck = sdir / "checks-recheck.json"
    if recheck.is_file():
        ok = bool(lab.load(recheck)["recheck"]["accepted"])
        return ok, ok
    rec = lab.load(sdir / "result.json")
    checks = rec.get("checks") or {}
    if rec.get("status") == "accepted":
        return True, not checks.get("relaxed", False)
    reasons = checks.get("reasons") or []
    relaxed = (rec.get("status") == "rejected" and s["kind"] in ("malware", "attack") and bool(reasons)
               and all(capacity_only(r) for r in reasons))
    return relaxed, False


def identity(s):
    if s["kind"] == "malware":
        return "malware:" + s["sha256"]
    if s.get("archive"):
        return "%s:%s" % (s["kind"], s["archive"])
    return "%s:%s:%s:%s" % (s["kind"], s["name"], s.get("tool", ""), json.dumps(s.get("args", [])))


def group_of(s):
    if s["kind"] == "malware":
        return "family::" + s["family"].lower()
    if s["kind"] == "attack":
        return "flood::" + s["name"]
    if s["kind"] == "benign":
        return "project::" + s.get("project", FS.benign_shape(s["name"]))
    return "%s::%s" % (s["kind"], s["name"])


def stratum_of(s, ds99, rev5):
    k = s["kind"]
    if k == "malware":
        if s["sha256"] in ds99:
            return "malware_dataset99"
        return "malware_dataset_extra" if s["sha256"] in rev5 else "malware_triage"
    if k == "benign":
        return "benign_network" if (not s.get("archive") or s.get("network")) else "benign_cli"
    return k                                                      # attack, null


def load_runs(names):
    out, skipped = [], Counter()
    for run in names:
        att = HERE / "runs" / RUNS[run]
        if not (att / "analysis.json").is_file():
            skipped["%s: no analysis.json" % run] += 1
            continue
        protocol = lab.load(att / "protocol.json")
        reports = {r["sid"]: r for r in lab.load(att / "analysis.json")["sessions"]}
        for s in protocol["sessions"]:
            if s["kind"] not in ("malware", "attack", "benign", "null"):
                continue
            sdir = att / "sessions" / s["sid"]
            if not (sdir / "result.json").is_file():
                continue
            if not (sdir / "windows.json").is_file() or s["sid"] not in reports:
                skipped["%s: not analysed" % run] += 1
                continue
            relaxed, strict = acceptance(sdir, s)
            ran = CS.program_ran(sdir)
            w = lab.load(sdir / "windows.json")
            out.append(dict(s, run=run, attempt=att.name, W=w["features"], program_ran=ran,
                            accepted_relaxed=relaxed, accepted_strict=strict))
    return out, dict(skipped)


def build_views(sessions, rule, ds99, rev5):
    key = "accepted_" + rule
    rows = [s for s in sessions if s[key] and s["program_ran"] is not False]
    for s in rows:
        s["identity"], s["group"], s["stratum"] = identity(s), group_of(s), stratum_of(s, ds99, rev5)
    order = sorted(rows, key=lambda s: (ORDER.index(s["run"]), s["sid"]))
    first, per_family, dropped = {}, Counter(), []
    for s in order:
        if s["identity"] in first:
            continue
        if s["kind"] == "malware":
            fam = s["family"].lower()
            if per_family[fam] >= CAP:
                dropped.append(s["identity"])
                continue
            per_family[fam] += 1
        first[s["identity"]] = s
    unique = [first[k] for k in first]
    for s in rows:
        s["in_unique"] = int(first.get(s["identity"]) is s)
    return order, unique, dropped


def matrices(ps, n):
    rows, host_cols, net_cols = C.load()
    hs, ns = C.signals(host_cols), C.signals(net_cols)
    pi = [int(s["t_inject_s"] // 0.5) for s in ps]
    Xh = C.summarize(CS.window_matrix(ps, "program", "host", pi, n, hs))
    Xn = C.summarize(CS.window_matrix(ps, "program", "net", pi, n, ns))
    return Xh, Xn, pi, host_cols, net_cols


def write_csv(path, ps, Xh, Xn, host_cols, net_cols):
    with path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(META + host_cols + net_cols)
        for s, h, n in zip(ps, Xh, Xn):
            meta = {"execution_id": "%s:%s" % (s["attempt"], s["sid"]), "label": CS.label(s),
                    "family": s.get("family", ""), "project": s.get("project", ""), "program": s.get("program", ""),
                    "sha256": s.get("sha256", ""), "archive": s.get("archive", ""), "mode": CS.mode_of(s),
                    "accepted_relaxed": int(s["accepted_relaxed"]), "accepted_strict": int(s["accepted_strict"])}
            w.writerow([meta.get(k, s.get(k, "")) for k in META] + ["%.10g" % v for v in h] + ["%.10g" % v for v in n])


def stratum_recall(ps, P):
    out = {}
    st = np.asarray([s["stratum"] for s in ps])
    for name in sorted(set(st)):
        idx = np.where(st == name)[0]
        neg = name.startswith("benign") or name == "null"
        out[name] = {"n": int(len(idx)), "measure": "specificity" if neg else "recall",
                     **{d: float(((P[d][:, idx] < 0.5) if neg else (P[d][:, idx] >= 0.5)).mean()) for d in P}}
    return out


def score_view(ps, n, attempts):
    y = np.asarray([CS.label(s) for s in ps])
    g = np.asarray([s["group"] for s in ps])
    Xh, Xn, pi, _, _ = matrices(ps, n)
    sc, P = CS.grouped_cv_P(Xh, Xn, y, g)
    out = {"n": int(len(y)), "malicious": int(y.sum()), "benign": int((y == 0).sum()),
           "groups": {"malicious": len(set(g[y == 1])), "benign": len(set(g[y == 0]))}, "scores": sc}
    if P is None:
        return out
    out["per_stratum"] = stratum_recall(ps, P)
    out["minus_host"] = CS.paired(y, P)
    out["per_group"] = CS.by_group(y, g, P)
    base = CS.program_baselines(ps, pi, n, attempts)
    out["baselines"] = {k: CS.baseline_cv(v, y, g) for k, v in base.items()}
    out["noise_reference"] = CS.noise_reference(y, g)
    c2 = np.asarray([(s["kind"] == "malware" and s["family"].lower() in C2_FAMILIES) or s["kind"] in ("benign", "null")
                     for s in ps])
    yc, gc = y[c2], g[c2]
    sc2, P2 = CS.grouped_cv_P(Xh[c2], Xn[c2], yc, gc)
    sub = [s for s, keep in zip(ps, c2) if keep]
    c2_out = {"n_implant": int(yc.sum()), "n_benign": int((yc == 0).sum()),
              "families": sorted({s["family"].lower() for s in sub if s["kind"] == "malware"}), "scores": sc2}
    if P2 is not None:
        c2_out["minus_host"] = CS.paired(yc, P2)
        life = CS.program_baselines(sub, [p for p, k in zip(pi, c2) if k], n, attempts)["lifetime"]
        c2_out["lifetime_baseline"] = CS.baseline_cv(life, yc, gc)
        c2_out["noise_reference"] = CS.noise_reference(yc, gc)
        c2_out["per_family_recall"] = {grp: v for grp, v in CS.by_group(yc, gc, P2).items() if v["label"] == 1}
    out["c2_subset"] = c2_out
    return out


def composition(ps):
    return {"by_stratum": dict(Counter(s["stratum"] for s in ps)), "by_run": dict(Counter(s["run"] for s in ps)),
            "malware_families": len({s["family"].lower() for s in ps if s["kind"] == "malware"}),
            "benign_groups": len({s["group"] for s in ps if s["kind"] == "benign"}),
            "by_mode_label": dict(Counter("%s:%s" % (CS.mode_of(s), CS.label(s)) for s in ps))}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", required=True)
    p.add_argument("--runs", default=",".join(ORDER))
    p.add_argument("--spans", default="20s,80s")
    p.add_argument("--rules", default="relaxed,strict")
    p.add_argument("--skip-scores", action="store_true")
    a = p.parse_args()
    out_dir = Path(a.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    names = [r for r in a.runs.split(",") if r]
    sessions, skipped = load_runs(names)
    release = list(csv.DictReader(RELEASE.open()))
    ds99 = {r["sha256"] for r in release if r["category"] == "malware"}
    rev5 = {c["member_sha256"] for c in lab.load(Path(lab.REV5).parent / "cases.json") if c["label"] == "malware"}
    attempts = [RUNS[r] for r in ORDER]
    result = {"runs": {r: RUNS[r] for r in names}, "loaded_program_sessions": len(sessions), "skipped": skipped,
              "inputs": {"release_features_sha256": hashlib.sha256(RELEASE.read_bytes()).hexdigest(),
                         "builder_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
              "rules": {}}
    lines = []
    for rule in a.rules.split(","):
        allrows, unique, dropped = build_views(sessions, rule, ds99, rev5)
        views = {"sessions": allrows, "unique": unique}
        res = {"cap_dropped": dropped, "views": {}}
        for vname, ps in views.items():
            vres = {"composition": composition(ps)}
            lines.append("[%s/%s] %s" % (rule, vname, json.dumps(vres["composition"]["by_stratum"], sort_keys=True)))
            for span in a.spans.split(","):
                n = SPANS[span]
                Xh, Xn, _, host_cols, net_cols = matrices(ps, n)
                fname = "base_%s_%s_%s.csv" % (rule, vname, span)
                write_csv(out_dir / fname, ps, Xh, Xn, host_cols, net_cols)
                vres.setdefault("files", {})[span] = {"csv": fname,
                                                     "sha256": hashlib.sha256((out_dir / fname).read_bytes()).hexdigest()}
                if a.skip_scores or (rule == "strict" and vname == "unique" and span != "20s"):
                    continue
                s = score_view(ps, n, attempts)
                vres[span] = s
                sc = s["scores"]
                if "skipped" in sc:
                    lines.append("  %s: %s" % (span, sc["skipped"]))
                    continue
                lines.append("  %s n=%d (%d mal / %d ben; %d / %d groups)" % (
                    span, s["n"], s["malicious"], s["benign"], s["groups"]["malicious"], s["groups"]["benign"]))
                for d in C.DETECTORS:
                    lines.append("    %-8s BA %.3f+/-%.3f AUC %.3f rec %.3f spec %.3f" % (
                        d, sc[d]["ba_mean"], sc[d]["ba_sd"], sc[d]["auc_mean"], sc[d]["recall_mean"],
                        sc[d]["specificity_mean"]))
                bl = s["baselines"]
                lines.append("    baselines BA: " + ", ".join("%s %.3f" % (k, v["ba_mean"]) for k, v in bl.items()
                                                            if "ba_mean" in v)
                             + " | noise p95 %.3f" % s["noise_reference"].get("p95", float("nan")))
                lines.append("    per stratum: " + "; ".join("%s(%d %s) h%.2f n%.2f c%.2f s%.2f" % (
                    k, v["n"], v["measure"][:4], v["host"], v["network"], v["concat"], v["stacked"])
                    for k, v in s["per_stratum"].items()))
                c2 = s["c2_subset"]
                if "skipped" not in c2["scores"]:
                    lines.append("    C2 subset (%d implants / %d benign): " % (c2["n_implant"], c2["n_benign"])
                                 + ", ".join("%s %.3f" % (d, c2["scores"][d]["ba_mean"]) for d in C.DETECTORS)
                                 + " | lifetime %.3f | noise p95 %.3f" % (
                                     c2["lifetime_baseline"].get("ba_mean", float("nan")),
                                     c2["noise_reference"].get("p95", float("nan"))))
            res["views"][vname] = vres
        result["rules"][rule] = res
    with (out_dir / "manifest.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["run", "attempt", "sid", "kind", "name", "family", "project", "identity", "group", "stratum",
                    "accepted_relaxed", "accepted_strict", "program_ran"])
        for s in sorted(sessions, key=lambda s: (ORDER.index(s["run"]), s["sid"])):
            w.writerow([s["run"], s["attempt"], s["sid"], s["kind"], s["name"], s.get("family", ""),
                        s.get("project", ""), identity(s), group_of(s),
                        stratum_of(s, ds99, rev5), int(s["accepted_relaxed"]), int(s["accepted_strict"]),
                        s["program_ran"]])
    (out_dir / "base.json").write_text(json.dumps(result, indent=1, default=str))
    (out_dir / "base.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()

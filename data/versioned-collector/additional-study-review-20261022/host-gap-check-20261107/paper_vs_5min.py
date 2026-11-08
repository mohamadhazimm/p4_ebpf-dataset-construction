"""Deep comparison: the paper's 20 s dataset vs the 5-min observation-length cohort, on one footing.

  paper     revision5 classifier cases used in Table IV / the 204 general-malware rows of Table V
            (99 malware / 105 benign, 20 s = 40 windows, one interleaved campaign, pre-registered split)
  five_V1   the 5-min cohort (102 malware) with its working benign (92; top/lowrate removed), 600 windows
  five_est  five_V1 + the 43 planned short tasks SIMULATED (20 s capture + zeros), always-busy programs capped at 10
            (= S43cap of estimate_with_paper_short.py; replaced by real runs when the collection finishes)

S1 composition and design          S2 shortcut baselines (lifetime, activity, exit code, mode, collection batch)
S3 detectors (host/network/hybrid; all features and timing-free 'shape')   S4 the 98 malware run in BOTH datasets:
how reproducibly the collector measured the same program twice   S5 what the 20 s window misses (5-min malware)
S6 first check of the simulation against short tasks that have already finished in the real run.
Protocol everywhere: StratifiedGroupKFold(5) with whole malware families / benign projects held out, RF300 balanced,
threshold 0.5, 10 fold seeds (42, 0-8). Host = ADFA 18 signals, network = P4 29 signals, 5 statistics each.
Offline; no VM; no merge; no promotion.   Run: nice -n 19 /usr/bin/python3 paper_vs_5min.py
"""
import csv
import glob
import json
import sys
from collections import Counter, defaultdict
from multiprocessing import Pool

import numpy as np
from scipy.stats import spearmanr
from sklearn.model_selection import StratifiedGroupKFold

HERE = __file__.rsplit("/", 1)[0]
sys.path.insert(0, HERE)
sys.path.insert(0, HERE.rsplit("/", 1)[0])
import compare_host as ch                  # noqa: E402
import timing_control as tc                # noqa: E402
import rescore_with_bursty as rb           # noqa: E402
import estimate_with_paper_short as est    # noqa: E402
import build_benign_bursty_payload as bbp  # noqa: E402

R5 = ch.PROJ + "/revision5-collection/20261025T100025568989Z"
OUT = ch.PROJ + "/host-gap-check-20261107/paper_vs_5min.json"


# ------------------------------------------------------------------------------------------------ cohorts
def load_paper(host, net):
    rows = list(csv.DictReader(open(ch.REL + "/dataset/features.csv")))
    mal_sha = {r["execution_id"] for r in rows if r["category"] == "malware"}
    cases = {c["sample"]: c for c in json.load(open(R5 + "/payload/cases.json"))}
    out = []
    for rj in sorted(glob.glob(R5 + "/runs/*/output/run_*/run.json")):
        sample = rj.split("/runs/")[1].split("/")[0]
        c = cases.get(sample)
        if not c or c["label"] not in ("malware", "benign"):
            continue
        if c["label"] == "malware" and sample[:-4] not in mal_sha:
            continue                                          # the 6 excluded malware are not in the dataset
        d = json.load(open(rj))
        if d.get("collection_quality_status") != "accepted":
            continue
        tel = list(csv.DictReader(open(rj.rsplit("/", 1)[0] + "/telemetry.csv")))
        mal = c["label"] == "malware"
        out.append({"sample": sample, "sha": sample[:-4] if mal else None, "y": int(mal), "mode": c["mode"],
                    "group": ("fam:" + c["family"]) if mal else ("proj:" + c["project"]), "rc": d.get("return_code"),
                    "batch": "revision5", "H": np.array([[float(t[s]) for s in host] for t in tel]),
                    "N": np.array([[float(t[s]) for s in net] for t in tel])})
    return out


def load_five(host, net):
    old, _, _, _ = rb.load_all(host, net)
    old = [c for c in old if not c["src"].startswith("new-") and not c["broken"]]
    modes = {}
    for _, rel, _ in ch.ATT:
        for c in json.load(open(ch.PROJ + "/" + rel + "/protocol.json"))["cases"]:
            modes[c["sample"]] = c["mode"]
    for c in old:
        c.update(mode=modes[c["sample"]], group=c["group_proj"], batch=c["src"],
                 sha=c["sample"][:-4] if c["y"] == 1 else None)
    sim, _ = est.load_paper_benign(host, net)
    planned = {c["sample"] for c in bbp.select_short()}
    r5 = {c["sample"]: c for c in json.load(open(R5 + "/payload/cases.json"))}
    sim = [dict(c, mode=r5[c["sample"]]["mode"], group=c["group_proj"], batch="sim-short", sha=None)
           for c in sim if c["sample"] in planned]
    return old, est.cap_dense(old + sim)


# ------------------------------------------------------------------------------------------------ helpers
def last_active(M, col):
    nz = np.nonzero(M[:, col])[0]
    return int(nz.max()) if len(nz) else -1


def activity_mix(cs, gate):
    out = {}
    for lab, yv in (("malware", 1), ("benign", 0)):
        sub = [c for c in cs if c["y"] == yv]
        k = sub[0]["H"].shape[0]
        lasts = np.array([last_active(c["H"], gate) for c in sub])
        frac = np.array([(c["H"][:, gate] != 0).mean() for c in sub])
        first = lasts <= 1
        out[lab] = {"n": len(sub), "windows": k, "first_second_only": float(first.mean()),
                    "sparse": float(((~first) & (frac <= 0.1)).mean()), "busy": float(((~first) & (frac > 0.1)).mean())}
    return out


def onehot(values):
    keys = sorted({str(v) for v in values})
    return np.array([[float(str(v) == k) for k in keys] for v in values])


# ------------------------------------------------------------------------------------------------ main
def main():
    host, net = tc.signals()
    hg, ng = host.index("host_total_syscalls_total"), net.index("net_pkts_total_delta")
    paper = load_paper(host, net)
    five_v1, five_est = load_five(host, net)
    res = {}

    # ---------- S1 composition and design
    s1 = {}
    for name, cs, k in (("paper", paper, 40), ("five_V1", five_v1, 600), ("five_est", five_est, 600)):
        cut = [dict(c, H=c["H"][:k], N=c["N"][:k]) for c in cs]
        y = np.array([c["y"] for c in cs])
        net_active = lambda lab: float(np.mean([(c["N"][:k, ng] != 0).any() for c in cs if c["y"] == lab]))
        rc_top = lambda lab: Counter(str(c["rc"]) for c in cs if c["y"] == lab).most_common(4)
        s1[name] = {"malware": int(y.sum()), "benign": int((y == 0).sum()),
                    "malware_groups": len({c["group"] for c in cs if c["y"] == 1}),
                    "benign_groups": len({c["group"] for c in cs if c["y"] == 0}),
                    "network_active_share": {"malware": net_active(1), "benign": net_active(0)},
                    "modes": {lab: dict(Counter(c["mode"] for c in cs if c["y"] == yv)) for lab, yv in (("malware", 1), ("benign", 0))},
                    "exit_codes_top4": {"malware": rc_top(1), "benign": rc_top(0)},
                    "batches": {lab: dict(Counter(c["batch"] for c in cs if c["y"] == yv)) for lab, yv in (("malware", 1), ("benign", 0))},
                    "activity_mix": activity_mix(cut, hg)}
    res["S1"] = s1

    # ---------- S2 shortcut baselines + S3 detectors (same protocol)
    life, tot = hg * 5 + 4, hg * 5 + 2
    sets = {}
    for name, cs, lengths in (("paper", paper, (40,)), ("five_V1", five_v1, (40, 600)), ("five_est", five_est, (40, 600))):
        y = np.array([c["y"] for c in cs]); g = np.array([c["group"] for c in cs])
        for k in lengths:
            lab = "20s" if k == 40 else "5min"
            Hf = np.array([ch.summ(c["H"], k) for c in cs]); Nf = np.array([ch.summ(c["N"], k) for c in cs])
            Hs = np.array([tc.shape(c["H"], k, hg) for c in cs]); Ns = np.array([tc.shape(c["N"], k, ng) for c in cs])
            pre = "%s|%s" % (name, lab)
            sets[pre + "|baseline|lifetime"] = (Hf[:, [life]], y, g)
            sets[pre + "|baseline|activity"] = (Hf[:, [tot]], y, g)
            sets[pre + "|baseline|exit_code"] = (onehot([c["rc"] for c in cs]), y, g)
            sets[pre + "|baseline|mode"] = (onehot([c["mode"] for c in cs]), y, g)
            if name != "paper":
                sets[pre + "|baseline|batch"] = (onehot([c["batch"] for c in cs]), y, g)
            for view, (Hx, Nx) in (("full", (Hf, Nf)), ("shape", (Hs, Ns))):
                sets[pre + "|%s|host" % view] = (Hx, y, g)
                sets[pre + "|%s|network" % view] = (Nx, y, g)
                sets[pre + "|%s|hybrid" % view] = (np.hstack([Hx, Nx]), y, g)
    jobs = [(n, X, y, g, s, 300) for n, (X, y, g) in sets.items() for s in ch.SEEDS]
    with Pool(8) as pool:
        out = pool.map(ch.job_cv, jobs)
    per = defaultdict(list)
    for n, seed, sc, _ in out:
        per[n].append(sc)
    res["S2_S3"] = {n: {"ba": ch.summary([s["ba"] for s in per[n]]), "auc": ch.summary([s["auc"] for s in per[n]])}
                    for n in sets}

    # ---------- S4 the same malware measured twice (paper 20 s run vs the 5-min run's first 20 s)
    p_by = {c["sha"]: c for c in paper if c["y"] == 1}
    f_by = {c["sha"]: c for c in five_v1 if c["y"] == 1}
    shared = sorted(set(p_by) & set(f_by))
    P = np.array([np.r_[ch.summ(p_by[s]["H"], 40), ch.summ(p_by[s]["N"], 40)] for s in shared])
    F = np.array([np.r_[ch.summ(f_by[s]["H"], 40), ch.summ(f_by[s]["N"], 40)] for s in shared])
    rho = []
    for j in range(P.shape[1]):
        if np.ptp(P[:, j]) > 0 and np.ptp(F[:, j]) > 0:
            rho.append((j, spearmanr(P[:, j], F[:, j])[0]))
    hr = np.array([r for j, r in rho if j < 90]); nr = np.array([r for j, r in rho if j >= 90])
    tp = np.array([p_by[s]["H"][:, hg].sum() for s in shared]); tf = np.array([f_by[s]["H"][:40, hg].sum() for s in shared])
    netp = np.array([(p_by[s]["N"][:, ng] != 0).any() for s in shared]); netf = np.array([(f_by[s]["N"][:40, ng] != 0).any() for s in shared])
    po, fo = (netp.mean() * netf.mean() + (1 - netp.mean()) * (1 - netf.mean())), (netp == netf).mean()
    kappa = (fo - po) / (1 - po) if po < 1 else 1.0
    # detector agreement: grouped CV on the paper data; each fold model scores the held-out paper runs AND the
    # 5-min runs of the same samples
    y = np.array([c["y"] for c in paper]); g = np.array([c["group"] for c in paper])
    Xp = {"host": np.array([ch.summ(c["H"], 40) for c in paper]), "network": np.array([ch.summ(c["N"], 40) for c in paper])}
    Xp["hybrid"] = np.hstack([Xp["host"], Xp["network"]])
    Xf = {"host": np.array([ch.summ(f_by[s]["H"], 40) for s in shared]), "network": np.array([ch.summ(f_by[s]["N"], 40) for s in shared])}
    Xf["hybrid"] = np.hstack([Xf["host"], Xf["network"]])
    idx_of = {c["sha"]: i for i, c in enumerate(paper) if c["y"] == 1}
    agree = {}
    for det in ("host", "network", "hybrid"):
        pp, pf = np.full(len(shared), np.nan), np.full(len(shared), np.nan)
        for tr, te in StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42).split(Xp[det], y, g):
            m = ch.rf(300).fit(Xp[det][tr], y[tr])
            te = set(te.tolist())
            for i, s in enumerate(shared):
                if idx_of[s] in te:
                    pp[i] = m.predict_proba(Xp[det][[idx_of[s]]])[0, 1]
                    pf[i] = m.predict_proba(Xf[det][[i]])[0, 1]
        agree[det] = {"spearman": float(spearmanr(pp, pf)[0]), "decision_agreement": float(((pp >= .5) == (pf >= .5)).mean()),
                      "recall_paper_runs": float((pp >= .5).mean()), "recall_5min_runs_first20s": float((pf >= .5).mean()),
                      "median_abs_prob_diff": float(np.median(np.abs(pp - pf)))}
    res["S4"] = {"shared_malware": len(shared),
                 "feature_spearman": {"host_median": float(np.median(hr)), "host_share_ge_0.8": float((hr >= .8).mean()),
                                      "network_median": float(np.median(nr)), "network_share_ge_0.8": float((nr >= .8).mean()),
                                      "n_host": len(hr), "n_network": len(nr)},
                 "syscalls_first20s": {"spearman": float(spearmanr(tp, tf)[0]),
                                       "share_within_2x": float(np.mean((np.maximum(tp, tf) + 1) / (np.minimum(tp, tf) + 1) <= 2))},
                 "network_presence_first20s": {"paper": float(netp.mean()), "five": float(netf.mean()),
                                               "agreement": float(fo), "kappa": float(kappa)},
                 "detector_agreement": agree}

    # ---------- S5 what the 20 s window misses (5-min malware)
    mal = [c for c in five_v1 if c["y"] == 1]
    host_after = np.array([c["H"][40:, hg].sum() / c["H"][:, hg].sum() if c["H"][:, hg].sum() else 0 for c in mal])
    pk = [c["N"][:, ng] for c in mal]
    net_any = np.array([p.sum() > 0 for p in pk])
    net_after = np.array([p[40:].sum() / p.sum() for p in pk if p.sum() > 0])
    net_only_late = np.array([p[:40].sum() == 0 and p[40:].sum() > 0 for p in pk])
    host_late = np.array([(c["H"][40:, hg] != 0).any() for c in mal])
    by_fam = defaultdict(list)
    for c, p in zip(mal, pk):
        by_fam[c["group"][4:]].append(bool(p[40:].sum() > 0))
    res["S5"] = {"malware": len(mal), "host_activity_after_20s_median_share": float(np.median(host_after)),
                 "any_host_activity_after_20s": float(host_late.mean()), "network_active_in_5min": float(net_any.mean()),
                 "network_after_20s_median_share_of_active": float(np.median(net_after)) if len(net_after) else 0.0,
                 "network_seen_only_after_20s": float(net_only_late.mean()),
                 "families_with_network_after_20s": {f: "%d/%d" % (sum(v), len(v)) for f, v in sorted(by_fam.items()) if any(v)}}

    # ---------- S6 first check of the simulation against short tasks already finished in the real run
    sim_by = {c["sample"]: c for c in five_est if c["batch"] == "sim-short"}
    meta = {c["sample"]: c for c in json.load(open(rb.NEW + "/protocol.json"))["cases"]}
    checks = []
    for rj in sorted(glob.glob(rb.NEW + "/runs/*/output/run_*/run.json")):
        s = rj.split("/runs/")[1].split("/")[0]
        if meta.get(s, {}).get("kind") != "short" or s not in sim_by:
            continue
        r = rb.read_run(rj, host, net)
        if r is None:
            continue
        _, H, N = r
        sim = sim_by[s]
        a = np.r_[ch.summ(H, 600), ch.summ(N, 600)]; b = np.r_[ch.summ(sim["H"], 600), ch.summ(sim["N"], 600)]
        checks.append({"sample": s, "activity_after_20s": bool(H[40:, hg].any() or N[40:, ng].any()),
                       "last_active_real": last_active(H, hg), "last_active_sim": last_active(sim["H"], hg),
                       "syscalls_real": float(H[:, hg].sum()), "syscalls_sim": float(sim["H"][:, hg].sum()),
                       "feature_spearman": float(spearmanr(a, b)[0])})
    res["S6"] = checks
    json.dump(res, open(OUT, "w"), indent=2, default=float)
    print(json.dumps({k: res[k] for k in ("S1", "S4", "S5", "S6")}, indent=1, default=float)[:20000])
    print("\nsaved", OUT)


if __name__ == "__main__":
    main()

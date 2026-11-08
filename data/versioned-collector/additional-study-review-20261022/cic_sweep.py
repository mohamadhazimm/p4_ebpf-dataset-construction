"""Full CIC-DDoS2019 (03-11) network-feature sweep over all 7 DDoS attack types (offline; streams the zip, no VM).

For each attack CSV: stream rows (never load the GB file whole), reservoir-subsample BENIGN vs attack to CAP/class,
select the thesis payload-free FLOW features by stripped CIC column name (NO IPs/ports/timestamp/Flow ID), clean
inf/NaN, balance to the min class, and fit RF200/seed42 with a 70-30 stratified split. Reports test accuracy /
balanced accuracy / top features per attack type. This is the network-strong backbone: it shows the P4/network flow
features detect each DDoS type. In-distribution (same-capture benign), network-only -> cannot be merged with the VM
host+network cohort; it is the thesis's network-half evidence across attack TYPES.
"""
import csv, io, json, sys, zipfile, random, math
from pathlib import Path

ZIP = Path("/home/ali/Desktop/Hazim/CSV-03-11.zip")
OUT = Path(__file__).resolve().parent / "cic-ddos-sweep"
CAP = 8000
SEED = 42
# thesis flow-feature set (stripped CIC names); payload-free flow statistics only
FEATURES = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Mean", "Bwd IAT Mean", "Down/Up Ratio", "Average Packet Size",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "URG Flag Count",
]


def clean(v):
    try:
        x = float(v)
    except Exception:
        return 0.0
    if math.isinf(x) or math.isnan(x):
        return 0.0
    return x


def sweep_one(z, name):
    random.seed(SEED)
    with z.open(name) as f:
        tf = io.TextIOWrapper(f, encoding="utf-8", errors="replace")
        rd = csv.reader(tf)
        hdr = [h.strip() for h in next(rd)]
        idx = {h: i for i, h in enumerate(hdr)}
        lab_i = idx.get("Label")
        feat_i = [(fn, idx[fn]) for fn in FEATURES if fn in idx]
        ben, atk = [], []     # reservoir per class
        nben = natk = 0
        for row in rd:
            if lab_i is None or lab_i >= len(row):
                continue
            lab = row[lab_i].strip().upper()
            vec = [clean(row[i]) for _, i in feat_i]
            if lab == "BENIGN":
                nben += 1
                if len(ben) < CAP:
                    ben.append(vec)
                elif random.random() < CAP / nben:
                    ben[random.randrange(CAP)] = vec
            else:
                natk += 1
                if len(atk) < CAP:
                    atk.append(vec)
                elif random.random() < CAP / natk:
                    atk[random.randrange(CAP)] = vec
    return [fn for fn, _ in feat_i], ben, atk, nben, natk


def evaluate(feat_names, ben, atk):
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import balanced_accuracy_score, accuracy_score
    k = min(len(ben), len(atk))
    if k < 50:
        return {"error": "too few samples", "benign": len(ben), "attack": len(atk)}
    rng = random.Random(SEED)
    b = rng.sample(ben, k); a = rng.sample(atk, k)
    X = np.array(b + a, float); y = np.array([0] * k + [1] * k)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=SEED, stratify=y)
    clf = RandomForestClassifier(n_estimators=200, random_state=SEED, n_jobs=1).fit(Xtr, ytr)
    pred = clf.predict(Xte)
    imp = sorted(zip(clf.feature_importances_, feat_names), reverse=True)[:5]
    return {"balanced_per_class": k, "test_acc": round(accuracy_score(yte, pred), 4),
            "balanced_acc": round(balanced_accuracy_score(yte, pred), 4),
            "top_features": [(round(float(i), 3), n) for i, n in imp]}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    z = zipfile.ZipFile(ZIP)
    csvs = sorted(n for n in z.namelist() if n.lower().endswith(".csv"))
    results = {}
    for name in csvs:
        attack = Path(name).stem
        print("=== %s ===" % attack, flush=True)
        feat_names, ben, atk, nben, natk = sweep_one(z, name)
        print("   streamed: benign=%d attack=%d; subsample benign=%d attack=%d" % (nben, natk, len(ben), len(atk)), flush=True)
        res = evaluate(feat_names, ben, atk)
        res.update({"streamed_benign": nben, "streamed_attack": natk, "n_features": len(feat_names)})
        results[attack] = res
        print("   ->", {k: res[k] for k in ("test_acc", "balanced_acc", "balanced_per_class") if k in res}, flush=True)
    out = OUT / "cic_sweep_results.json"
    out.write_text(json.dumps({"features": FEATURES, "cap_per_class": CAP, "seed": SEED, "results": results}, indent=2))
    print("\n==== SUMMARY (test_acc / balanced_acc) ====")
    for a, r in results.items():
        print("  %-10s acc=%s ba=%s  (benign %d / attack %d streamed)" %
              (a, r.get("test_acc"), r.get("balanced_acc"), r.get("streamed_benign", 0), r.get("streamed_attack", 0)))
    print("wrote", out)


if __name__ == "__main__":
    main()

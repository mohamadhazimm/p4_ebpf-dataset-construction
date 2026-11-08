"""Re-run the CIC-DDoS2019 (03-11) sweep with the exact sampling of cic_sweep.py, evaluating several feature subsets
from ONE streaming pass (the reservoir selection does not depend on feature values). Writes to the scratchpad only."""
import csv, io, json, math, random, sys, zipfile
from pathlib import Path
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import balanced_accuracy_score
from sklearn.model_selection import train_test_split

ZIP = Path("/home/ali/Desktop/Hazim/CSV-03-11.zip"); CAP = 8000; SEED = 42
ALL29 = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets",
         "Total Length of Bwd Packets", "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
         "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Min Packet Length",
         "Max Packet Length", "Packet Length Mean", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Max",
         "Flow IAT Min", "Fwd IAT Mean", "Bwd IAT Mean", "Down/Up Ratio", "Average Packet Size", "FIN Flag Count",
         "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count"]
BASE13 = ["Total Fwd Packets", "Total Backward Packets", "Total Length of Fwd Packets", "Total Length of Bwd Packets",
          "Fwd Packet Length Mean", "Bwd Packet Length Mean", "Flow Duration", "Flow Bytes/s", "Flow Packets/s",
          "SYN Flag Count", "ACK Flag Count", "RST Flag Count"]
VARIANTS = {"all29": ALL29, "13_pktlenmean": BASE13 + ["Packet Length Mean"],
            "13_avgpktsize": BASE13 + ["Average Packet Size"]}


def clean(v):
    try:
        x = float(v)
    except Exception:
        return 0.0
    return 0.0 if math.isinf(x) or math.isnan(x) else x


def sweep_one(z, name):
    random.seed(SEED)
    with z.open(name) as f:
        rd = csv.reader(io.TextIOWrapper(f, encoding="utf-8", errors="replace"))
        hdr = [h.strip() for h in next(rd)]; idx = {h: i for i, h in enumerate(hdr)}
        lab_i = idx.get("Label"); feat_i = [(fn, idx[fn]) for fn in ALL29 if fn in idx]
        ben, atk = [], []; nben = natk = 0
        for row in rd:
            if lab_i is None or lab_i >= len(row):
                continue
            lab = row[lab_i].strip().upper(); vec = [clean(row[i]) for _, i in feat_i]
            if lab == "BENIGN":
                nben += 1
                if len(ben) < CAP: ben.append(vec)
                elif random.random() < CAP / nben: ben[random.randrange(CAP)] = vec
            else:
                natk += 1
                if len(atk) < CAP: atk.append(vec)
                elif random.random() < CAP / natk: atk[random.randrange(CAP)] = vec
    return [fn for fn, _ in feat_i], ben, atk, nben, natk


def evaluate(names, ben, atk, subset):
    k = min(len(ben), len(atk)); rng = random.Random(SEED)
    b = rng.sample(ben, k); a = rng.sample(atk, k)
    cols = [names.index(s) for s in subset]
    X = np.array(b + a, float)[:, cols]; y = np.array([0] * k + [1] * k)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=SEED, stratify=y)
    clf = RandomForestClassifier(n_estimators=200, random_state=SEED, n_jobs=1).fit(Xtr, ytr)
    return {"k": k, "ba": round(balanced_accuracy_score(yte, clf.predict(Xte)), 4),
            "ba6": round(balanced_accuracy_score(yte, clf.predict(Xte)), 6), "n_features": len(cols)}


z = zipfile.ZipFile(ZIP); out = {}
for name in sorted(n for n in z.namelist() if n.lower().endswith(".csv")):
    att = Path(name).stem; names, ben, atk, nb, na = sweep_one(z, name)
    missing = {v: [s for s in sub if s not in names] for v, sub in VARIANTS.items()}
    out[att] = {v: evaluate(names, ben, atk, sub) for v, sub in VARIANTS.items()}
    out[att]["streamed"] = [nb, na]; out[att]["missing"] = missing
    print(att, json.dumps(out[att]), flush=True)
json.dump(out, open(sys.argv[1], "w"), indent=1)
for v in VARIANTS:
    print(v, "total per class", sum(out[a][v]["k"] for a in out), "min BA", min((out[a][v]["ba6"], a) for a in out))

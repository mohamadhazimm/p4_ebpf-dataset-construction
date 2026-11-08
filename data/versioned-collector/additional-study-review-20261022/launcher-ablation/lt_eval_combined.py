import sys, numpy as np
from multiprocessing import Pool
REL="/home/ali/Desktop/Hazim/p4-ebpf-malware-detection"
S="/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/additional-study-review-20261022/launcher-ablation"
sys.path.insert(0, REL+"/evaluation")
import common, combined
from common import load, labels, matrix

def run_combined(path):
    rows,host,network=load(path); y=labels(rows)
    groups=np.asarray([r["cv_group"] for r in rows])
    jobs=[(seed, matrix(rows,host), matrix(rows,network), y, groups) for seed in combined.FOLD_SEEDS]
    with Pool(10) as p: res=p.map(combined.run, jobs)
    out={}
    for name in ("host-only","network-only","hybrid"):
        out[name]={c: (np.mean([r[name][c] for r in res]), np.std([r[name][c] for r in res],ddof=1))
                   for c in ("balanced_accuracy","recall","specificity","precision","f1")}
    return out

with open(S+"/combined_results.txt","w") as f:
    for tag,path in [("ORIGINAL (control)",S+"/features_original.csv"),("LAUNCHER-FREE",S+"/features_launcherfree.csv")]:
        o=run_combined(path)
        f.write("="*64+"\n"+tag+"\n")
        f.write("  combined     BA              recall          spec            prec            F1\n")
        for n in ("host-only","network-only","hybrid"):
            c=o[n]; f.write("  %-11s "%n + "  ".join("%.3f+-%.3f"%(c[k][0],c[k][1]) for k in ("balanced_accuracy","recall","specificity","precision","f1"))+"\n")
        f.flush()
    f.write("DONE\n")
print("combined eval launched")

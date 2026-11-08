import sys, numpy as np
REL="/home/ali/Desktop/Hazim/p4-ebpf-malware-detection"
S="/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/additional-study-review-20261022/launcher-ablation"
sys.path.insert(0, REL+"/evaluation")
import common, heldout
from common import load, labels, matrix, metrics, random_forest

def heldout_tbl(path):
    rows,host,network=load(path)
    rows=[r for r in rows if r["category"] in ("malware","benign")]
    tr=[r for r in rows if r["split"]=="train"]; te=[r for r in rows if r["split"]=="test"]
    ytr,yte=labels(tr),labels(te)
    feats={"network":(matrix(tr,network),matrix(te,network)),
           "host":(matrix(tr,host),matrix(te,host)),
           "hybrid":(matrix(tr,host+network),matrix(te,host+network))}
    out={}
    for n,(Xtr,Xte) in feats.items():
        out[n]=metrics(yte, random_forest().fit(Xtr,ytr).predict_proba(Xte)[:,1])
    # grouped 5-fold CV on train
    groups=np.asarray([r["cv_group"] for r in tr])
    cv={n:heldout.grouped_cv_ba(matrix(tr,cols),ytr,groups)
        for n,cols in [("network",network),("host",host),("hybrid",host+network)]}
    # baselines (host-independent, identical across CSVs)
    bi_tr,bi_te=heldout.baseline_inputs(tr),heldout.baseline_inputs(te)
    base={n:metrics(yte,heldout.fit_baseline(n,bi_tr[n],bi_te[n],ytr))["balanced_accuracy"]
          for n in ("metadata","activity","mode")}
    return out,cv,base

for tag,path in [("ORIGINAL (control)",S+"/features_original.csv"),("LAUNCHER-FREE",S+"/features_launcherfree.csv")]:
    o,cv,base=heldout_tbl(path)
    print("="*64); print(tag)
    print("  held-out    BA     AUC   recall  prec   TN/FP/FN/TP")
    for n in ("network","host","hybrid"):
        m=o[n]; print("  %-9s %.3f  %.3f  %.3f  %.3f  %d/%d/%d/%d"%(n,m["balanced_accuracy"],m["auc"],m["recall"],m["precision"],m["tn"],m["fp"],m["fn"],m["tp"]))
    print("  grouped-CV BA:  network %.3f  host %.3f  hybrid %.3f"%(cv["network"],cv["host"],cv["hybrid"]))
    print("  baselines BA:   metadata %.3f  activity %.3f  mode %.3f"%(base["metadata"],base["activity"],base["mode"]))

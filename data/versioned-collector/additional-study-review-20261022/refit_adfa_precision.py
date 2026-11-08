"""Option (a) with the ADFA-90 host contract: does adding HIGH-VOLUME network-active benign to the
training set realize the precision benefit (stop the hybrid false-alarming on benign bulk) while still
flagging floods?

Two ADFA-90 fits (RF500/balanced/seed42, direct 90-col fit a la probe_adfa_heldout_revision5), scored on
the SAME held-out set (held-out floods + held-out benign bulk + bulkdl + null, all .21-captured):
  BASELINE  : revision5 training only (benign = mostly network-silent CLI tools)
  AUGMENTED : revision5 training + high-volume benign HTTP-bulk .21 captures (label benign)

Host = ADFA-90 (locked contract). P4 = 145. Hybrid = 90+145. Exploratory/OOD (models never trained on floods);
reports malware-probability per held-out case for host/P4/hybrid under both fits. No model promotion, no merge.
Usage: python3 refit_adfa_precision.py <bulk-attempt-dir> <flood-attempt-dir>
"""
import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import analyze_v21 as base          # noqa: E402
import analyze_revision5 as rev5    # noqa: E402
import score_flood21 as sf          # noqa: E402  (build_record)

ADFA = ROOT.parents[2] / "data/benign/revision3/labeled_sample_dataset.feature_columns.adfa-host.json"


def main():
    bulk_attempt = Path(sys.argv[1]); flood_attempt = Path(sys.argv[2])
    base.V21_ATTEMPT = rev5.ATTEMPT
    base.CASES_ORDER = rev5.ATTEMPT / "payload/cases.json"
    base.case_metadata = rev5.case_metadata
    base.HOST_CONTRACT = str(ADFA)
    trainer, data, _ = base.frozen.dependencies()
    np = trainer.np
    records, host, *_ = base.prepare(trainer, data)
    assert len(host) == 90, "expected 90 ADFA host cols"
    P4 = list(data.p4.P4_SAMPLE_FEATURES)
    host_signals = {n.removeprefix("host__").rsplit("__", 1)[0] for n in host}

    rev5_common = [r for r in records if r["p4_alignment_status"] == "unique" and r["p4_parity"] == "True"]
    tr_idx, _ = trainer.split_indices(rev5_common)
    rev5_train = [rev5_common[i] for i in tr_idx]

    def rec(attempt, name, label):
        sd = attempt / "runs" / (name + ".zip")
        return sf.build_record(sd, name, label, host, host_signals, trainer, data)

    # benign-bulk augmentation (label 0): 4 into training, 2 held out
    aug_train = [rec(bulk_attempt, n, 0) for n in ("bulk400", "bulk700", "bulk1300", "bulk2000")]
    held = [("floodsyn", 1, flood_attempt), ("floodudp", 1, flood_attempt),
            ("bulk1000", 0, bulk_attempt), ("bulk1600", 0, bulk_attempt),
            ("bulkdl", 0, flood_attempt), ("nullidle", 0, flood_attempt)]
    held_recs = [(n, lab, rec(att, n, lab)) for n, lab, att in held]

    def mat(rows, names):
        return np.asarray([[float(r[name]) for name in names] for r in rows], dtype=float)

    def fit(train, names):
        est = trainer.random_forest()
        est.fit(mat(train, names), np.asarray([r["label"] for r in train]))
        return est

    def scorable(r, names):
        return all(name in r for name in names)

    out = {"host_contract": "ADFA-90", "n_adfa": len(host), "fits": {}}
    for tag, train in (("baseline_rev5_only", rev5_train),
                       ("augmented_plus_netbenign", rev5_train + aug_train)):
        eh = fit(train, host); ep = fit(train, P4); ey = fit(train, host + P4)
        print("\n=== %s  (train n=%d, benign=%d, malware=%d) ===" %
              (tag, len(train), sum(r["label"] == 0 for r in train), sum(r["label"] == 1 for r in train)))
        print("  %-9s %-6s  host90   p4-145   hybrid" % ("case", "truth"))
        rows = []
        for n, lab, r in held_recs:
            if r.get("p4_parity") != "True":
                print("  %-9s %-6s  (not P4-aligned: %s)" % (n, "FLOOD" if lab else "benign", r.get("p4_alignment_status")))
                continue
            h = float(eh.predict_proba(mat([r], host))[:, 1][0])
            p = float(ep.predict_proba(mat([r], P4))[:, 1][0])
            y = float(ey.predict_proba(mat([r], host + P4))[:, 1][0])
            print("  %-9s %-6s  %.3f(%s) %.3f(%s) %.3f(%s)" %
                  (n, "FLOOD" if lab else "benign",
                   h, "M" if h >= .5 else "b", p, "M" if p >= .5 else "b", y, "M" if y >= .5 else "b"))
            rows.append({"case": n, "truth": lab, "host": round(h, 3), "p4": round(p, 3), "hybrid": round(y, 3)})
        out["fits"][tag] = rows
    (flood_attempt / "adfa_precision_refit.json").write_text(json.dumps(out, indent=2))
    print("\nwrote", flood_attempt / "adfa_precision_refit.json")


if __name__ == "__main__":
    main()

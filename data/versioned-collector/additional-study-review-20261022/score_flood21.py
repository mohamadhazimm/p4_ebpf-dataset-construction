"""Score the revision5-trained host/P4/hybrid models on the .21-captured rate-capped floods + benign bulk.
Reuses analyze_v21's EXACT feature pipeline: prepare() rebuilds the revision5 cohort and trainer.fit_final_models
refits deterministically (seed42 -> reproduces the saved models) and scores whatever we pass as `validation`.
We pass the flood_gen captures as validation records (built with the identical per-capture feature extraction).

Deployed host contract (35 ebpf-counter families x5 -> trainer MI-selects 29 families = 145 cols), P4 145, hybrid 290
-- i.e. the host_29_families / network_p4 / hybrid_29_plus_29 models. This is an OUT-OF-DISTRIBUTION probe: the
models were trained on CLI-benign vs botnet/miner/ransomware, never on a flood. No merge, no model promotion.
Usage: python3 score_flood21.py <flood21-collect-attempt-dir>
"""
import json, math, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import analyze_v21 as az   # noqa: E402


def build_record(sample_dir, name, label, host, host_signals, trainer, data):
    run_json = next(sample_dir.glob("output/run_*/run.json"))
    metadata = json.loads(run_json.read_text())
    telemetry = data.p4.load_telemetry_rows(sample_dir)
    q = metadata.get("collection_quality_status")
    reasons = metadata.get("collection_quality_reasons", [])
    rec = {"sample": name, "class": "flood" if label == 1 else "benign", "label": label,
           "split": "validation", "mode": metadata.get("execution_mode", "amd64_static"),
           "group_id": "flood_" + name, "position": 0, "run_id": metadata.get("run_id", ""),
           "return_code": metadata.get("return_code"),
           "post_target_lineage_raw_syscalls": int(metadata.get("target_exec", {}).get("post_target_lineage_raw_syscalls", 0)),
           "quality": q, "quality_reasons": reasons, "windows": len(telemetry)}
    if len(telemetry) != 40:
        rec["p4_alignment_status"] = "no_telemetry"; rec["p4_parity"] = "False"; return rec
    summary = {s: data.aggregate([float(w[s]) for w in telemetry]) for s in host_signals | set(data.p4.P4_FEATURES)}
    for n in host:
        rec[n] = summary[n.removeprefix("host__").rsplit("__", 1)[0]][n.rsplit("__", 1)[1]]
    pcap = next(sample_dir.glob("output/run_*/packet_capture.pcap"))
    extracted, _, diag = data.p4.derive_p4_features(pcap, telemetry, metadata, byte_layer="ethernet", rate_window="nominal")
    rec["p4_alignment_status"] = diag["alignment_status"]
    rec["p4_parity"] = "True" if diag["alignment_status"] == "unique" else "False"
    if diag["alignment_status"] == "unique":
        for n in data.p4.P4_SAMPLE_FEATURES:
            rec[n] = float(extracted[n])
    return rec


def main():
    attempt = Path(sys.argv[1])
    az.HOST_CONTRACT = None
    trainer, data, _ = az.frozen.dependencies()
    records, host, *_ = az.prepare(trainer, data)
    common = [r for r in records if r["p4_alignment_status"] == "unique" and r["p4_parity"] == "True"]
    train_idx, _ = trainer.split_indices(common)
    training = [common[i] for i in train_idx]
    host_signals = {n.removeprefix("host__").rsplit("__", 1)[0] for n in host}

    labels = {"floodsyn": 1, "floodudp": 1, "bulkdl": 0, "nullidle": 0}
    flood = []
    for name, lab in labels.items():
        sd = attempt / "runs" / (name + ".zip")
        if not sd.exists():
            sd = attempt / "runs" / name
        if not sd.exists():
            print("MISSING capture:", name); continue
        flood.append(build_record(sd, name, lab, host, host_signals, trainer, data))

    print("\n=== captured flood/bulk records (through the real .21 collector) ===")
    for r in flood:
        print("  %-9s quality=%-9s win=%s syscalls=%s p4=%s %s" %
              (r["sample"], r.get("quality"), r.get("windows"), r.get("post_target_lineage_raw_syscalls"),
               r.get("p4_alignment_status"), ("" if r.get("quality") == "accepted" else "reasons=" + str(r.get("quality_reasons")))))

    scorable = [r for r in flood if r["p4_parity"] == "True"]
    hostonly = [r for r in flood if r["p4_parity"] != "True" and r.get("windows") == 40]
    import tempfile
    models = Path(tempfile.mkdtemp()) / "m"; models.mkdir()
    out = {"attempt": str(attempt), "records": []}
    KEYMAP = {"host_29_families": "host", "network_p4": "p4", "hybrid_29_plus_29": "hybrid"}
    if scorable:
        probs, _sel, _d = trainer.fit_final_models(training, scorable, host, models, "flood_score")
        # map whatever the trainer names its model outputs to host/p4/hybrid
        colmap = {}
        for k in probs.keys():
            colmap[KEYMAP.get(k, k)] = k
        print("\n=== three-model malware-probability on .21-captured floods vs benign (deployed host/P4/hybrid) ===")
        print("  raw model keys:", sorted(probs.keys()))
        for i, r in enumerate(scorable):
            row = {}
            for short in ("host", "p4", "hybrid"):
                if short in colmap:
                    row[short] = round(float(probs[colmap[short]][i]), 3)
            print("  %-9s (truth=%-6s syscalls=%7d)  " % (r["sample"], "FLOOD" if r["label"] == 1 else "benign",
                  r["post_target_lineage_raw_syscalls"]) +
                  "  ".join("%s=%.3f(%s)" % (s, row[s], "MAL" if row[s] >= 0.5 else "ben") for s in ("host", "p4", "hybrid") if s in row))
            out["records"].append({"sample": r["sample"], "truth": r["label"],
                                   "syscalls": r["post_target_lineage_raw_syscalls"], **row})
    if hostonly:
        print("\n(host-only, P4 not alignable for:", [r["sample"] for r in hostonly], ")")
    (attempt / "flood_model_scores.json").write_text(json.dumps(out, indent=2))
    print("\nwrote", attempt / "flood_model_scores.json")


if __name__ == "__main__":
    main()

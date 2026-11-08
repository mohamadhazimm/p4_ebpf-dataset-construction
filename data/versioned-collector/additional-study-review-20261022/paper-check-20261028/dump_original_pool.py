"""Rebuild the Table V pool through the ORIGINAL code path (score_balanced_21 + expanded EXTRA, incl. PCAP
reconstruction of P4 features) and dump it, so it can be compared cell-by-cell with the independent rebuild.
Read-only on the study tree; writes only to the scratchpad path given as argv[1].
"""
import json, sys
from pathlib import Path

ROOT = Path("/home/ali/Desktop/Hazim/vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/additional-study-review-20261022")
sys.path.insert(0, str(ROOT))
import analyze_v21 as base          # noqa: E402
import analyze_revision5 as rev5    # noqa: E402
import score_flood21 as sf          # noqa: E402

OUT = Path(sys.argv[1])
ADFA = ROOT.parents[2] / "data/benign/revision3/labeled_sample_dataset.feature_columns.adfa-host.json"
RT = ROOT / "realtools-collect/20261026T165642798242Z"
DV = ROOT / "flood21-collect/20261026T154421063760Z"
FLOOD = ["syn_fan_40k", "syn_fan_100k", "syn_fan_150k", "syn_sink_40k", "syn_sink_100k", "udp_fan_60k", "udp_fan_250k",
         "udp_sink_60k", "udp_sink_150k", "udp_sink_250k", "slowloris_150", "slowloris_300", "slowloris_500",
         "slowloris_800", "slowloris_1000", "goldeneye_g5", "goldeneye_g10", "goldeneye_g15", "goldeneye_p10",
         "goldeneye_r10"]
NET = ["bulkup_200", "bulkup_400", "bulkup_700", "session_300", "session_600", "session_1000", "beacon_50",
       "beacon_100", "dns_2k", "dns_5k", "dns_10k"]
base.V21_ATTEMPT = rev5.ATTEMPT
base.CASES_ORDER = rev5.ATTEMPT / "payload/cases.json"
base.case_metadata = rev5.case_metadata
base.HOST_CONTRACT = str(ADFA)
trainer, data, _ = base.frozen.dependencies()
records, host, *_ = base.prepare(trainer, data)
P4 = list(data.p4.P4_SAMPLE_FEATURES)
sig = {n.removeprefix("host__").rsplit("__", 1)[0] for n in host}
pool = [dict(r, stratum="general_malware" if r["label"] == 1 else "cli_benign") for r in records
        if r["p4_alignment_status"] == "unique" and r["p4_parity"] == "True"]
diag = []


def add(att, name, label, stratum, group):
    try:
        r = sf.build_record(att / "runs" / (name + ".zip"), name, label, host, sig, trainer, data)
    except Exception as e:
        diag.append((name, "build failed", repr(e)[:200])); return
    if r.get("quality") != "accepted" or r.get("p4_parity") != "True":
        diag.append((name, r.get("quality"), r.get("p4_alignment_status"))); return
    r["stratum"] = stratum; r["group_id"] = group
    pool.append(r)


for n in FLOOD:
    add(RT, n, 1, "flood_" + n.split("_")[0], "flood_" + n)
for n in NET:
    add(DV, n, 0, "net_benign", "netb_" + n.rsplit("_", 1)[0])
for n in ["null1", "null2"]:
    add(DV, n, 0, "null", "null")
xb = DV.parent
for a, n, st, g in [("20261026T150016786262Z", "bulkdl", "net_benign", "netb_bulkdl"),
                    ("20261026T150016786262Z", "nullidle", "null", "null")] + \
                   [("20261026T151240756153Z", "bulk%d" % k, "net_benign", "netb_bulkup") for k in (400, 700, 1000, 1300, 1600, 2000)]:
    add(xb / a, n, 0, st, g)
keep = ["sample", "label", "group_id", "stratum", "post_target_lineage_raw_syscalls", "return_code"] + list(host) + P4
OUT.mkdir(parents=True, exist_ok=True)
json.dump({"host": list(host), "p4": P4, "diag": diag, "rows": [{k: r.get(k) for k in keep} for r in pool]},
          open(OUT / "original_pool.json", "w"))
print("pool", len(pool), "dropped", diag)

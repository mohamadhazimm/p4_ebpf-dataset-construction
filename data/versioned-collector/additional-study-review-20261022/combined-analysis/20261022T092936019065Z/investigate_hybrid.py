#!/usr/bin/env python3
"""Read-only diagnostics of saved forests/predictions; no refits or threshold tuning."""

import argparse
import csv
import json
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ATTEMPT = Path(__file__).resolve().parent
REVIEW = ATTEMPT.parents[1]
sys.path.insert(0, str(REVIEW))
import analyze_matched45 as analysis

MODELS = ("network_p4", "host_29_families", "hybrid_29_plus_29")


def load_csv(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def index_predictions(rows):
    result = {}
    for row in rows:
        if row["model"] not in MODELS:
            continue
        key = (row["sample"], row["model"])
        if key in result:
            raise ValueError("Duplicate model/sample prediction")
        result[key] = row
    for sample in {key[0] for key in result}:
        if {int(result[sample, model]["label"]) for model in MODELS} not in ({0}, {1}):
            raise ValueError("Models disagree on sample labels")
    return result


def evaluate(index, names, trainer):
    ordered = sorted(names)
    return {model: trainer.binary_metrics(
        trainer.np.asarray([int(index[sample, model]["label"]) for sample in ordered]),
        trainer.np.asarray([float(index[sample, model]["probability_malware"]) for sample in ordered]))
        for model in MODELS}


def packet_context(row):
    directory = analysis.ready.STUDY / row["source_run_dir"]
    metadata = analysis.ready.load(directory / "run.json")
    result = {"sample": row["sample"], "group_id": row["group_id"], "cohort": row["cohort"],
        "source_run_dir": row["source_run_dir"], "target_exec": metadata["target_exec"],
        "quality_status": metadata["collection_quality_status"],
        "loss": {key: metadata[key] for key in ("ebpf_lost_event_count", "packet_capture_counter_discrepancy", "packet_capture_dropped_by_kernel")},
        "target_connect_count": float(row["host__ebpf_connect_count__sum"]),
        "p4_alignment": row["p4_alignment_status"], "p4_parity": row["p4_parity"],
        "metadata_sha256": analysis.ready.digest(directory / "run.json")}
    binary = shutil.which("tshark")
    if not binary:
        result["packet_decode"] = "unavailable: tshark not installed"
        return result
    fields = ["frame.time_epoch", "ip.src", "ip.dst", "ip.proto", "tcp.srcport", "tcp.dstport",
              "udp.srcport", "udp.dstport", "http.host", "http.request.uri", "dns.qry.name", "http.user_agent"]
    command = [binary, "-n", "-r", str(directory / "packet_capture.pcap"), "-Y", "ip", "-T", "fields"]
    for field in fields:
        command.extend(("-e", field))
    decoded = subprocess.run(command, capture_output=True, text=True, check=True, timeout=120)
    packets = [dict(zip(fields, values)) for values in csv.reader(decoded.stdout.splitlines(), delimiter="\t")]
    intervals = [(datetime.fromisoformat(window["window_start_utc"].replace("Z", "+00:00")).timestamp(),
                  datetime.fromisoformat(window["window_end_utc"].replace("Z", "+00:00")).timestamp())
                 for window in load_csv(directory / "telemetry.csv")]
    modeled = [packet for packet in packets if any(
        start <= float(packet["frame.time_epoch"]) < end for start, end in intervals)]
    result["in_window_ipv4_packets"] = len(modeled)
    result["in_window_tcp_udp_packets"] = sum(packet["ip.proto"] in ("6", "17") for packet in modeled)
    result["in_window_http_hosts"] = sorted({packet["http.host"] for packet in modeled if packet.get("http.host")})
    result["in_window_http_user_agents"] = sorted({packet["http.user_agent"] for packet in modeled if packet.get("http.user_agent")})
    result["in_window_dns_names"] = sorted({packet["dns.qry.name"] for packet in modeled if packet.get("dns.qry.name")})
    result["decoded_ipv4_packets"] = len(packets)
    result["decoded_http_requests"] = [
        {key: packet.get(key, "") for key in ("ip.src", "ip.dst", "http.host", "http.request.uri")}
        for packet in packets if packet.get("http.host") or packet.get("http.request.uri")]
    result["decoded_dns_names"] = sorted({packet["dns.qry.name"] for packet in packets if packet.get("dns.qry.name")})
    result["flows"] = [{"flow": list(flow), "packets": count} for flow, count in Counter(
        (packet.get("ip.src", ""), packet.get("ip.dst", ""), packet.get("ip.proto", ""),
         packet.get("tcp.srcport") or packet.get("udp.srcport", ""),
         packet.get("tcp.dstport") or packet.get("udp.dstport", "")) for packet in packets).most_common(12)]
    return result


def run():
    analysis.verify_inputs()
    trainer, data, _ = analysis.combined.frozen.dependencies()
    old_output = analysis.BASE / "analysis/model-fit"
    new_output = ATTEMPT / "analysis/model-fit"
    old = index_predictions(load_csv(old_output / "validation_predictions.csv"))
    new = index_predictions(load_csv(new_output / "validation_predictions.csv"))
    old_names, new_names = {key[0] for key in old}, {key[0] for key in new}
    if not old_names < new_names:
        raise ValueError("Cannot compare unchanged old population with additions")
    rows = {row["sample"]: row for row in load_csv(ATTEMPT / "analysis/eligible_dataset.csv")}
    pairs, contexts = [], []
    for sample in sorted(new_names):
        host, hybrid, network = (new[sample, model] for model in ("host_29_families", "hybrid_29_plus_29", "network_p4"))
        if host["prediction"] == hybrid["prediction"]:
            continue
        label = int(host["label"])
        pairs.append({"sample": sample, "class": rows[sample]["class"], "group_id": host["group_id"],
            "cohort": rows[sample]["cohort"], "mode": host["mode"],
            "host_probability": float(host["probability_malware"]), "hybrid_probability": float(hybrid["probability_malware"]),
            "network_probability": float(network["probability_malware"]),
            "host_correct": int(host["prediction"]) == label, "hybrid_correct": int(hybrid["prediction"]) == label})
        contexts.append(packet_context(rows[sample]))
    forests = {}
    paths = [Path(__file__), ATTEMPT / "analysis/compatibility_audit.json", ATTEMPT / "verification.json"]
    for version, output in (("before", old_output), ("after", new_output)):
        metrics = analysis.ready.load(output / "metrics.json")
        expected_hashes = analysis.ready.load(output / "model_sha256.json")
        selections = analysis.ready.load(output / "feature_selection.json")["primary"]
        features = {"network_p4": list(data.p4.P4_SAMPLE_FEATURES),
            "host_29_families": selections["selected_host_features"],
            "hybrid_29_plus_29": list(data.p4.P4_SAMPLE_FEATURES) + selections["selected_host_features"]}
        index = old if version == "before" else new
        names = old_names if version == "before" else new_names
        ordered = sorted(names)
        for model in MODELS:
            path = output / "models" / (model + ".joblib")
            if analysis.ready.digest(path) != expected_hashes[path.name]:
                raise ValueError("Saved model hash differs")
            fitted = trainer.joblib.load(path)
            matrix = trainer.matrix([rows[sample] for sample in ordered], features[model])
            probabilities = fitted.predict_proba(matrix)[:, 1]
            expected = trainer.np.asarray([float(index[sample, model]["probability_malware"]) for sample in ordered])
            if not trainer.np.allclose(probabilities, expected, rtol=0, atol=1e-12):
                raise ValueError("Saved prediction/model/data disagreement")
            forest = fitted.steps[-1][1]
            importance = forest.feature_importances_
            top = sorted(zip(features[model], importance), key=lambda pair: pair[1], reverse=True)[:12]
            forests[version + ":" + model] = {"feature_count": int(forest.n_features_in_),
                "max_features": forest.max_features,
                "actual_split_candidate_counts": sorted({tree.max_features_ for tree in forest.estimators_}),
                "importance_network": float(importance[:145].sum()) if model == "hybrid_29_plus_29" else None,
                "importance_host": float(importance[145:].sum()) if model == "hybrid_29_plus_29" else None,
                "top_impurity_importance": [{"feature": name, "importance": float(value)} for name, value in top],
                "training_grouped_oof": metrics["training_grouped_oof"][model]}
            paths.append(path)
        paths.extend((output / "metrics.json", output / "validation_predictions.csv", output / "feature_selection.json"))
    summary = {"scope": "Post-hoc diagnostics of unchanged saved models; no fit, tuning, recollection or VM operations",
        "comparison_counts": {"old_validation": len(old_names), "new_validation": len(new_names), "added": len(new_names - old_names)},
        "old_model_old_cases": evaluate(old, old_names, trainer),
        "new_model_old_cases": evaluate(new, old_names, trainer),
        "new_model_added_cases": evaluate(new, new_names - old_names, trainer),
        "new_model_all_cases": evaluate(new, new_names, trainer),
        "paired_disagreements": pairs,
        "hybrid_only_correct": sum(row["hybrid_correct"] for row in pairs),
        "host_only_correct": sum(row["host_correct"] for row in pairs),
        "forests": forests,
        "same_host_features_within_each_model_pair": True,
        "collection_audit": analysis.ready.load(ATTEMPT / "analysis/compatibility_audit.json"),
        "source_hashes": {str(path.relative_to(analysis.ready.STUDY)): analysis.ready.digest(path) for path in paths},
        "limitations": ["Impurity importance and split-candidate counts do not establish the causal effect of a different RF configuration",
            "Zero target connect calls plus ambient-flow signatures support a background-traffic concern, not proven packet attribution",
            "Successful archive/PCAP/P4 reconciliation cannot prove never-recorded-event completeness or malicious activation",
            "Do not tune models, thresholds or collection to force hybrid superiority on consumed validation",
            "An OR of detector alerts preserves host-positive alerts but cannot guarantee accuracy or specificity"]}
    output = ATTEMPT / "hybrid-investigation" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output.mkdir(parents=True, exist_ok=False)
    analysis.ready.save(output / "summary.json", summary)
    analysis.ready.save(output / "packet_context.json", contexts)
    analysis.combined.save_rows(output / "paired_disagreements.csv", pairs)
    print(json.dumps({"output": str(output), "hybrid_only_correct": summary["hybrid_only_correct"],
        "host_only_correct": summary["host_only_correct"], "cases": pairs,
        "packet_context": [{key: row[key] for key in ("sample", "target_connect_count", "in_window_ipv4_packets",
            "in_window_tcp_udp_packets", "in_window_http_hosts", "in_window_http_user_agents", "in_window_dns_names") if key in row} for row in contexts]}, indent=2))


def self_test():
    rows = [{"sample": "fixture", "model": model, "label": "1", "probability_malware": "0.6"} for model in MODELS]
    assert len(index_predictions(rows)) == 3
    for bad in (rows + [rows[0]], [dict(row, label="0") if row["model"] == "network_p4" else row for row in rows]):
        try:
            index_predictions(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid paired prediction table accepted")
    print("PASS: long-form model/sample indexing and duplicate/label-mismatch guards; no refit")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    self_test() if args.self_test else run()
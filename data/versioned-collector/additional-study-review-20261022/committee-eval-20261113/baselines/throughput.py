"""Single-core software extraction throughput on the two largest attack captures (offline, CPU time).

Tools: (a) the CICFlowMeter-like extractor of flow_extract.py (pure Python, whole file: pcap read, parse, flow
table, per-flow features, run aggregates); (b) Kitsune's official AfterImage (FeatureExtractor/netStat, pure
Python) on the already-parsed .tsv of the first 20,000 in-window packets; (c) tshark -T fields with Kitsune's
19-field list (whole file, output discarded); (d) Zeek 9.0.1 (official binary package from the Zeek OBS repository,
extracted into vendor/zeek, not installed) with its default scripts, `zeek -C -r file` (whole file).

CPU seconds = user + system time of the measuring process (a, b) or of the child process (c, d).
Cores for 100 Gb/s = packet rate / single-core rate: 148.8 Mpps at 64-byte frames, 23.5 Mpps at 512-byte frames
(perfect scaling assumed; capture, load balancing and memory are ignored, so these are lower bounds).

    /usr/bin/python3 throughput.py
"""
import contextlib
import io
import json
import os
import resource
import subprocess
import sys
import time

import numpy as np

import bl_common as B
import flow_extract as FX
import kitsune_extract as KE

RATES = {"64B": 148.8e6, "512B": 23.5e6}
RUNS = ("syn_fan_150k", "udp_sink_250k")
ZEEK = B.VENDOR / "zeek" / "root" / "opt" / "zeek"


def child_cpu():
    r = resource.getrusage(resource.RUSAGE_CHILDREN)
    return r.ru_utime + r.ru_stime


def self_cpu():
    r = resource.getrusage(resource.RUSAGE_SELF)
    return r.ru_utime + r.ru_stime


def count_frames(path):
    return sum(1 for _ in FX.frames(path))


def t_flow(path):
    c0 = self_cpu(); w0 = time.time()
    fl = FX.run_flows(path)
    FX.run_vector(fl)
    return self_cpu() - c0, time.time() - w0, len(fl)


def t_kitsune(tsv, limit):
    FEmod = KE.import_official()
    with contextlib.redirect_stdout(io.StringIO()):
        fe = FEmod.FE(str(tsv), limit)
        c0 = self_cpu(); w0 = time.time(); n = 0
        while True:
            x = fe.get_next_vector()
            if len(x) == 0:
                break
            n += 1
    return self_cpu() - c0, time.time() - w0, n


def t_tshark(path):
    c0 = child_cpu(); w0 = time.time()
    subprocess.run([KE.TSHARK, "-r", str(path), "-T", "fields", *KE.FIELDS, "-E", "header=y", "-E", "occurrence=f"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    return child_cpu() - c0, time.time() - w0


def t_zeek(path, name):
    work = B.CACHE / "zeek_run" / ("%s-%s" % (name, time.strftime("%Y%m%dT%H%M%S")))
    work.mkdir(parents=True)  # fresh directory per measurement (Zeek writes its logs into the working directory)
    env = dict(os.environ)
    root = str(ZEEK)
    env.update(ZEEKPATH=".:{0}/share/zeek:{0}/share/zeek/policy:{0}/share/zeek/site:{0}/share/zeek/builtin-plugins"
               .format(root),
               ZEEK_PLUGIN_PATH="%s/lib/zeek/plugin" % root, LD_LIBRARY_PATH="%s/lib" % root)
    c0 = child_cpu(); w0 = time.time()
    subprocess.run([str(ZEEK / "bin" / "zeek"), "-C", "-r", str(path)], cwd=work, env=env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    cpu, wall = child_cpu() - c0, time.time() - w0
    conn = work / "conn.log"
    nconn = sum(1 for l in open(conn) if not l.startswith("#")) if conn.exists() else 0
    logs = sorted(p.name for p in work.iterdir())
    return cpu, wall, nconn, logs


TOOLS = ("flow_extractor", "kitsune_afterimage", "tshark_fields", "zeek")


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", nargs="*", default=list(TOOLS))
    a = ap.parse_args()
    rows, *_ = B.dataset()
    dirs = B.C.run_dirs(rows)
    idx = {r["execution_id"]: i for i, r in enumerate(rows)}
    path = B.RESULTS / "throughput.json"
    out = json.loads(path.read_text()) if path.exists() else {"rates_pps": RATES, "runs": {}}
    for name in RUNS:
        i = idx[name]
        od = B.C.output_dir(dirs[i])
        pcap = od / "packet_capture.pcap"
        n = count_frames(pcap)
        res = out["runs"].setdefault(name, {})
        res.update({"row": i, "frames_in_file": n, "bytes": pcap.stat().st_size})
        if "flow_extractor" in a.tools:
            cpu, wall, nf = t_flow(pcap)
            res["flow_extractor"] = {"packets": n, "flows": nf, "cpu_s": cpu, "wall_s": wall, "pps": n / cpu}
        if "tshark_fields" in a.tools:
            cpu, wall = t_tshark(pcap)
            res["tshark_fields"] = {"packets": n, "cpu_s": cpu, "wall_s": wall, "pps": n / cpu}
        if "zeek" in a.tools:
            cpu, wall, nconn, logs = t_zeek(pcap, name)
            res["zeek"] = {"packets": n, "cpu_s": cpu, "wall_s": wall, "pps": n / cpu, "conn_log_lines": nconn,
                           "logs": logs, "version": "9.0.1 (zeek-9.0-core_9.0.1-0_amd64.deb)"}
        if "kitsune_afterimage" in a.tools:
            meta = json.loads((B.CACHE / "kitsune" / "meta" / ("%03d.json" % i)).read_text())
            tsv = B.CACHE / "kitsune" / "tsv" / ("%03d.tsv" % i)
            lim = 2000 if name == "syn_fan_150k" else 20000
            cpu, wall, nk = t_kitsune(tsv, lim)
            res["kitsune_afterimage"] = {"packets": nk, "cpu_s": cpu, "wall_s": wall, "pps": nk / cpu,
                                         "extraction_run_first_20000_wall_s_including_tshark": meta["seconds"],
                                         "note": "first %d in-window packets" % lim}
        B.log(name, {k: (round(v["pps"]) if isinstance(v, dict) and "pps" in v else v) for k, v in res.items()})
    summary = {}
    for tool in TOOLS:
        if not all(tool in out["runs"].get(r, {}) for r in RUNS):
            continue
        pps = {r: out["runs"][r][tool]["pps"] for r in RUNS}
        best = max(pps.values())
        summary[tool] = {"pps_per_core": pps, "best_pps_per_core": best,
                         "cores_for_100G": {k: v / best for k, v in RATES.items()},
                         "cores_for_100G_worst_capture": {k: v / min(pps.values()) for k, v in RATES.items()}}
    out["summary"] = summary
    B.write_json(path, out)
    for t, s in summary.items():
        print("%-20s best %10.0f pkt/s/core -> cores for 100G: 64B %8.0f  512B %8.0f" % (
            t, s["best_pps_per_core"], s["cores_for_100G"]["64B"], s["cores_for_100G"]["512B"]))


if __name__ == "__main__":
    sys.exit(main())

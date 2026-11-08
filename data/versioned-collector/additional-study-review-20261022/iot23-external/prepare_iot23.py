#!/usr/bin/env python3
"""Cut IoT-23 captures into 20-s observations and compute the switch's 145 network columns.

For each capture:
  1. a header-only pass gives the capture span and the number of frames in every 20-s chunk;
  2. the labeled Zeek connection log gives every chunk a category (ddos, scan, attack, cc, other,
     benign traffic, idle) from the labels of the flows that overlap it;
  3. a seeded sample of chunks is drawn per category;
  4. one pass over the capture computes, for each sampled chunk, the 40 window features of the
     paper's switch model and summarizes them into the 145 dataset columns.

The window features come from the release repository's features/switch_model.py (FlowTable,
parse_flow_packet) and features/summary.py, unchanged. Each chunk starts with an empty flow table,
as every execution of the dataset did. The only addition is the single pass over a long capture;
--self-check compares it with switch_model.window_features() on sampled chunks.

    python3 -I prepare_iot23.py DATA_ROOT OUT_DIR [--seed 42] [--jobs 6] [--only SCENARIO ...]
"""

import argparse
import csv
import hashlib
import json
import os
import random
import site
import struct
import sys
import time
from decimal import Decimal
from multiprocessing import Pool
from pathlib import Path

RELEASE = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
sys.path.insert(0, str(RELEASE / "features"))
if site.getusersitepackages() not in sys.path:
    sys.path.append(site.getusersitepackages())  # numpy for summary.py

import switch_model  # noqa: E402
from summary import summarize  # noqa: E402

WINDOW_SECONDS = 0.5
WINDOWS = 40
TTL_WINDOWS = 3
WINDOW_US = 500_000
CHUNK_US = WINDOWS * WINDOW_US

# Malware family per scenario, from the IoT-23 page's scenario table.
CAPTURES = [
    # scenario, family, role, pcap (relative to the scenario directory), label log or None
    ("CTU-Honeypot-Capture-4-1", "Philips Hue", "benign", "2018-10-25-14-06-32-192.168.1.132.pcap", "bro/conn.log.labeled"),
    ("CTU-Honeypot-Capture-5-1", "Amazon Echo", "benign", "2018-09-21-capture.pcap", "bro/conn.log.labeled"),
    ("CTU-Honeypot-Capture-7-1", "Somfy door lock", "benign", "Somfy-01/2019-07-03-15-15-47-first_start_somfy_gateway.pcap", "Somfy-01/bro/conn.log.labeled"),
    ("CTU-Honeypot-Capture-7-1", "Somfy door lock", "benign", "Somfy-02/2019-07-03-16-41-09-192.168.1.158.pcap", None),
    ("CTU-Honeypot-Capture-7-1", "Somfy door lock", "benign", "Somfy-03/2019-07-04-16-41-10-192.168.1.158.pcap", None),
    ("CTU-Honeypot-Capture-7-1", "Somfy door lock", "benign", "Somfy-04/2019-07-05-16-41-14-192.168.1.158.pcap", None),
    ("CTU-Honeypot-Capture-7-1", "Somfy door lock", "benign", "Somfy-05/2019-07-06-16-41-17-192.168.1.158.pcap", None),
    ("CTU-Honeypot-Capture-7-1", "Somfy door lock", "benign", "Somfy-06/2019-07-07-16-41-19-192.168.1.158.pcap", None),
    ("CTU-IoT-Malware-Capture-34-1", "Mirai", "malware", "2018-12-21-15-50-14-192.168.1.195.pcap", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-44-1", "Mirai", "malware", "2019-01-10-21-06-26-192.168.1.199.pcap", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-35-1", "Mirai", "malware", "2018-12-21-15-33-59-192.168.1.196.pcap", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-7-1", "Mirai", "malware", "2018-07-20-17-31-20-192.168.100.108.pcap", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-48-1", "Mirai", "malware", "2019-02-28-19-15-13-192.168.1.200.pcap", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-49-1", "Mirai", "malware", "2019-02-28-20-50-15-192.168.1.193.pcap", "bro/conn.log.labeled"),
    # 60-1 (21 GB) is used through time slices fetched by slice_iot23.py: four flood types, the
    # spoofed-source TCP flood, and a 30-min stretch without a flood (slices.json has the byte ranges).
    *[("CTU-IoT-Malware-Capture-60-1", "Gafgyt", "malware",
       "slices/2019-09-20-02-40-32-192.168.1.195.slice-2019-09-20T%s-2019-09-20T%s.pcap" % span, "bro/conn.log.labeled")
      for span in (("024100", "025100"), ("043000", "044000"), ("061100", "062100"), ("100000", "103000"),
                   ("140600", "141600"), ("222300", "223000"))],
    ("CTU-IoT-Malware-Capture-9-1", "Hajime", "malware", "2018-07-25-10-53-16-192.168.100.111.pcap", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-3-1", "Muhstik", "malware", "2018-05-21_capture.pcap", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-1-1", "Hide and Seek", "malware", "2018-05-09-192.168.100.103.pcap", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-8-1", "Hakai", "malware", "2018-07-31-15-15-09-192.168.100.113.pcap", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-20-1", "Torii", "malware", "2018-10-02-13-12-30-192.168.100.103.pcap", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-21-1", "Torii", "malware", "2018-10-03-15-22-32-192.168.100.113.pcap", "bro/conn.log.labeled"),
    ("CTU-IoT-Malware-Capture-42-1", "Trojan", "malware", "2019-01-10-14-34-38-192.168.1.197.pcap", "bro/conn.log.labeled"),
]

# Chunk category: the highest-priority label among the flows overlapping the chunk.
PRIORITY = ("ddos", "scan", "attack", "cc", "other", "benign", "idle")
SAMPLE_PER_CATEGORY = {"ddos": 200, "scan": 200, "attack": 200, "cc": 200, "other": 200,
                       "benign": 200, "idle": 20}
SAMPLE_BENIGN_SCENARIO = 600  # benign-device chunks per benign scenario, spread over its captures


def flow_category(label, detailed):
    if label.lower() == "benign":
        return "benign"
    d = detailed.lower()
    if "ddos" in d:
        return "ddos"
    if "horizontalportscan" in d:
        return "scan"
    if "attack" in d:
        return "attack"
    if "c&c" in d or "heartbeat" in d or "filedownload" in d:
        return "cc"
    return "other"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(1 << 24)
            if not block:
                return h.hexdigest()
            h.update(block)


def pcap_format(f):
    header = f.read(24)
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 6), b"\xa1\xb2\xc3\xd4": (">", 6),
               b"\x4d\x3c\xb2\xa1": ("<", 9), b"\xa1\xb2\x3c\x4d": (">", 9)}
    if header[:4] not in formats:
        raise ValueError("not a classic pcap file")
    order, digits = formats[header[:4]]
    linktype = struct.unpack(order + "I", header[20:24])[0]
    return order, digits, linktype


def span_pass(path):
    """First and last frame time (us), frames per chunk, frames out of time order."""
    counts, first, last, frames, backwards, prev = [], None, None, 0, 0, None
    with open(path, "rb", buffering=1 << 22) as f:
        order, digits, linktype = pcap_format(f)
        unpack = struct.Struct(order + "IIII").unpack
        while True:
            record = f.read(16)
            if len(record) < 16:
                break
            seconds, fraction, captured, _ = unpack(record)
            t = seconds * 1_000_000 + (fraction if digits == 6 else fraction // 1000)
            if first is None:
                first = t
            if prev is not None and t < prev:
                backwards += 1
            prev = t
            last = t if last is None else max(last, t)
            c = (t - first) // CHUNK_US
            if c >= 0:
                if c >= len(counts):
                    counts.extend([0] * (c + 1 - len(counts)))
                counts[c] += 1
            frames += 1
            f.seek(captured, 1)
    return {"first_us": first, "last_us": last, "frames": frames, "frames_backwards": backwards,
            "linktype": linktype, "chunk_frames": counts}


def label_rows(path):
    """Yield (ts, duration, packets, label, detailed) from an IoT-23 conn.log.labeled.

    Most IoT-23 logs separate the last three columns (tunnel_parents, label, detailed-label) by spaces;
    some use tabs and name the last column det_label."""
    names = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#"):
                if line.startswith("#fields"):
                    names = line.rstrip("\n").split("\t")[1:]
                    if len(names) < 23:
                        names = names[:-1] + names[-1].split()
                    names = ["detailed-label" if n == "det_label" else n for n in names]
                    index = {n: i for i, n in enumerate(names)}
                continue
            fields = line.rstrip("\n").split("\t")
            if len(fields) < len(names):
                fields = fields[:-1] + fields[-1].split()
            if len(fields) != len(names):
                raise ValueError("%s: unexpected line %r" % (path, line[:200]))
            duration = fields[index["duration"]]
            packets = 0
            for name in ("orig_pkts", "resp_pkts"):
                value = fields[index[name]]
                packets += int(value) if value not in ("-", "") else 0
            yield (float(fields[index["ts"]]), float(duration) if duration not in ("-", "") else 0.0,
                   packets, fields[index["label"]], fields[index["detailed-label"]])


def label_pass(path, first_us, n_chunks):
    """Per chunk: overlapping flows and estimated packets per flow category; totals per label."""
    flows = {c: [0] * n_chunks for c in PRIORITY[:-1]}
    packets = {c: [0.0] * n_chunks for c in PRIORITY[:-1]}
    totals, outside = {}, 0
    t0, width = first_us / 1e6, CHUNK_US / 1e6
    for ts, duration, pkts, label, detailed in label_rows(path):
        key = "%s|%s" % (label, detailed)
        totals[key] = totals.get(key, 0) + 1
        category = flow_category(label, detailed)
        k0, k1 = int((ts - t0) // width), int((ts + duration - t0) // width)
        if k1 < 0 or k0 >= n_chunks:
            outside += 1
            continue
        for k in range(max(k0, 0), min(k1, n_chunks - 1) + 1):
            flows[category][k] += 1
            if duration > 0:
                lo, hi = max(ts, t0 + k * width), min(ts + duration, t0 + (k + 1) * width)
                packets[category][k] += pkts * max(hi - lo, 0.0) / duration
            else:
                packets[category][k] += pkts
    return flows, packets, totals, outside


def stream_features(path, first_us, selected):
    """Window features of the selected chunks in one pass; see the module docstring."""
    selected_set, done, stats = set(selected), {}, {}
    current = None  # [chunk, table, window, rows, stats]

    def close(state):
        chunk, table, window, rows, st = state
        while window < WINDOWS:
            rows.append(table.read_window(window))
            window += 1
        done[chunk], stats[chunk] = rows, st

    with open(path, "rb", buffering=1 << 22) as f:
        order, digits, _ = pcap_format(f)
        unpack = struct.Struct(order + "IIII").unpack
        while True:
            record = f.read(16)
            if len(record) < 16:
                break
            seconds, fraction, captured, _ = unpack(record)
            t = seconds * 1_000_000 + (fraction if digits == 6 else fraction // 1000)
            c = (t - first_us) // CHUNK_US
            if c not in selected_set:
                if current is not None and c > current[0]:
                    close(current)
                    current = None
                f.seek(captured, 1)
                continue
            frame = f.read(captured)
            if current is not None and c != current[0]:
                if c > current[0]:
                    close(current)
                    current = None
                else:  # frame of an earlier chunk arriving late: counted in the open chunk, as the switch would
                    current[4]["late_frames"] += 1
                    if c in stats:
                        stats[c]["frames_lost_late"] += 1
                    c = current[0]
            if current is None:
                if c in done:  # earlier chunk already closed and no chunk open
                    stats[c]["frames_lost_late"] += 1
                    continue
                current = [c, switch_model.FlowTable(WINDOW_SECONDS, TTL_WINDOWS), 0, [], new_stats()]
            chunk, table, window, rows, st = current
            st["frames"] += 1
            w = min((t - (first_us + chunk * CHUNK_US)) // WINDOW_US, WINDOWS - 1)
            if w < window:  # out of time order within the chunk: counted in the current window, as the switch would
                st["out_of_order"] += 1
                w = window
            while window < w:
                rows.append(table.read_window(window))
                window += 1
            current[2] = window
            packet = switch_model.parse_flow_packet(frame)
            if packet is not None:
                timestamp = float(Decimal(seconds) + Decimal(fraction).scaleb(-digits))
                source, destination, protocol, ports, flags = packet
                table.update(w, timestamp, source, destination, protocol, ports, flags, len(frame))
                st["flow_frames"] += 1
    if current is not None:
        close(current)
    for chunk in selected:  # chunks without any frame: empty table
        if chunk not in done:
            table = switch_model.FlowTable(WINDOW_SECONDS, TTL_WINDOWS)
            done[chunk] = [table.read_window(w) for w in range(WINDOWS)]
            stats[chunk] = new_stats()
    return done, stats


def new_stats():
    return {"frames": 0, "flow_frames": 0, "late_frames": 0, "out_of_order": 0, "frames_lost_late": 0}


def process(job):
    data_root, out_dir, seed, scenario, family, role, pcap_rel, label_rel = job
    started = time.time()
    base = Path(data_root) / scenario
    pcap = base / pcap_rel
    unit = "%s/%s" % (scenario, pcap_rel)
    info = {"scenario": scenario, "family": family, "role": role, "pcap": unit,
            "pcap_sha256": sha256(pcap), "pcap_bytes": pcap.stat().st_size}
    span = span_pass(pcap)
    info.update({k: v for k, v in span.items() if k != "chunk_frames"})
    n_chunks = (span["last_us"] - span["first_us"] + 1) // CHUNK_US  # complete chunks only
    frames = (span["chunk_frames"] + [0] * n_chunks)[:n_chunks]
    info["complete_chunks"] = n_chunks
    if label_rel:
        label_path = base / label_rel
        info["labels"] = "%s/%s" % (scenario, label_rel)
        info["labels_sha256"] = sha256(label_path)
        flows, packets, totals, outside = label_pass(label_path, span["first_us"], n_chunks)
        info["label_totals"] = totals
        info["label_flows_outside_chunks"] = outside
        categories = []
        for k in range(n_chunks):
            category = next((c for c in PRIORITY[:-1] if flows[c][k] > 0), "idle")
            if role == "benign" and category not in ("benign", "idle"):
                raise ValueError("%s: malicious label in a benign capture" % unit)
            categories.append(category)
    else:  # benign capture without a label log: chunks with frames are benign traffic
        flows = packets = None
        categories = ["benign" if frames[k] > 0 else "idle" for k in range(n_chunks)]
    by_category = {}
    for k, category in enumerate(categories):
        by_category.setdefault(category, []).append(k)
    info["chunks_by_category"] = {c: len(v) for c, v in sorted(by_category.items())}

    # Seeded sample per category (benign scenarios: a quota shared over their captures, set by caller).
    quota = dict(SAMPLE_PER_CATEGORY)
    if role == "benign":
        captures = sum(1 for c in CAPTURES if c[0] == scenario)
        quota["benign"] = -(-SAMPLE_BENIGN_SCENARIO // captures)
    selected = []
    for category, chunks in sorted(by_category.items()):
        rng = random.Random("%d|%s|%s" % (seed, unit, category))
        selected += rng.sample(chunks, min(quota[category], len(chunks)))
    selected.sort()
    windows, stats = stream_features(pcap, span["first_us"], selected)

    rows = []
    for k in selected:
        row = {"unit": unit, "scenario": scenario, "family": family, "role": role, "chunk": k,
               "start_us": span["first_us"] + k * CHUNK_US, "category": categories[k],
               "frames_in_chunk": frames[k]}
        if flows is not None:
            for c in PRIORITY[:-1]:
                row["flows_%s" % c] = flows[c][k]
                row["est_pkts_%s" % c] = round(packets[c][k], 3)
        row.update({"stat_%s" % key: value for key, value in stats[k].items()})
        row.update(summarize(windows[k], switch_model.FEATURES))
        rows.append(row)
    info["sampled"] = len(selected)
    info["sampled_by_category"] = {c: sum(1 for k in selected if categories[k] == c) for c in by_category}
    info["seconds"] = round(time.time() - started, 1)
    name = unit.replace("/", "__")
    with open(Path(out_dir) / "units" / (name + ".json"), "w") as f:
        json.dump(info, f, indent=1, sort_keys=True)
    with open(Path(out_dir) / "units" / (name + ".rows.json"), "w") as f:
        json.dump(rows, f)
    with open(Path(out_dir) / "units" / (name + ".categories.json"), "w") as f:
        json.dump({"first_us": span["first_us"], "categories": categories, "frames": frames}, f)
    return unit, info["sampled"], info["seconds"]


def check_unit(job):
    out_dir, data_root, name, per_unit = job
    info = json.load(open(Path(out_dir) / "units" / name.replace(".rows.json", ".json")))
    rows = json.load(open(Path(out_dir) / "units" / name))
    candidates = [r for r in rows if r["stat_out_of_order"] == 0 and r["stat_late_frames"] == 0
                  and r["stat_frames_lost_late"] == 0 and r["stat_flow_frames"] > 0]
    rng = random.Random("self-check|" + info["pcap"])
    lines, checked, mismatches = [], 0, 0
    for row in rng.sample(candidates, min(per_unit, len(candidates))):
        pcap = Path(data_root) / info["pcap"]
        reference = switch_model.window_features(str(pcap), row["start_us"], WINDOW_SECONDS, WINDOWS, TTL_WINDOWS)
        expected = summarize(reference, switch_model.FEATURES)
        bad = [k for k, v in expected.items() if v != row[k]]
        checked += 1
        mismatches += bool(bad)
        lines.append("self-check %s chunk %d (%s): %s" % (info["pcap"], row["chunk"], row["category"],
                                                          "OK" if not bad else "MISMATCH %s" % bad[:5]))
    return lines, checked, mismatches


def self_check(out_dir, data_root, max_mb, jobs, per_unit=4):
    """Compare the single pass with switch_model.window_features() on sampled chunks of every capture
    file up to max_mb (window_features re-reads the whole file for each chunk)."""
    names = []
    for name in sorted(os.listdir(Path(out_dir) / "units")):
        if name.endswith(".rows.json"):
            info = json.load(open(Path(out_dir) / "units" / name.replace(".rows.json", ".json")))
            if info["pcap_bytes"] <= max_mb * 1024 * 1024:
                names.append(name)
            else:
                print("self-check skips %s (%d MB)" % (info["pcap"], info["pcap_bytes"] >> 20))
    checked = mismatches = 0
    with Pool(jobs) as pool:
        for lines, c, m in pool.imap_unordered(check_unit, [(out_dir, data_root, n, per_unit) for n in names]):
            print("\n".join(lines), flush=True)
            checked, mismatches = checked + c, mismatches + m
    print("self-check: %d chunks, %d with mismatches" % (checked, mismatches))
    return checked, mismatches


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("data_root")
    parser.add_argument("out_dir")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--jobs", type=int, default=6)
    parser.add_argument("--only", nargs="*")
    parser.add_argument("--self-check", action="store_true", help="only run the equivalence check on OUT_DIR")
    parser.add_argument("--self-check-max-mb", type=int, default=1000)
    args = parser.parse_args()
    if args.self_check:
        checked, mismatches = self_check(args.out_dir, args.data_root, args.self_check_max_mb, args.jobs)
        sys.exit(1 if mismatches or not checked else 0)
    os.makedirs(Path(args.out_dir) / "units", exist_ok=True)
    jobs = [(args.data_root, args.out_dir, args.seed, *c) for c in CAPTURES if not args.only or c[0] in args.only]
    jobs.sort(key=lambda j: -(Path(j[0]) / j[3] / j[6]).stat().st_size)  # largest first
    failed = 0
    with Pool(args.jobs) as pool:
        for unit, result in pool.imap_unordered(safe_process, jobs):
            if isinstance(result, str):
                failed += 1
                print("%s: FAILED %s" % (unit, result), flush=True)
            else:
                print("%s: %d chunks sampled, %.0f s" % (unit, *result), flush=True)
    sys.exit(1 if failed else 0)


def safe_process(job):
    try:
        unit, sampled, seconds = process(job)
        return unit, (sampled, seconds)
    except Exception as error:  # report and continue with the other captures
        import traceback
        return "%s/%s" % (job[3], job[6]), "%r\n%s" % (error, traceback.format_exc())


if __name__ == "__main__":
    main()

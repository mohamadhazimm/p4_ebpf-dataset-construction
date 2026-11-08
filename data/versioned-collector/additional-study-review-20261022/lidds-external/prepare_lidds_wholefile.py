#!/usr/bin/env python3
"""Turn LID-DS 2021 recordings into host + network feature rows of the paper's format.

Each recording holds the victim container's system calls (.sc), its packet capture (.pcap, Linux cooked
framing), metadata with the attack time (.json) and resource statistics. For one observation window
per recording this computes:

  host:    the paper's 18 window features (features/host_model.py) from the call-entry events of the
           victim's processes, each summarized by mean/max/sum/std/active windows -> 90 columns;
  network: the switch's 29 window features (features/switch_model.py, called unchanged) on the frames
           of the victim's Ethernet interface (loopback frames never reach a switch and are dropped),
           rewritten from cooked to Ethernet framing (frame bytes = 14 + IP bytes) -> 145 columns.

Observation: 10 s = 20 windows of 0.5 s, because attack recordings are short (the shortest has 10 s after
warm-up). Window placement is matched between classes so that timing cannot tell them apart:
  attack: the window starts 2 s before the logged attack time, clamped to the recording;
  normal: the same rule applied to a pseudo attack time drawn (seeded per recording) from the attack
          offsets after warm-up of the same scenario;
  control (normal recordings only): a second window placed near the recording end the way attack
          windows are (gap to the end drawn from the attack windows' gaps). It is never used for
          training; it shows whether the models react to the end of a recording.

    python3 -I prepare_lidds.py BUNDLE.zip OUT_DIR [--jobs 16] [--seed 42]
"""

import argparse
import bisect
import io
import json
import os
import random
import re
import site
import struct
import sys
import tempfile
import zipfile
from multiprocessing import Pool
from pathlib import Path

HERE = Path(__file__).resolve().parent
RELEASE = Path("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection")
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(RELEASE / "features"))
if site.getusersitepackages() not in sys.path:
    sys.path.append(site.getusersitepackages())

import host_model  # noqa: E402
import switch_model  # noqa: E402
from summary import summarize  # noqa: E402

import lidds_zip  # noqa: E402

WINDOW_SECONDS = 0.5
WINDOWS = 20
SPAN_US = int(WINDOWS * WINDOW_SECONDS * 1_000_000)
LEAD_US = 2_000_000           # attack starts 2 s into the window
# sysdig event names that differ from the kernel's x86_64 names; procexit and signaldeliver are not calls
ALIASES = {"pread": "pread64", "pwrite": "pwrite64", "sigreturn": "rt_sigreturn", "fstatat": "newfstatat"}
NOT_SYSCALLS = {"procexit", "signaldeliver", "switch", "container", "notification", "infra", "page_fault"}


def syscall_table():
    table = {}
    for line in open("/usr/include/x86_64-linux-gnu/asm/unistd_64.h"):
        m = re.match(r"#define __NR_(\w+)\s+(\d+)", line)
        if m:
            table[m.group(1)] = int(m.group(2))
    return table


SYSCALLS = syscall_table()


def recording_files(scenario_zip):
    """{(folder, recording): {"zip": member}} for every recording archive. Skipped: __MACOSX, .DS_Store,
    and the two unpacked folder copies of recordings that are also present as zips."""
    found = {}
    for info in scenario_zip.infolist():
        name = info.filename
        if name.startswith("__MACOSX") or info.is_dir() or not name.endswith(".zip"):
            continue
        parts = name.split("/")
        found[("/".join(parts[:-1]), parts[-1][:-4])] = {"zip": name}
    return found


def read_recording(scenario_zip, entry, base):
    inner = zipfile.ZipFile(io.BytesIO(scenario_zip.read(entry["zip"])))
    return {ext: inner.read(base + "." + ext) for ext in ("json", "sc", "pcap")}


def parse_sc(data):
    """(timestamps ns, pids, syscall ids) of call-entry events in file order; counts of dropped names."""
    times, pids, ids, dropped = [], [], [], {}
    for line in data.decode("utf-8", "replace").splitlines():
        parts = line.split(" ", 7)
        if len(parts) < 7 or parts[6] != ">":
            continue
        name = ALIASES.get(parts[5], parts[5])
        number = SYSCALLS.get(name)
        if number is None:
            dropped[parts[5]] = dropped.get(parts[5], 0) + 1
            continue
        times.append(int(parts[0]))
        pids.append(int(parts[2]))
        ids.append(number)
    if any(b < a for a, b in zip(times, times[1:])):  # keep call order per time; windows need sorted times
        order = sorted(range(len(times)), key=lambda i: times[i])
        times, pids, ids = [times[i] for i in order], [pids[i] for i in order], [ids[i] for i in order]
        dropped["_resorted"] = 1
    return times, pids, ids, dropped


def sc_span(data):
    """First and last event time (ns) of a trace, from its first and last lines."""
    text = data.decode("utf-8", "replace").strip().splitlines()
    return (int(text[0].split(" ", 1)[0]), int(text[-1].split(" ", 1)[0])) if text else (None, None)


def ethernet_pcap(data):
    """Ethernet-framed copy of a cooked (linktype 113) capture without loopback frames, and frame times."""
    if struct.unpack("<I", data[20:24])[0] != 113:
        raise ValueError("expected Linux cooked capture")
    header = bytearray(data[:24])
    header[20:24] = struct.pack("<I", 1)
    out, times, off, kept, loopback, other = [bytes(header)], [], 24, 0, 0, 0
    while off + 16 <= len(data):
        seconds, fraction, captured, original = struct.unpack_from("<IIII", data, off)
        frame = data[off + 16:off + 16 + captured]
        off += 16 + captured
        if len(frame) < 16:
            other += 1
            continue
        arphrd = struct.unpack(">H", frame[2:4])[0]
        if arphrd == 772:          # loopback device
            loopback += 1
            continue
        if arphrd != 1:            # only Ethernet devices reach a switch
            other += 1
            continue
        address_len = min(struct.unpack(">H", frame[4:6])[0], 6)
        source = frame[6:6 + address_len].ljust(6, b"\0")
        ethernet = b"\0" * 6 + source + frame[14:16] + frame[16:]
        out.append(struct.pack("<IIII", seconds, fraction, len(ethernet), max(original - 2, len(ethernet))))
        out.append(ethernet)
        times.append(seconds * 1_000_000 + fraction)
        kept += 1
    return b"".join(out), times, {"kept": kept, "loopback": loopback, "other": other}


def place(anchor_us, start_us, end_us):
    """Window start: LEAD before the anchor, clamped so that the window lies inside [start, end]."""
    return max(start_us, min(anchor_us - LEAD_US, end_us - SPAN_US))


def features(times, pids, ids, pcap_path, frame_times, window_start):
    lo = bisect.bisect_left(times, window_start * 1000)
    hi = bisect.bisect_left(times, (window_start + SPAN_US) * 1000)
    window_ns = int(WINDOW_SECONDS * 1e9)
    events = (((times[i] - window_start * 1000) // window_ns, pids[i], ids[i]) for i in range(lo, hi))
    host = summarize(host_model.window_features(events, WINDOWS), host_model.FEATURES)
    network = summarize(switch_model.window_features(pcap_path, window_start, WINDOW_SECONDS, WINDOWS),
                        switch_model.FEATURES)
    calls = hi - lo
    frames = bisect.bisect_left(frame_times, window_start + SPAN_US) - bisect.bisect_left(frame_times, window_start)
    return host, network, calls, frames


def load_recording(job):
    """Pass 1, with errors recorded instead of stopping the run."""
    try:
        return _load_recording(job)
    except Exception as error:  # a malformed recording is reported and skipped
        bundle, scenario, folder, base, entry = job
        return {"scenario": scenario, "folder": folder, "recording": base, "skipped": "error: %r" % error}


def _load_recording(job):
    """Pass 1: metadata, span and attack offset of one recording."""
    bundle, scenario, folder, base, entry = job
    z = archive(bundle, scenario)
    files = read_recording(z, entry, base)
    meta = json.loads(files["json"].decode().replace("'", '"'))
    first_ns, last_ns = sc_span(files["sc"])
    _, frame_times, _ = ethernet_pcap(files["pcap"])
    warmup = int(meta["time"]["warmup_end"]["absolute"] * 1e6)
    start = max(warmup, first_ns // 1000 if first_ns else warmup, frame_times[0] if frame_times else warmup)
    end = min(last_ns // 1000 if last_ns else start, frame_times[-1] if frame_times else start)
    attack = int(meta["time"]["exploit"][0]["absolute"] * 1e6) if meta["exploit"] and meta["time"]["exploit"] else None
    return {"scenario": scenario, "folder": folder, "recording": base, "exploit": bool(meta["exploit"]),
            "attack_us": attack, "start_us": start, "end_us": end, "recording_time": meta["recording_time"]}


_archives = {}


def archive(bundle, scenario):
    key = (bundle, scenario)
    if key not in _archives:
        for name, z in lidds_zip.scenario_archives(bundle):
            if name == scenario:
                _archives[key] = z
    return _archives[key]


def compute_row(job):
    """Pass 2, with errors recorded instead of stopping the run."""
    try:
        return _compute_row(job)
    except Exception as error:
        bundle, scenario, entry, plan = job
        return [{"scenario": scenario, "folder": plan["folder"], "recording": plan["recording"], "kind": kind,
                 "label": int(kind == "attack"), "window_start_us": start, "attack_us": plan["attack_us"],
                 "error": "recording: %r" % error} for kind, start in plan["windows"]]


def _compute_row(job):
    """Pass 2: features of the planned windows of one recording."""
    bundle, scenario, entry, plan = job
    z = archive(bundle, scenario)
    files = read_recording(z, entry, plan["recording"])
    times, pids, ids, dropped = parse_sc(files["sc"])
    data, frame_times, frame_stats = ethernet_pcap(files["pcap"])
    out = []
    with tempfile.NamedTemporaryFile(suffix=".pcap") as tmp:
        tmp.write(data)
        tmp.flush()
        for kind, window_start in plan["windows"]:
            try:
                host, network, calls, frames = features(times, pids, ids, tmp.name, frame_times, window_start)
                error = None
            except ValueError as e:  # e.g. frames out of time order inside the window
                host = network = {}
                calls = frames = 0
                error = str(e)
            out.append({"scenario": scenario, "folder": plan["folder"], "recording": plan["recording"],
                        "kind": kind, "label": int(kind == "attack"), "window_start_us": window_start,
                        "attack_us": plan["attack_us"], "calls_in_window": calls, "frames_in_window": frames,
                        "dropped_events": sum(dropped.values()), "dropped_names": dropped,
                        "loopback_frames": frame_stats["loopback"], "error": error, **host, **network})
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("bundle")
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--jobs", type=int, default=16)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--only", nargs="*", help="scenario archive names")
    parser.add_argument("--skip", nargs="*", default=[], help="scenario archive names already processed")
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=False)

    jobs = []
    entries = {}
    for scenario, z in lidds_zip.scenario_archives(args.bundle):
        if (args.only and scenario not in args.only) or scenario in args.skip:
            continue
        for (folder, base), entry in sorted(recording_files(z).items()):
            jobs.append((args.bundle, scenario, folder, base, entry))
            entries[(scenario, base)] = entry
    print("recordings:", len(jobs), flush=True)
    with Pool(args.jobs) as pool:
        recordings = pool.map(load_recording, jobs, chunksize=4)

    plans = []
    for scenario in sorted({r["scenario"] for r in recordings}):
        rows = [r for r in recordings if r["scenario"] == scenario and not r.get("skipped")]
        attacks = [r for r in rows if r["exploit"] and r["attack_us"] is not None]
        offsets = [r["attack_us"] - r["start_us"] for r in attacks]
        gaps = []
        for r in attacks:
            s = place(r["attack_us"], r["start_us"], r["end_us"])
            gaps.append(r["end_us"] - (s + SPAN_US))
        for r in rows:
            rng = random.Random("%d|%s|%s" % (args.seed, scenario, r["recording"]))
            if r["end_us"] - r["start_us"] < SPAN_US:
                r["skipped"] = "shorter than the window"
                continue
            if r["exploit"]:
                if r["attack_us"] is None:
                    r["skipped"] = "attack recording without attack time"
                    continue
                windows = [("attack", place(r["attack_us"], r["start_us"], r["end_us"]))]
            else:
                pseudo = r["start_us"] + rng.choice(offsets)
                gap = rng.choice(gaps)
                windows = [("normal", place(pseudo, r["start_us"], r["end_us"])),
                           ("end_control", max(r["start_us"], r["end_us"] - SPAN_US - gap))]
            plans.append((args.bundle, scenario, entries[(scenario, r["recording"])], {**r, "windows": windows}))
    with open(args.out_dir / "recordings.json", "w") as f:
        json.dump(recordings, f)
    print("windows planned for %d recordings" % len(plans), flush=True)

    rows = []
    with Pool(args.jobs) as pool:
        for i, out in enumerate(pool.imap_unordered(compute_row, plans, chunksize=2)):
            rows += out
            if (i + 1) % 500 == 0:
                print("  %d / %d recordings" % (i + 1, len(plans)), flush=True)
    rows.sort(key=lambda r: (r["scenario"], r["recording"], r["kind"]))
    with open(args.out_dir / "rows.json", "w") as f:
        json.dump(rows, f)
    print("rows:", len(rows), "errors:", sum(1 for r in rows if r["error"]), flush=True)


if __name__ == "__main__":
    main()

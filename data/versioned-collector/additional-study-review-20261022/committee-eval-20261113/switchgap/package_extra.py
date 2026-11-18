"""Package the 36 non-cohort captures (network attacks, network-benign, null) for the switch replays.

Same steps and checks as p4_ebpf/live_test/package_cohort.py, applied to rows 204-239 of the release
dataset: trim each capture to the observation [anchor, anchor + 20 s), sanitize every IPv4 frame with the
packager's own sanitize() (headers kept, later bytes zeroed, lengths kept, checksums recomputed), and check
that the delivered capture gives the same features under the published extractor and the switch rules.

    /usr/bin/python3 package_extra.py      # writes captures-extra/ and captures-extra.tar.gz
"""
import csv
import hashlib
import json
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, "/home/ali/Desktop/Hazim/p4_ebpf/live_test")
import common as C  # noqa: E402
import package_cohort as PC  # noqa: E402

OUT = Path(__file__).resolve().parent / "captures-extra"


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    rows, hc, nc = C.load()
    rel = PC.load_release(C.RELEASE)
    sm, crc = rel
    feats = sm.FEATURES
    exact = {0.5: PC.SwitchRules(rel, 0.5, 40), 1.0: PC.SwitchRules(rel, 1.0, 20)}
    OUT.mkdir(exist_ok=True)
    manifest, skipped, failures = [], [], []
    for i, (row, d) in enumerate(zip(rows, C.run_dirs(rows))):
        if i < 204:
            continue
        out = C.output_dir(d)
        meta = json.loads((out / "run.json").read_text())
        anchor = int(meta["sample_started_wall_us"])
        pcap = out / "packet_capture.pcap"
        head, records = PC.read_pcap(pcap)
        pub = sm.window_features(str(pcap), anchor, 0.5, 40)
        summ = PC.five(pub, feats)
        diff = max(abs(summ[k] - float(row[k])) / max(1.0, abs(float(row[k]))) for k in summ)
        if diff > 1e-9:
            failures.append((row["execution_id"], "capture does not give its dataset row", diff))
        obs = [r for r in records if 0 <= (r[0] * 1_000_000 + r[1]) - anchor < PC.OBS_US]
        tcpudp = [r for r in obs if sm.parse_flow_packet(r[3]) is not None]
        if not tcpudp:
            skipped.append({"execution_id": row["execution_id"], "category": row["category"],
                            "reason": "no IPv4 TCP/UDP packet in the observation"})
            continue
        sw = {ws: m.run(records, anchor) for ws, m in exact.items()}
        kept = []
        for sec, usec, orig, frame in obs:
            s = PC.sanitize(frame)
            if s is not None:
                if len(s) != len(frame):
                    failures.append((row["execution_id"], "sanitize changed a length"))
                kept.append((sec, usec, orig, s))
        name = row["execution_id"] + ".pcap"
        PC.write_pcap(OUT / name, head, kept)
        _, back = PC.read_pcap(OUT / name)
        for ws, m in exact.items():
            dd = PC.windows_equal(m.run(back, anchor), sw[ws], feats, rel=0)
            if dd is not None:
                failures.append((row["execution_id"], "sanitized differs under switch rules %s s" % ws, dd))
        dd = PC.windows_equal(sm.window_features(str(OUT / name), anchor, 0.5, 40), pub, feats, rel=0)
        if dd is not None:
            failures.append((row["execution_id"], "sanitized differs under switch_model", dd))
        buckets, active_1s = {}, {}
        for s_, u_, _o, f in tcpudp:
            src, dst, proto, (sp, dp), _fl = sm.parse_flow_packet(f)
            ip = lambda a: int.from_bytes(bytes(map(int, a.split("."))), "big")
            key = (proto, *sorted(((src, sp), (dst, dp))))
            b = crc(ip(src), ip(dst), sp, dp, proto)
            buckets.setdefault(b, set()).add(key)
            w1 = ((s_ * 1_000_000 + u_) - anchor) // 1_000_000
            active_1s.setdefault(w1, set()).add(b)
        first_us = kept[0][0] * 1_000_000 + kept[0][1]
        mx = max(len(v) for v in active_1s.values())
        manifest.append({"execution_id": row["execution_id"], "run_id": meta["run_id"], "category": row["category"],
                         "label": row["label"], "cv_group": row["cv_group"], "attack_type": row["attack_type"],
                         "capture": name, "sha256_original": sha(pcap), "sha256": sha(OUT / name),
                         "anchor_us": anchor, "first_kept_frame_us": first_us,
                         "anchor_offset_s": round((anchor - first_us) / 1e6, 6), "ipv4_packets": len(kept),
                         "tcpudp_packets": len(tcpudp), "flow_buckets": len(buckets),
                         "colliding_buckets": sum(1 for v in buckets.values() if len(v) > 1),
                         "max_active_buckets_1s": mx, "expect_overload": int(mx > PC.OVERLOAD_BUCKETS_1S)})
    if failures:
        for f in failures:
            print("FAIL", f)
        sys.exit(1)
    with open(OUT / "manifest.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(manifest[0])); w.writeheader(); w.writerows(manifest)
    with open(OUT / "not_replayed.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(skipped[0])); w.writeheader(); w.writerows(skipped)
    with open(OUT / "SHA256SUMS", "w") as f:
        for p in sorted(OUT.glob("*")):
            if p.name != "SHA256SUMS":
                f.write("%s  %s\n" % (sha(p), p.name))
    with tarfile.open(OUT.with_suffix(".tar.gz"), "w:gz") as t:
        t.add(OUT, arcname=OUT.name)
    print("packaged %d captures (%d overloading), skipped %d; %s" % (
        len(manifest), sum(m["expect_overload"] for m in manifest), len(skipped), OUT.with_suffix(".tar.gz")))


if __name__ == "__main__":
    main()

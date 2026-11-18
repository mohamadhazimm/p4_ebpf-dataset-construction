#!/usr/bin/env python3
"""Which of the 99 malware use the network on Triage's internet-connected sandbox, and how does that compare with
our sealed lab? Offline; reads the reports saved by triage_network_fetch.py. No fitting: detector results are the
saved out-of-fold (Table V, 10 assignments) and held-out (Table IV) predictions of committee-eval-20261113.

Definitions (fixed before the full data was looked at; one report, Gafgyt 0004b57f, had been read):
- A Triage report lists every flow of the sandbox VM, the OS's own traffic included. Background = multicast,
  broadcast and link-local destinations; destination IPs, and DNS names, seen in the reports of at least 15% of the
  99 hashes and at least 3 families; and IPs that a background name resolved to in the same report. A DNS flow is
  background when every name it asks is background (or it carries no request). Everything else is the sample's.
- Per hash, all its reports (up to 3 analyses) are pooled. A flow is answered when Triage counted a packet back
  (rx_packets > 0; a reset counts, as in our lab's definition).
- Classes, as in cue/unanswered_cue.py: silent, every flow answered, some unanswered, none answered.
- First contact: time of the sample's first flow after the earliest process start, in seconds.
- Lab side: cue/run_flows.csv (exact per-flow counts of our 20-s captures).
- Added after inspecting the first version (kept as triage_network-20261115-v1.*): the sandbox OS also talks to
  vendor services through CDNs whose addresses change, so they fell below the 15% rule. Also background: DNS
  names under VENDOR_SUFFIXES (OS, desktop and browser services), names reached from them through DNS aliases,
  every IP that any report resolved from such a name or tagged with it (DNS answer, Triage's domain tag or the TLS
  server name), and Canonical's network (AS41231).
- Fixed after a third look: DNS flows are judged only by the names they ask (the shared resolvers 1.1.1.1 and
  8.8.8.8 had passed the 15% rule and hid malware lookups), and www.google.com is never background (Kaiji, Chaos
  and DeskRAT query it to check for internet; it had passed the 15% rule too), nor are the addresses it resolved to.
- Only Linux runs are used: Triage also ran some of these Linux programs on Windows machines, where they cannot
  start, so those reports hold Windows background only. Browser services of the desktop Ubuntu image (Firefox)
  were added to the vendor list.
- A sample whose only traffic is at most 3 flows to ports 80/443 with no name outside the vendor list is labelled
  "uncertain" (such flows can still be OS traffic whose name the report does not show) and not counted as active.

    python3 triage_network_analyze.py
"""
import collections
import csv
import hashlib
import ipaddress
import json
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
RAW = HERE / "triage-reports-20261115"
EVAL = HERE.parent / "committee-eval-20261113"
sys.path.insert(0, str(EVAL))
import common as C  # noqa: E402

RUN_FLOWS = EVAL / "cue" / "run_flows.csv"
OUT = HERE / "triage_network-20261115.json"
TABLE = HERE / "triage_network-20261115.csv"
BG_SHARE, BG_FAMILIES = 0.15, 3
VENDOR_SUFFIXES = ("ubuntu.com", "canonical.com", "snapcraft.io", "snapcraftcontent.com", "launchpad.net",
                   "launchpadcontent.net", "debian.org", "fwupd.org", "gnome.org", "mozilla.com", "mozilla.org",
                   "mozilla.net", "thunderbird.net", "firefox.com", "microsoft.com", ".microsoft", "live.com",
                   "msedge.net", "googleapis.com", "gstatic.com", "pki.goog", "nodesource.com",
                   "mozgcp.net", "transcend-cdn.com", "fundraiseup.com", "fndrsp.net", "innocraft.cloud",
                   "openh264.org", "ftp.acc.umu.se", "mozilla.fastly-edge.com", "mozilla-ohttp.fastly-edge.com",
                   "ucarecdn.com", "cloudflare-dns.com", "ipv4only.arpa", "example.org")
VENDOR_ASNS = ("AS41231",)
NEVER_BACKGROUND = ("www.google.com", "google.com")


def vendor(name):
    name = (name or "").lower().rstrip(".")
    return any(name == v.lstrip(".") or name.endswith("." + v.lstrip(".")) or (v.startswith(".") and name.endswith(v))
               for v in VENDOR_SUFFIXES)


def special(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_multicast or a.is_link_local or (a.version == 4 and str(a).endswith(".255")) or str(a) == "255.255.255.255"


def split_ep(ep):
    host, _, port = ep.rpartition(":")
    return host.strip("[]"), int(port) if port.isdigit() else None


def load_reports():
    per_hash = {}
    for d in sorted(RAW.iterdir()):
        done = d / "done.json"
        if not done.exists():
            continue
        entry = json.load(open(done))
        reps = []
        for s in entry["samples"]:
            for t in s["tasks"]:
                p = d / ("%s_%s.json" % (s["id"], t["task"]))
                if t["status"] == 200 and p.exists():
                    rep = json.load(open(p))
                    plat = t.get("os") or (rep.get("analysis") or {}).get("platform") or ""
                    if not plat.startswith(("ubuntu", "debian", "linux")):
                        continue             # a Linux program cannot start on a Windows machine
                    reps.append({"id": s["id"], "task": t["task"], "os": plat, "report": rep})
        per_hash[entry["sha256"]] = {"family": entry["family"], "reports": reps}
    return per_hash


def report_parts(rep):
    net = rep.get("network") or {}
    flows = net.get("flows") or []
    asked, answers = collections.defaultdict(set), collections.defaultdict(set)
    for q in net.get("requests") or []:
        if "dns_request" in q:
            asked[q.get("flow")].update(x.get("name", "").lower().rstrip(".") for x in q["dns_request"].get("questions", []))
        if "dns_response" in q:
            for a in q["dns_response"].get("answers", []):
                answers[a.get("name", "").lower().rstrip(".")].add((a.get("value") or "").lower().rstrip("."))
    return flows, asked, answers


def alias_closure(answers, seeds):
    """Names reachable from the seed names through DNS answers (CNAME chains), and the addresses they resolve to."""
    names, todo, addrs = set(seeds), list(seeds), set()
    while todo:
        n = todo.pop()
        for v in answers.get(n, ()):
            try:
                ipaddress.ip_address(v)
                addrs.add(v)
            except ValueError:
                if v and v not in names:
                    names.add(v)
                    todo.append(v)
    return names, addrs


def main():
    per_hash = load_reports()
    rows = [r for r in csv.DictReader(open("/home/ali/Desktop/Hazim/p4-ebpf-malware-detection/dataset/features.csv"))
            if r["category"] == "malware"]
    fam = {r["sha256"]: r["family"] for r in rows}
    have = [h for h in fam if h in per_hash and per_hash[h]["reports"]]
    print("hashes with at least one behavioral report: %d of 99 (fetched %d)" % (len(have), len(per_hash)))

    # background: endpoints seen by many hashes of several families
    ip_h, ip_f, dom_h, dom_f = (collections.defaultdict(set) for _ in range(4))
    for h in have:
        for rp in per_hash[h]["reports"]:
            flows, asked, _ = report_parts(rp["report"])
            for f in flows:
                ip, _ = split_ep(f.get("dst", ""))
                ip_h[ip].add(h)
                ip_f[ip].add(fam[h])
            for names in asked.values():
                for n in names:
                    dom_h[n].add(h)
                    dom_f[n].add(fam[h])
    n = len(have)
    bg_ip = {ip for ip in ip_h if len(ip_h[ip]) >= BG_SHARE * n and len(ip_f[ip]) >= BG_FAMILIES}
    bg_dom = {d for d in dom_h if len(dom_h[d]) >= BG_SHARE * n and len(dom_f[d]) >= BG_FAMILIES}
    bg_dom |= {d for d in dom_h if vendor(d)}
    bg_dom -= set(NEVER_BACKGROUND)
    for h in have:                       # IPs that any report resolved from, or tagged with, a vendor name
        for rp in per_hash[h]["reports"]:
            flows, asked, answers = report_parts(rp["report"])
            ips = (rp["report"].get("network") or {}).get("ips") or {}
            names, addrs = alias_closure(answers, [d for d in answers if vendor(d) or d in bg_dom])
            bg_dom |= names - set(NEVER_BACKGROUND)
            bg_ip |= addrs
            for f in flows:
                ip, _ = split_ep(f.get("dst", ""))
                if (vendor(f.get("domain")) or vendor(f.get("tls_sni")) or (f.get("domain") or "").lower().rstrip(".") in bg_dom
                        or (ips.get(ip) or {}).get("asn") in VENDOR_ASNS):
                    bg_ip.add(ip)

    google = set()                       # addresses www.google.com resolved to: never background
    for h in have:
        for rp in per_hash[h]["reports"]:
            google |= alias_closure(report_parts(rp["report"])[2], list(NEVER_BACKGROUND))[1]
    bg_ip -= google

    lab = {r["execution_id"]: r for r in csv.DictReader(open(RUN_FLOWS))}
    per_sample = {}
    bg_reports = []          # per report: unicast background flows and how many got no packet back
    for h in fam:
        rec = {"family": fam[h], "reports": 0, "oses": [], "flows": 0, "answered": 0, "tcp": 0, "udp": 0,
               "dst_ips": set(), "dst_ports": collections.Counter(), "dns_names": set(), "protocols": collections.Counter(),
               "first_contact_s": None, "max_time_network_s": [], "named": set()}
        for rp in per_hash.get(h, {}).get("reports", []):
            r = rp["report"]
            rec["reports"] += 1
            rec["oses"].append(rp["os"])
            an = r.get("analysis") or {}
            if an.get("max_time_network"):
                rec["max_time_network_s"].append(an["max_time_network"] / 1000)
            starts = [p.get("started") for p in (r.get("processes") or []) if p.get("started") is not None]
            t0 = min(starts) if starts else 0
            flows, asked, answers = report_parts(r)
            bg_resolved = {v for d in bg_dom for v in answers.get(d, ())}
            bg_uni = bg_unans = 0
            for f in flows:
                ip, port = split_ep(f.get("dst", ""))
                names = asked.get(f.get("id"), set())
                if port == 53:           # DNS: judged by the names asked, whatever the resolver
                    is_bg = not names or names <= bg_dom
                else:
                    is_bg = (ip in bg_ip or ip in bg_resolved or (f.get("domain") or "").lower().rstrip(".") in bg_dom
                             or vendor(f.get("domain")))
                if special(ip):
                    continue
                if is_bg:
                    bg_uni += 1
                    bg_unans += int((f.get("rx_packets") or 0) == 0)
                    continue
                rec["flows"] += 1
                rec["answered"] += int((f.get("rx_packets") or 0) > 0)
                rec[f.get("proto", "?")] = rec.get(f.get("proto", "?"), 0) + 1
                rec["dst_ips"].add(ip)
                rec["dst_ports"][port] += 1
                rec["dns_names"] |= {x for x in names if x not in bg_dom}
                rec["protocols"].update(f.get("protocols") or [])
                rec["named"] |= {x for x in (f.get("domain"), f.get("tls_sni")) if x and not vendor(x)}
                t = (f.get("first_seen", 0) - t0) / 1000
                rec["first_contact_s"] = t if rec["first_contact_s"] is None else min(rec["first_contact_s"], t)
            bg_reports.append({"hash": h, "os": rp["os"], "unicast_background_flows": bg_uni,
                               "unanswered": bg_unans})
        fl, ans = rec["flows"], rec["answered"]
        rec["class"] = ("no_report" if not rec["reports"] else "silent" if fl == 0 else "all_answered" if ans == fl
                        else "none_answered" if ans == 0 else "some_unanswered")
        if 0 < fl <= 3 and set(rec["dst_ports"]) <= {80, 443} and not rec["dns_names"] and not rec["named"]:
            rec["class"] = "uncertain"
        del rec["named"]
        rec["scanner"] = len(rec["dst_ips"]) >= 50
        lr = lab[h]
        rec["lab"] = {"class": lr["class"], "flows": int(lr["flows"]), "unanswered": int(lr["unanswered_flows"]),
                      "packets": int(lr["packets"])}
        rec["dst_ips_n"] = len(rec["dst_ips"])
        rec["top_ports"] = [p for p, _ in rec["dst_ports"].most_common(4)]
        rec["dns_names"] = sorted(rec["dns_names"])[:8]
        rec["protocols"] = dict(rec["protocols"])
        del rec["dst_ips"], rec["dst_ports"]
        per_sample[h] = rec

    # detectors per group (saved predictions)
    rows240, _, _ = C.load()
    idx = {r["sha256"]: i for i, r in enumerate(rows240) if r["category"] == "malware"}
    z = np.load(C.CACHE / "cv_published_k40.npz", allow_pickle=False)
    flag_v = {d: (z[d] >= 0.5).mean(axis=0) for d in C.DETECTORS}       # share of the 10 assignments flagging each row
    hz = np.load(C.CACHE / "heldout_k40.npz", allow_pickle=False)
    te = list(hz["te"])
    flag_iv = {d: dict(zip(te, (hz["%s__rf42" % d] >= 0.5).astype(float))) for d in C.DETECTORS}

    def group_scores(members):
        ii = [idx[h] for h in members]
        out = {"n": len(ii), "table_v_recall": {d: float(np.mean([flag_v[d][i] for i in ii])) if ii else None
                                                for d in C.DETECTORS}}
        t = [i for i in ii if i in flag_iv["host"]]
        out["table_iv_test_n"] = len(t)
        out["table_iv_recall_rf42"] = {d: float(np.mean([flag_iv[d][i] for i in t])) if t else None for d in C.DETECTORS}
        return out

    groups = collections.defaultdict(list)
    for h, rec in per_sample.items():
        groups["triage:" + rec["class"]].append(h)
        groups["lab:" + rec["lab"]["class"]].append(h)
        groups["triage_active:%s|lab:%s" % (rec["class"] not in ("silent", "no_report", "uncertain"),
                                            rec["lab"]["class"] != "silent")].append(h)
    for h, rec in per_sample.items():
        if rec["class"] in ("silent", "no_report", "uncertain"):
            continue
        late = rec["first_contact_s"] is not None and rec["first_contact_s"] > 20
        groups["triage_active_first_contact_%s" % ("after_20s" if late else "within_20s")].append(h)
    cross = collections.Counter((rec["class"], rec["lab"]["class"]) for rec in per_sample.values())

    out = {"definitions": __doc__, "background": {"share": BG_SHARE, "families": BG_FAMILIES,
                                                 "ips": sorted(bg_ip), "dns_names": sorted(bg_dom)},
           "hashes_with_reports": len(have),
           "background_traffic_per_report": {
               "reports": len(bg_reports),
               "with_unanswered_unicast_flow": sum(1 for b in bg_reports if b["unanswered"] > 0),
               "unicast_flows": sum(b["unicast_background_flows"] for b in bg_reports),
               "unanswered_unicast_flows": sum(b["unanswered"] for b in bg_reports),
               "by_os": {o: {"reports": sum(1 for b in bg_reports if b["os"] == o),
                             "with_unanswered": sum(1 for b in bg_reports if b["os"] == o and b["unanswered"] > 0)}
                         for o in sorted({b["os"] or "?" for b in bg_reports})}},
           "triage_class_counts": collections.Counter(r["class"] for r in per_sample.values()),
           "cross_triage_vs_lab": {"%s|%s" % k: v for k, v in sorted(cross.items())},
           "groups": {g: group_scores(m) for g, m in sorted(groups.items())},
           "per_sample": per_sample}
    out["inputs_sha256"] = {"run_flows.csv": hashlib.sha256(RUN_FLOWS.read_bytes()).hexdigest(),
                            "cv_published_k40.npz": hashlib.sha256((C.CACHE / "cv_published_k40.npz").read_bytes()).hexdigest(),
                            "heldout_k40.npz": hashlib.sha256((C.CACHE / "heldout_k40.npz").read_bytes()).hexdigest()}
    OUT.write_text(json.dumps(out, indent=1, default=lambda o: dict(o) if isinstance(o, collections.Counter) else str(o)))
    with open(TABLE, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["sha256", "family", "triage_reports", "triage_class", "triage_flows", "triage_answered", "triage_dst_ips",
                    "triage_top_ports", "triage_first_contact_s", "triage_dns_names", "lab_class", "lab_flows",
                    "lab_unanswered", "table_v_host", "table_v_network", "table_v_stacked"])
        for h, r in sorted(per_sample.items(), key=lambda kv: (kv[1]["family"], kv[0])):
            i = idx[h]
            w.writerow([h, r["family"], r["reports"], r["class"], r["flows"], r["answered"], r["dst_ips_n"],
                        " ".join(map(str, r["top_ports"])), "" if r["first_contact_s"] is None else round(r["first_contact_s"], 1),
                        " ".join(r["dns_names"]), r["lab"]["class"], r["lab"]["flows"], r["lab"]["unanswered"],
                        round(flag_v["host"][i], 2), round(flag_v["network"][i], 2), round(flag_v["stacked"][i], 2)])

    print("background IPs", len(bg_ip), "names", sorted(bg_dom)[:12])
    print("Triage classes:", dict(out["triage_class_counts"]))
    print("sandbox OS background:", {k: v for k, v in out["background_traffic_per_report"].items() if k != "by_os"})
    print("Triage x lab:")
    for k, v in sorted(cross.items()):
        print("   %-16s lab %-16s %3d" % (k[0], k[1], v))
    for g, s in out["groups"].items():
        print("%-48s n=%2d  Table V recall host %.2f net %.2f concat %.2f stacked %.2f | IV test n=%d" % (
            g, s["n"], *[s["table_v_recall"][d] for d in ("host", "network", "concat", "stacked")], s["table_iv_test_n"]))
    print("wrote", OUT, TABLE)


if __name__ == "__main__":
    main()

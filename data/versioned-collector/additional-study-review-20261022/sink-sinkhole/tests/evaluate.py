#!/usr/bin/env python3
"""Check the output of netns_test.sh. Usage: python3 -I tests/evaluate.py OUTDIR
Writes OUTDIR/evaluation.json and exits 1 if any assertion failed."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

REDIRECTED_CHECKS = {"dns_to_other_resolver_redirected", "http_to_other_address_redirected",
                     "https_to_other_address_redirected", "tcp_other_port_silent_catchall",
                     "tcp_irc_port_silent_catchall"}
UNCHANGED_CHECKS = {"default_route_via_sink", "dns_to_sink_unchanged", "http_to_sink_unchanged",
                    "tcp_closed_port_on_sink_refused", "udp_closed_port_on_sink_refused"}


def main():
    out = Path(sys.argv[1])
    results = []

    def expect(name, condition, detail=""):
        results.append({"assertion": name, "ok": bool(condition), "detail": detail})

    def text(name):
        path = out / name
        return path.read_text() if path.exists() else ""

    def records(path):
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    log = records(out / "log" / "catchall.jsonl")
    expect("finished", text("finished.txt").strip() == "done")

    render = text("render-nft.txt")
    for piece in ("meta pkttype host", "ip saddr 10.0.0.10", "udp dport 53 counter redirect",
                  "tcp dport 443 counter redirect", "tcp dport 1-65535 counter redirect to :64999",
                  "udp dport 1-65535 counter redirect to :64999", "10.0.0.255", "224.0.0.0/4"):
        expect("render-nft has " + piece, piece in render)

    for backend in ("nft", "iptables"):
        marker = text(backend + "-marker.txt").strip()
        expect(backend + ": on succeeded", "ON:" in text(backend + "-on.txt"), text(backend + "-on.txt")[-300:])
        expect(backend + ": status OK while on", "overall:            OK" in text(backend + "-status-on.txt"))
        on = json.loads(text(backend + "-check-on.json") or "{}")
        expect(backend + ": guest check passes while on", on.get("passed") is True,
               on.get("required_failed"))
        by_name = {item["name"]: item for item in on.get("checks", [])}
        expect(backend + ": udp to other port gets no answer", by_name.get("udp_other_port_no_answer", {}).get("ok"))
        off = json.loads(text(backend + "-check-off.json") or "{}")
        failed = set(off.get("required_failed", []))
        expect(backend + ": guest check fails while off, only on the redirected checks",
               off.get("passed") is False and failed == REDIRECTED_CHECKS, sorted(failed))
        off_names = {item["name"]: item for item in off.get("checks", [])}
        expect(backend + ": unchanged checks pass while off",
               all(off_names.get(name, {}).get("ok") for name in UNCHANGED_CHECKS))
        expect(backend + ": status off after off", "overall:            off" in text(backend + "-status-off.txt"))
        after = text(backend + "-rules-after-off.txt")
        expect(backend + ": no sinkhole rules after off", "hazim_sinkhole" not in after and "HAZIM_SINKHOLE" not in after)

        mine = [r for r in log if r.get("type") in ("tcp", "udp") and marker in r.get("preview", "")
                and (marker + "off") not in r.get("preview", "")]
        check_tcp = {r["orig_dst"]: r for r in mine if r["type"] == "tcp" and " tcp " in r["preview"]}
        for dst in ("192.0.2.44:4444", "192.0.2.45:6667"):
            rec = check_tcp.get(dst, {})
            expect("%s: catch-all logged %s with the original address" % (backend, dst),
                   rec.get("redirected") is True and rec.get("src", "").startswith("10.0.0.10:")
                   and rec.get("bytes_in", 0) > 0, rec)
        expect(backend + ": catch-all logged the udp datagram",
               any(r["type"] == "udp" and r["orig_dst"] is None for r in mine))
        burst = json.loads(text(backend + "-burst.json") or "{}")
        expect(backend + ": burst of 60 connections all silent", burst.get("count") == 60 and burst.get("silent") == 60,
               {k: burst.get(k) for k in ("count", "silent")})
        sent = {item["dst"]: item.get("sent") for item in burst.get("results", [])}
        logged = {r["orig_dst"]: r for r in mine if r["type"] == "tcp" and " burst " in r["preview"]}
        expect(backend + ": burst logged with exact original addresses and byte counts",
               set(logged) == set(sent) and all(logged[d]["bytes_in"] == sent[d] and logged[d]["redirected"]
                                                for d in sent), "%d of %d" % (len(logged), len(sent)))
        expect(backend + ": nothing logged for the off run",
               not any((marker + "off") in r.get("preview", "") for r in log))
        expect(backend + ": find lists the marker", text(backend + "-find.txt").count(marker) >= 3)

    refusals = text("refusals.txt").split("\n")
    for case in ("forwarding-on", "port-in-use", "inetsim-down"):
        expect("on refuses: " + case, ("ok " + case) in refusals, text("refuse-%s.txt" % case)[-200:])
    after = text("rules-after-refusals.txt")
    expect("no rules left after refusals", "hazim_sinkhole" not in after and "HAZIM_SINKHOLE" not in after)

    unit = records(out / "unit.jsonl")
    client = json.loads(text("unit-client.json") or "{}")
    tcp_logged = [r for r in unit if r.get("type") == "tcp"]
    summaries = [r for r in unit if r.get("type") == "summary"]
    tcp_total = sum(s["counts"].get("tcp", 0) for s in summaries)
    udp_total = sum(s["counts"].get("udp", 0) for s in summaries)
    expect("unit: start and stop records", unit and unit[0].get("type") == "start" and unit[-1].get("type") == "stop")
    expect("unit: summaries count all 31 tcp connections and the udp datagram", tcp_total == 31 and udp_total == 1,
           {"tcp": tcp_total, "udp": udp_total})
    expect("unit: record budget limits detailed records", 0 < len(tcp_logged) <= 12, len(tcp_logged))
    expect("unit: direct connections are not marked redirected", all(r["redirected"] is False for r in tcp_logged))
    idle = [r for r in tcp_logged if r.get("end") == "idle"]
    expect("unit: idle connection closed by the listener after about 1 s without data",
           client.get("idle_data") == "" and 0.8 <= client.get("idle_closed_after_s", 0) <= 2.5, client)
    expect("unit: idle close recorded", len(idle) <= 1)  # may fall outside the record budget
    expect("unit: final summary written", any(s.get("final") for s in summaries))

    unit_file = out / "hazim-sinkhole-catchall.service"
    if shutil.which("systemd-analyze") and unit_file.exists():
        verify = subprocess.run(["systemd-analyze", "verify", str(unit_file)], capture_output=True, text=True)
        relevant = [line for line in (verify.stdout + verify.stderr).splitlines()
                    if "hazim-sinkhole-catchall" in line]
        expect("systemd-analyze verify: no complaints about the unit", not relevant, relevant)

    failed = [r for r in results if not r["ok"]]
    (out / "evaluation.json").write_text(json.dumps({"assertions": len(results), "failed": len(failed),
                                                     "results": results}, indent=2) + "\n")
    for r in results:
        print(("PASS " if r["ok"] else "FAIL ") + r["assertion"] + ("" if r["ok"] else "  -> %s" % (r["detail"],)))
    print("%d assertions, %d failed" % (len(results), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

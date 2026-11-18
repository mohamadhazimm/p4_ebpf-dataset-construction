#!/usr/bin/env python3
"""Behaviour check of the network-active benign batch: did each benign program do what its task was designed to do,
in the guest, against the real servers? Reported, never used to exclude a row (the base rule keeps every accepted
session whose program ran).

Per benign session, from the analysis (analyze_session_lab.py's injected_flows: the program's own connections,
attributed by the socket tracer) and the program's own output (injected.stdout / injected.stderr in out.tgz):
  networked   at least one connection
  answered    every connection got a reply packet
  ports       the destination ports are the task's (protocol "destinations"; names resolve to the DNS redirect address)
  receipt     the client reports success: a JSON receipt with successful operations (webfetch, netpoll, labtransport,
              python-client), "CONNECTION ESTABLISHED"/"CONNECTED(" (openssl), "Connected to" (telnet); curl and wget
              run silently (-s / -q), so for them the connections stand in for the receipt
The test server's log (phases/test-server/server.log) gives the requests it served per client port; the INetSim and
dnsmasq logs are in phases/sink-logs.

  /usr/bin/python3 check_netbenign_behaviour.py runs/<batch>
"""
import json
import sys
import tarfile
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLS = {"webfetch", "netpoll", "labtransport", "python-client"}


def member(tgz, name):
    try:
        with tarfile.open(tgz) as t:
            return t.extractfile(name).read().decode(errors="replace")
    except (KeyError, OSError, tarfile.TarError, AttributeError):
        return ""


def receipt_ok(program, out, err):
    text = out + err
    if program in TOOLS:
        try:
            r = json.loads(out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return False, "no receipt"
        if program == "netpoll":
            ok = sum(a.get("ok", 0) for a in r.get("activities", []))
            bad = sum(a.get("failed", 0) for a in r.get("activities", []))
        else:
            ok = r.get("ok", r.get("OK", r.get("answers", 0)))
            bad = r.get("Failed", r.get("rounds", ok) - ok if "rounds" in r else 0)
        return ok > 0, "ok %s failed %s" % (ok, bad)
    if program == "openssl":
        return ("CONNECTION ESTABLISHED" in text or "CONNECTED(" in text), "openssl output"
    if program == "telnet":
        return "Connected to" in text, "telnet output"
    return None, "silent client"


def main():
    att = Path(sys.argv[1]).resolve()
    protocol = json.loads((att / "protocol.json").read_text())
    analysis = {s["sid"]: s for s in json.loads((att / "analysis.json").read_text())["sessions"]}
    server = Counter()
    slog = att / "phases" / "test-server" / "server.log"
    if slog.is_file():
        for line in slog.read_text().splitlines():
            if line.startswith("{") and '"remote"' in line:
                r = json.loads(line)
                server[r.get("port")] += 1
    rows, summary = [], Counter()
    for s in protocol["sessions"]:
        if s["kind"] != "benign":
            continue
        a = analysis.get(s["sid"], {})
        f = a.get("injected_flows") or {}
        flows, answered = f.get("flows", 0), f.get("answered", 0)
        want = sorted({int(d.rsplit(":", 1)[1]) for d in s.get("destinations", [])})
        ports = sorted(f.get("ports") or [])
        out = member(att / "sessions" / s["sid"] / "out.tgz", "./injected.stdout")
        err = member(att / "sessions" / s["sid"] / "out.tgz", "./injected.stderr")
        rok, why = receipt_ok(s.get("program"), out, err)
        row = {"sid": s["sid"], "name": s["name"], "status": a.get("status", "missing"),
               "batch_control": bool(s.get("batch_control")), "flows": flows, "answered": answered,
               "flows_20s": f.get("flows_20s"), "first_contact_s": f.get("first_contact_s"), "ports": ports,
               "expected_ports": want, "remotes": f.get("remotes"), "dns_relayed": f.get("dns_relayed"),
               "receipt": rok, "receipt_note": why, "stderr_tail": err.strip()[-200:]}
        row["networked"] = flows > 0
        row["all_answered"] = flows > 0 and answered == flows
        row["ports_ok"] = (not want) or (set(ports) - {53}) == (set(want) - {53})   # DNS may be its own or relayed
        row["as_designed"] = bool(row["status"] == "accepted" and row["networked"] and row["all_answered"]
                                  and row["ports_ok"] and rok is not False)
        rows.append(row)
        summary["as_designed" if row["as_designed"] else "not_as_designed"] += 1
    result = {"attempt": att.name, "benign_sessions": len(rows), "summary": dict(summary),
              "test_server_requests_by_port": dict(server), "not_as_designed": [r for r in rows if not r["as_designed"]],
              "rows": rows}
    (att / "analysis").mkdir(exist_ok=True)
    (att / "analysis" / "behaviour.json").write_text(json.dumps(result, indent=1))
    for r in rows:
        print("%-4s %-30s %-9s flows %4s answered %4s ports %-18s receipt %-5s %s" % (
            "ok" if r["as_designed"] else "NO", r["name"][:30], r["status"], r["flows"], r["answered"],
            ",".join(map(str, r["ports"]))[:18], r["receipt"], r["receipt_note"][:40]))
    print(json.dumps({"summary": dict(summary), "test_server_requests_by_port": dict(server)}))


if __name__ == "__main__":
    main()

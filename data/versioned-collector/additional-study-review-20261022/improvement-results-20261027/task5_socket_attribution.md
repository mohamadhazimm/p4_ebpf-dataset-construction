# Task 5 — Socket-level flow-to-process attribution: design (offline)

## Current limitation
P4 flow records (5-tuple) are joined to the monitored process only by TIME
WINDOW (paper: "flows are linked to processes by time window, not socket").
Consequences: a specific flow cannot be attributed to a specific process;
ambient/background traffic can leak into a run's P4 vector; and the fusion is
one aggregate P4 vector per run, which is why there is no per-flow
host-weak/net-strong complementarity to exploit.

## What the collector already has
`src/malware_runner.py` hooks connect / accept / accept4 / socket and, on
connect, decodes the REMOTE IPv4 address and port per PID (`record_activity
("connect", ip, port)`, decode near line ~651 and ~1293); `host_connect_total`
and per-process remote ip/port sets already exist. The PCAP/P4 side already
decodes full 5-tuples (src/dst IP, protocol, src/dst port). So one side of the
join exists.

## Design
1. eBPF side: on connect/accept EXIT, emit a socket-ownership record:
   (pid, tid, comm, local_ip:local_port, remote_ip:remote_port, direction, ts).
   The missing piece is the LOCAL ephemeral port — connect currently logs only
   the remote endpoint. Read it from the sock struct (inet_sport / sk_num) at
   the hook exit, or via a getsockname probe. accept gives the inbound peer.
2. Build a per-run socket table: 5-tuple → owning PID (+ first/last ts).
3. Offline: join each P4 flow to its owning PID by exact 5-tuple, using the
   time window only as a tiebreaker for ephemeral-port reuse.
4. Fusion becomes per-process: attach each process's own flows' P4 features to
   that process's host features → a true per-entity hybrid vector, instead of
   one time-aligned aggregate.

## Benefits
- Drops flows not owned by the monitored process tree → removes the ambient-
  traffic contamination the hybrid-reversal investigation flagged.
- Enables genuine per-flow complementarity: the mechanism by which the hybrid
  could beat host on general malware, not just on the flood pool.
- Makes the "hybrid" claim mechanistically honest (flows ARE attributed, not
  co-occurring in time).

## Cost / risk
- Collector schema change → NEW runner schema + SHA + the project's mandatory
  compatibility analysis; cannot retrofit existing `.21` captures, so it needs
  re-collection to populate the new records.
- eBPF work to read sk fields (BTF-dependent); INetSim/NAT may rewrite peers;
  port reuse needs the ts tiebreaker.
- Medium–high engineering. Best scoped as the next collector revision, not a
  same-day change. This design is the deliverable.

# Session lab with real internet (benign programs only)

A separate copy of the session lab for benign programs that need the real internet. The isolated lab and its malware
drivers are unchanged.

What changes against the isolated lab:

- **No Sink, no INetSim, no sinkhole, no fake DNS.** The guest's NIC 1 is on VirtualBox NAT with DHCP.
- **Network capture** is VirtualBox's NIC trace of NIC 1, written on the host (`sessions/<sid>/trace.pcap`). It
  has no drop counter.
- **No generated background.** `guest/bg.sh` only waits for the session's length.
- **Clock probes** go to the NAT gateway 10.0.2.2, UDP port 9.
- **Benign only.** A plan may hold benign, null and background-only sessions. An archive whose program is a known
  sample is refused.

The in-kernel host monitor, the socket tracer and the session timing are the same: `guest/enter.sh` and
`guest/session.sh` are byte-identical copies of `../guest/`.

## Files

| File | What it does |
|---|---|
| `make_internet_snapshot.py` | Builds the clean real-internet snapshot (see below) and records it in `snapshot.json`. |
| `guest_prep.sh`, `guest_scrub.py` | Run as root in the guest while it is still isolated: delete the staged lab inputs and every sample-like file, check again, switch `enp0s3` to DHCP. |
| `guest_verify.py` | Checks address, route, DNS and HTTPS on NAT, and that Downloads is empty. |
| `run_session_internet.py` | The driver: freeze a plan, run it. |
| `example_plan.json` | Five sessions: background-only, HTTPS polling, a 50 MB download, DNS lookups, a null program. |

## Why a new snapshot

Every snapshot of this VM descends from `clean-malware-training-staged-20261017`, so its disk holds the staged
sample sets (in `~/Downloads`). `make_internet_snapshot.py`:

1. restores the quiet baseline (`clean-final-quiet-v19-...`), still on the isolated network;
2. deletes everything in `~/Downloads` and every file under `/home`, `/root`, `/tmp`, `/var/tmp`, `/opt`, `/srv`,
   `/mnt`, `/media`, `/usr/local` that matches one of 6,365 known sample or sample-archive SHA-256 values, has a
   sample-style name, or is an ELF file or archive in a user folder;
3. scans again (nothing may be left);
4. switches NIC 1 to NAT, boots, and checks the internet;
5. takes `clean-internet-benign-<time>`;
6. puts the VM back on `clean-tls-paired-2026-10-19` (isolated).

The scrub report is kept in `snapshot-runs/<time>/prep-report/`. Running it discards the guest's current state, as
every session run does.

## Commands

Run these from this folder:

```bash
/usr/bin/python3 make_internet_snapshot.py --run --approval "<your words>"        # once
/usr/bin/python3 run_session_internet.py --freeze-only --plan my_plan.json         # prints attempt and SHA
setsid nohup /usr/bin/python3 -u run_session_internet.py --run-all \
  --attempt runs/<ID> --protocol-sha256 <SHA> > runs/<ID>.log 2>&1 < /dev/null &
```

Plan format: see the docstring of `run_session_internet.py` and `example_plan.json`. A session runs one program as
the guest user, started at `t_inject_s` (seeded if not given) inside a 180-s session.

## Not done yet

The analysis scripts (`../analyze_session_lab.py` and the base builder) read `sink.pcap` and expect the isolated
guest address 10.0.0.10. They need a small change to read `trace.pcap` with guest address 10.0.2.15.

# Passive sinkhole for the lab Sink

A switchable "fake internet" layer for the Sink VM. When it is on, connections that the guest
makes to **any address other than the Sink** are answered by the Sink instead of being dropped:

- **DNS, HTTP and HTTPS** (udp/tcp 53, tcp 80, tcp 443) go to the INetSim services that already
  run on the Sink. A sample that uses a hard-coded resolver such as 8.8.8.8 now gets INetSim's
  answer (10.0.0.1).
- **Every other TCP or UDP port** goes to a silent catch-all listener on the Sink. It completes the
  TCP handshake, logs who connected, which address and port they originally dialed, and the first
  bytes they sent, and **never sends anything back**. IRC ports go here too, on purpose: no
  protocol is spoken to the samples.

Traffic addressed to the Sink itself (10.0.0.1) is not touched, so today's lab behaviour,
including the collector's capture probes to 10.0.0.1:80, stays exactly as it is. Nothing is
persistent: `off`, or a reboot of the Sink, removes the rules and stops the listener.

Why: the C2 viability probes of 2026-10-25 showed only 11–23 wire frames for every reverse shell
and beacon, because their connections to hard-coded C2 addresses went nowhere. With the sinkhole,
their handshakes, beacons and retries should reach the wire where the switch features can see
them. That is a hypothesis until a collection measures it.

## Files

| File | Runs on | What it does |
| --- | --- | --- |
| `sinkhole.sh` | Sink, as root | `install`, `on`, `off`, `status [--find MARKER]`, `uninstall` |
| `sinkhole_catchall.py` | Sink (installed by `install`) | the silent listener; stdlib Python, runs unprivileged under systemd |
| `push_to_sink.sh` | host, by you | copies the two files above into the Sink and checks their hashes; asks for the Sink password |
| `sinkhole_guest_check.py` | guest, as the normal user | benign check of the result; only contacts the Sink and RFC 5737 documentation addresses |
| `run_guest_check.py` | host | boots the guest's quiet baseline, runs the check, restores the original snapshot (a VM operation: needs an approval) |
| `tests/` | host | local test in private network namespaces (no VM, no real network) |

## The Sink (facts measured 2026-11-12)

- REMnux on Ubuntu 24.04, user `remnux` (same password as the guest's, passwordless sudo),
  Guest Additions 7.1.2, one NIC on `malnet`, 10.0.0.1/24, no default route, forwarding off,
  no firewall rules, no `ufw`.
- **DNS is dnsmasq, not INetSim.** `/etc/dnsmasq.d/malnet.conf` listens on 10.0.0.1, answers
  every name with 10.0.0.1 and logs to `/var/log/inetsim/dnsmasq.log`. INetSim's own DNS service
  dies right after it starts on this machine; INetSim provides HTTP, HTTPS, SMTP(S), POP3(S),
  FTP(S). Where this README says INetSim for DNS, read dnsmasq.
- **Neither starts at boot.** After any Sink restart or snapshot restore, start both by hand:
  `sudo systemctl start inetsim && sudo dnsmasq --conf-file=/etc/dnsmasq.d/malnet.conf`
  The outage of 2026-11-06 was exactly this: the Sink was restored to `sink-pre-gafgyt-20261016`
  at 16:00:21 UTC and neither service was started again until 2026-11-12.
- **Do not take a live snapshot of the Sink.** On 2026-11-12 VirtualBox 7.2 tried for two hours
  and gave up ("SSM: Giving up: Too many passes!"). Power the Sink off first if a snapshot is
  needed; an offline snapshot only records the disk and is quick.

## Before you start

1. If you want a rollback point beyond `sink-pre-gafgyt-20261016` and `hazim-sinkhole uninstall`,
   take an **offline** snapshot (power the Sink off first; see above).
2. Make sure INetSim and dnsmasq run (command above). `on` refuses to start while nothing
   listens on udp/53 and tcp/80.

## 1. Copy the files to the Sink (host terminal)

```bash
cd vbox-runs/hybrid-rf-study-20261010/data/versioned-collector/additional-study-review-20261022/sink-sinkhole
bash push_to_sink.sh remnux
```

It checks that the Sink is running and on `malnet` only, asks for the password (not echoed, kept
in a private temporary file, deleted afterwards), copies `/tmp/hazim-sinkhole.sh` and
`/tmp/hazim-sinkhole_catchall.py` into the Sink and compares their hashes. Guest Control works on
the Sink (it answered a logon attempt on 2026-10-25), so this needs only a valid Sink account. If
it fails, you can paste the two files into the Sink any other way; keep the names above.

## 2. Install and switch on (Sink console)

```bash
sudo bash /tmp/hazim-sinkhole.sh install    # copies files, writes the systemd unit, records the current state
sudo hazim-sinkhole on
sudo hazim-sinkhole status                  # ends with "overall: OK"
```

`install` saves the Sink's current addresses, routes, listening sockets, firewall rules and the
INetSim config hash under `/var/lib/hazim-sinkhole/before-<time>/`; it switches nothing on.
`on` refuses if forwarding is enabled, if INetSim is not listening, if the listener port (64999)
is taken, or if `ufw` is active (it prints the two `ufw allow` lines needed). It uses `nft` when
present, otherwise `iptables`; both were tested.

## 3. Check it from the guest (host; needs your approval)

```bash
/usr/bin/python3 run_guest_check.py --approval "<your words>"
```

This restores the guest's quiet baseline `clean-final-quiet-v19-20261024T150104720304Z`, boots it
headless, runs `sinkhole_guest_check.py` as `csci` (no sudo), copies the result to
`guest-check/<time>/`, then powers the guest off on `clean-tls-paired-2026-10-19`. It runs no
sample and does not touch the Sink. It takes about 2–3 minutes. Expected result with the sinkhole on:

| Check | Expected |
| --- | --- |
| default route via the Sink | `default via 10.0.0.1` |
| DNS to the Sink / to 192.0.2.53 | both answer `10.0.0.1` |
| HTTP to 198.51.100.7, HTTPS to 203.0.113.9 | `200` from INetSim |
| TCP to 192.0.2.44:4444 and 192.0.2.45:6667 | connects, then silence |
| UDP to 192.0.2.46:40000 | silence (arrival shows in the Sink log) |
| HTTP to 10.0.0.1, closed TCP/UDP ports on 10.0.0.1 | `200`, refused, refused (unchanged) |

With the sinkhole off, exactly the five redirected checks fail (time out) and the rest pass; the
local test confirms that. Then, on the Sink, the runner prints the marker to look for:

```bash
sudo hazim-sinkhole status --find <marker>   # three records: tcp 192.0.2.44:4444, tcp 192.0.2.45:6667, udp
```

## Turning it off

```bash
sudo hazim-sinkhole off          # rules removed, listener stopped, logs kept
sudo hazim-sinkhole uninstall    # also removes the unit and the files (keeps logs and saved state)
```

## What it changes for a collection

- **A separate dataset variant.** Every sample sees a different network with it on. Never mix
  captures taken with and without the sinkhole; collect benign controls under the same setting
  (including beacon-like benign), or network activity alone becomes a shortcut.
- **Scanners and floods get answers too.** Connections to random addresses now complete, so a
  scanner sends more traffic than before. Under a flood the Sink's connection-tracking table can
  fill (the Sink's kernel log says `nf_conntrack: table full`); excess packets are then dropped.
  Everything stays on `malnet`.
- **Not covered:** ICMP to other addresses (still unanswered); addresses inside 10.0.0.0/24 other
  than the Sink (the guest asks for them directly and gets no reply); the guest's own Docker
  subnets 172.17.0.0/16 and 172.28.0.0/24 (they never leave the guest).
- **Containment is unchanged.** The Sink has one NIC on `malnet`; the rules only redirect to the
  Sink's own address; `on` refuses when forwarding is on.

## Log records

`/var/log/hazim-sinkhole/catchall.jsonl`, one JSON object per line:

- `tcp`: `t_open`, `t_close`, `src`, `orig_dst` (address and port the sample dialed), `redirected`,
  `bytes_in`, `first_data_s`, `end` (`eof`, `idle`, `max_hold`, `reset`, `stopped`), and the first
  256 bytes as `head_hex`, `head_sha256`, `preview` (printable characters).
- `udp`: `t`, `src`, `bytes_in`, the same head fields. `orig_dst` is null: the original destination
  of a redirected UDP datagram is not available on the Sink; the guest-side capture has it.
- `summary` every 10 s: all counts, including connections that exceeded the record budget
  (200 detailed records per second, 512 MB of log).
- The Sink's clock may differ from the host's; match runs by marker, guest source port, or time.

INetSim logs the redirected DNS/HTTP/HTTPS in its own logs, seeing the Sink as the destination.

## How it was tested here

`bash tests/netns_test.sh OUT && /usr/bin/python3 -I tests/evaluate.py OUT` builds two private
network namespaces joined by a veth pair (Sink 10.0.0.1, guest 10.0.0.10 with its default route
via the Sink, a stand-in INetSim for DNS/HTTP/HTTPS) and runs the real `sinkhole.sh` with both
backends, the real listener and the real guest check: 51 assertions, all passed
(`tests/runs/20261112T192326Z/evaluation.json`). The listener ran there as a plain background
process; the systemd path and the `ufw` refusal were not exercised (the unit file passes
`systemd-analyze verify`). `run_guest_check.py --self-test` checks the VM call order and the
cleanup on failure with a fake VirtualBox.

On the real Sink (2026-11-12): `install`, `on`, `status` and `off` passed. `on` chose nft, mapped
udp/53 and tcp/53 (dnsmasq) and tcp/80 and tcp/443 (INetSim), and the listener ran under systemd
as its own dynamic user (about 7.5 MB); `status` said `overall: OK`; `off` left no nft tables.
The sinkhole is installed and **off**. The end-to-end check from the guest (step 3) has not run yet.

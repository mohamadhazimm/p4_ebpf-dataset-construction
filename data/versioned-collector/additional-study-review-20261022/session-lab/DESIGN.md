# Session lab: attacks injected into normal activity, network recorded outside the guest

Status: design and pilot build (2026-11-15). Nothing collected yet. A new, separate dataset; the paper's 240-row
dataset and every published number stay as they are.

## Why

Five problems of the current lab, all measured:

| Problem | Evidence |
|---|---|
| Malware sees our collector and quits | 5 held-out Tsunami bots quit when our tools run in the guest and connect within 1 s when they do not (`../sensor-visibility/`) |
| Only malware leaves connections unanswered | 42 of 52 sending malware vs 0 of 43 sending benign; the network detector leans on it (`../committee-eval-20261113/` §2.7) |
| Benign and malware came from separate batches | collection batch alone scores 0.93 on the 5-minute cohort |
| Benign programs are short and alone | lifetime alone scored 0.83-0.87 on the first 5-minute cohort |
| Some malware starts late | DeskRAT connected 12-51 s after starting; the dataset watched 20 s |

LID-DS 2021 avoids most of these by design: a server runs with normal users all the time, the attack arrives at a
logged time, and both classes come from the same server and setup. This lab copies that structure for host malware.

## Design

**Session.** One boot of the quiet headless guest, 180 s. From the start, benign background activity runs, and at a
random time (40-100 s, seeded) one program is injected:
- attack sessions: a dataset malware sample, or one of the dataset's attack generators;
- control sessions: a benign program (a download burst, browsing, periodic check-ins, DNS lookups, command-line
  jobs), a null program, or nothing (background only).
Attack and control sessions get the same kind of random injection time (LID-DS's attacks sat near the ends of its
recordings, and position alone scored 0.84 there), and they are interleaved in one batch.

**Background activity** (as the guest user, own cgroup, seeded per session), all from programs already used in the
dataset or the guest's own tools:
- a check-in to the Sink's web server every 10 s for the whole session;
- browsing-style requests (10-40 pages) every 30-60 s, to the Sink or to public addresses;
- short downloads every 45-90 s, DNS lookups every 20-40 s;
- command-line jobs every 15-40 s (hashing, compressing, sorting, archiving, searching files);
- once per session at most, NTP queries that nobody answers (a normal failure: the sandbox OS's own traffic had at
  least one unanswered connection in 38% of its runs).
Public addresses are used by benign activity too, so "talks to the internet" is not a malware-only sign.

**The Sink answers everything.** INetSim, dnsmasq answering every name with an outside address (203.0.113.200), and
the passive sinkhole on: every TCP connection to any address gets a handshake (INetSim on 80/443/53, a silent
listener on all other ports). UDP to arbitrary ports stays unanswered, for benign and malware alike.

**Network: recorded outside the guest.** tcpdump runs on the Sink's interface. The Sink is the guest's gateway, so
it sees all of the guest's traffic, which is the switch's vantage point, and tcpdump keeps its received/dropped
counters (VirtualBox's own recording has none). The 29 switch features come from this capture with the release's
switch model.

**Host: in-kernel monitor, hidden in plain sight.** No Python runner, bpftrace or tcpdump in the guest. Two
instances of the in-kernel monitor (`hostmon_agg`, validated equal to the release's host model) watch the injected
program's cgroup and the background's cgroup; the socket tracer (`sockowner`) attributes every flow to its process
and cgroup. Both run under neutral names (`sysstatd`, `netcfgd`) from `/opt/work`, started by one root script that
removes the password file and the sudo timestamps before anything else and stays asleep while the sample runs.
The injected program runs as the guest user from a neutral `/tmp/<random>` folder, with the dataset's launch wrapper
(bash exec, standard input `/dev/null`, own session).

**Clocks.** The host monitor's windows run on the guest clock and the capture on the Sink's. Marked UDP probes at
the start and end of each session carry the guest's time; their capture times give the offset and the drift.

**Labels and views.** Windows of 0.5 s from the session start. A session is "attack" from the injection time on.
Two views can be scored from the same session: per window for the whole machine (as LID-DS: background plus
injected program, all traffic), and per program (the injected cgroup's host rows, its sockets' flows).

## Pilot (20 sessions, about 80 minutes of VM time)

| Sessions | Injected |
|---|---|
| 5 | the five held-out Tsunami bots (do they connect now?) |
| 4 | malware that used the network in our lab and on the internet: Mirai, Kaiji, Ngioweb, CoinMiner |
| 1 | the dataset's SYN flood generator, 40,000 connections to the Sink |
| 6 | benign: download burst, browsing to a public address, check-ins, DNS lookups, archiving, a file search |
| 1 | the dataset's null program |
| 3 | nothing (background only; the first session is one of these, as a smoke test) |

Pilot checks (all must hold before scaling up):
1. Capture: tcpdump received = captured, no drops; the clock probes found at start and end with a stable offset.
2. Host monitors: rows for the whole session, health line with zero lost events.
3. Hidden monitor: the Tsunami bots connect (as without our tools in the sensor-visibility test).
4. Controls: background-only and null sessions carry only the background's traffic; the socket tracer attributes
   the injected program's flows to its cgroup.
5. Every session restored to the clean snapshot; Sink restored (original dnsmasq, sinkhole off) at the end.

## Evaluation (after the full collection)

Per window and per program; host-only, network-only, both hybrids. Seen vs unseen families; equal false-alarm
rates; baselines for injection time, activity, lifetime and batch. Reported next to the paper's results, not merged.

## Limits

- The background is generated, not real users (LID-DS sampled real web-server logs).
- The Sink fakes services; C2 protocols still are not spoken, so command phases stay absent.
- One host, VirtualBox: the guest's VirtualBox helpers remain visible.
- The capture on the Sink sees what the guest sends, as a switch port would; it is not the hardware switch.

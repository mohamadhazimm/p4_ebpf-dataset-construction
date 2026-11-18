# Threat-intel lookup of the sinkhole-run samples (2026-11-13)

Read-only OSINT on the 28 malware samples from the sinkhole C2 run, via Triage (tria.ge; needs a browser
User-Agent past Cloudflare) and MalwareBazaar (abuse.ch; the unified `ABUSE_CH_API_KEY`, not the old
`MALWARE_BAZAAR_API_KEY` which is now 403). Keys read from `.env`, never printed. ANY.RUN's API needs a paid key
we don't have; Triage is the same class of public sandbox and also extracts C2 configs.

`intel_lookup.py` — queries both for each hash; `intel-20261113.json` — full results (local, git-ignored).

## Findings
- Family labels confirmed by two independent services for every family (good validation of our labels).
- Rekoobe (10): Triage extracted C2 endpoints for 5 of them (CHECK.OFFICE365-UPDATE.COM:8081/8443,
  8.218.92.123:9911, yz.flashclouddns.com:62111, 154.84.63.184:443) — matches what they dialed in the sinkhole
  run. No keys extracted. Signatures: Unix-shell, raw sockets, PAM modification, credential dumping.
- Meterpreter (4): Triage score ~0, no config — bare stagers that do nothing without a handler (consistent with
  the sinkhole run, where they connected and sent nothing). These are the only samples commandable with a
  generic handler (the stager downloads whatever stage answers; no operator keys needed).
- Sliver (8) / Cobalt Strike (4) / Winnti / Merlin: confirmed, but no configs or keys extracted — their C2 is
  cryptographically locked to the operator's server, so they cannot be commanded without the operator's keys.

## Bearing on the C2 work
- Confirms the crypto-lock reality: Sliver/CS/Winnti can't be given a live command phase (no keys).
- Meterpreter is the one real-sample command-phase candidate (stager + handler); Rekoobe would need the embedded
  password reverse-engineered (Triage didn't extract keys).

## The 99 paper-dataset malware (2026-11-13)

Same lookup on the 99 general-malware samples the thesis detector is built on (`intel99-paper-dataset-*.json`).

- 87/99 flagged by Triage (score>=5), 91/99 labeled by MalwareBazaar: strong independent confirmation of the
  dataset's labels.
- Family-lineage notes worth a sentence in the paper: Katana -> Triage "mirai" (Katana is Mirai-based);
  Tsunami -> "kaiten" (Tsunami = Kaiten lineage); Chaos -> "kaiji"; BillGates/Dofloo -> "mrblack" (alias);
  CoinMiner -> "xmrig"; Bert -> "bert/sodinokibi".
- 17 C2 configs extracted (botnets): Gafgyt (139.59.139.52:23, 45.84.196.82:23), Mirai (91.92.42.7, 94.154.43.30),
  Kaiji (many: 118.107.41.238:808, air.duffy.baby:888, ...), XorDDoS (gddos.com domains + DNS C2), Chaos
  (niubi.5678.lol:1089). These confirm the botnets' real C2 (all unreachable in the sealed lab, which is why they
  never flooded there).
- Bearing on live C2: the 99 are DDoS botnets, ransomware and miners, not interactive-C2 families. The botnets
  among them are the only C2 candidates and would need the same per-sample C2 emulation found hard earlier
  (0/44 fresh bots flooded via generic triggering). Ransomware/miners aren't command-driven C2.

## Network behaviour of the 99 on Triage's internet-connected sandbox (2026-11-15)

User: "check the 99 malwares i have on an analysis platform and check which ones have network and do some
analysis on them". `triage_network_fetch.py` (`5249c886`) downloaded the behavioral reports (JSON only; no sample,
no pcap) of up to three Triage analyses per hash into `triage-reports-20261115/` (610 files, 320 MB, local only).
`triage_network_analyze.py` (`809aec68`) separates each sample's flows from the sandbox's own traffic and compares
them with our lab's 20-s captures (`../committee-eval-20261113/cue/run_flows.csv`) and with the saved detector
predictions; outputs `triage_network-20261115.json` (`358d8f2e`) and `.csv` (`d9963d51`, one row per sample).
The background filter was refined four times after inspection (documented in the script; the first version is kept
as `triage_network-20261115-v1.*`): OS/vendor names and the addresses they resolve to (incl. DNS aliases and TLS
names), Canonical's network, DNS judged by name (the shared resolvers had hidden malware lookups), www.google.com
never background (Kaiji, Chaos and DeskRAT use it as an internet check), Linux runs only (Triage also ran some
of these programs on Windows, where they cannot start).

Results (Linux runs, about 150 s each, real internet):
- 59 of 99 use the network (21 every connection answered, 32 some unanswered, 6 none answered); 33 silent; 7
  "uncertain" (1-3 unnamed web connections, most likely the sandbox OS). One of the 59 (INC, a few lookups 100 s
  in, on the desktop image) is most likely the image's browser.
- By type: botnets 46 of 56, miners 4 of 4, backdoors/RATs/proxies 6 of 11, ransomware 3 of 27 (one is INC above).
- First contact: median 1.8 s; 50 of 59 within 5 s, 56 within 20 s.
- Lab vs internet: same answer for 84 (48 network in both, 36 silent or uncertain in both). 11 use the network on
  the internet but were silent in our lab: 5 Tsunami (all held-out test rows; exited with code 0 after about 4,500
  calls in the lab, contact p.shadow-mods.net within 2 s on Triage), 2 DeskRAT (ran the whole 20 s in the lab,
  22,700 calls, no traffic; contact chuchuchacha.xyz at 5 s and 40 s on Triage), 1 Kaiten (exited, 1,148 calls),
  1 Mirai (crashed with SIGSEGV after 19 calls in the lab; 345,000 telnet scan attempts on Triage), 1 Nitrogen
  (exited after 19 calls; contact at 41 s on Triage), and INC. 4 the other way round (network in our lab, silent on
  Triage).
- Several lab-silent bots first list the running processes (pidof, pgrep, reading /proc/*/cmdline) and then exit
  or stall. Our in-guest sensors (tcpdump, bpftrace, the Python runner) are visible in that list, while Triage
  monitors from outside the VM. A plausible cause, not established: the traces do not record pgrep's arguments.
- Unanswered connections are real malware behaviour on the internet too: 38 of the 59 left connections unanswered
  there (scanning random addresses, servers already down). But the sandbox OS's own traffic also left at least one
  connection unanswered in 92 of 243 Linux runs (38%; 186 of 3,611 of its flows). 11 malware whose traffic was all
  answered on the internet were unanswered in our lab: there the lab cue is pure lab artifact.
- Detection (Table V, share caught over 10 assignments, host / network / concatenated / stacked): network in both
  0.91 / 0.99 / 1.00 / 1.00; internet-only 0.73 / 0.00 / 0.72 / 0.67; silent in both 0.41 / 0.00 / 0.41 / 0.38.
  By internet answer status: all answered (21) 0.96 / 0.74 / 0.96 / 0.95; some unanswered (32) 0.83 / 0.81 /
  0.93 / 0.92; none answered (6) 0.85 / 1.00 / 1.00 / 1.00. The hybrid's gain over host comes from malware that
  leaves connections unanswered on the internet as well; where the internet answered, hybrid = host.
- Table IV (26 held-out malware): the network detector catches 13. Of its 13 misses, 8 use the network on the
  internet but were silent in our lab (5 Tsunami, 2 DeskRAT, INC), 4 never use it, 1 was missed although it sent
  traffic in both.

Limits: Triage's sandbox is another environment (other OS images, about 150 s, real internet in 2026); its flow
table covers the whole VM, so the split into OS and sample traffic is a filter, with the residue above; Triage may
block some destinations itself. Detector numbers are our lab's predictions grouped by Triage's behaviour; no model
was refitted.

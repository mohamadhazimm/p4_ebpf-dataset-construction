# Sensor-visibility test (2026-11-15)

Question: seven dataset malware (5 Tsunami, 2 DeskRAT, all held-out test rows) used the network within seconds on
Triage's internet sandbox but sent nothing in our lab (`../sample-intel-20261113/triage_network-20261115.csv`). Do
they connect when nothing of ours runs inside the guest?

Design (`collect_visibility.py`, protocol `runs/20261115T194338586321Z/protocol.json`, SHA `e24cabb6...`): same sealed
lab (quiet headless guest from one staged snapshot, the Sink with INetSim and dnsmasq answering every name with
10.0.0.1, sinkhole off: checked before the runs), 60 s per run, each case twice:
- A: as in the dataset, the production batch with the .22 collector inside the guest.
- B: nothing of ours in the guest: `start.sh` unpacks the sample into a neutral /tmp folder and starts it with the
  dataset's launch wrapper; VirtualBox records the guest's network card from outside; one process listing after
  the minute.
Controls: a null program (must stay silent) and the lab's benign low-rate poller (lowrate_gen, every 5 s for 58 s;
its requests must appear in B for the whole minute).

Run: user approval "i approve, run"; preflight, Sink check, stage, dry run, A and B all passed (19:48-20:19 UTC);
A captures 9/9 accepted by the audit; original snapshot, power state and NIC-trace state restored (guest off on
`clean-tls-paired-2026-10-19`, trace off/none, only the Sink running).

| Sample | A: exit, flows, /proc reads | B: flows (answered), first contact after start |
|---|---|---|
| null | 0, 0, 0 | 0 |
| poller (control) | 0, 12 (12), 0 | 12 (12), whole minute |
| Tsunami 0d762c8c | 0, 0, 836 | 8 (2), within 1 s |
| Tsunami 3e16c3bc | 0, 0, 812 | 14 (8), within 1 s |
| Tsunami 7d22fabc | 0, 0, 828 | 14 (8), within 1 s |
| Tsunami 86947b00 | 0, 0, 848 | 12 (6), within 1 s |
| Tsunami 9e28f942 | 0, 0, 808 | 16 (10), within 1 s |
| DeskRAT 6ed2afc5 | killed at 60 s, 29 (28), 0 (73 pgrep/pidof/ps) | 4 (4), at 51 s |
| DeskRAT f0b98f95 | killed at 60 s, 24 (24), 0 (66 pgrep/pidof/ps) | 20 (20), at 24 s |

Reading:
- Tsunami: with our collector visible, all five read about 800 process entries under /proc, ran pidof/pgrep and
  exited cleanly without any traffic. With nothing of ours in the guest, all five connected within a second (DNS to
  the Sink, then port 8080 to the Sink and to 3-4 public addresses, the latter unanswered in the sealed lab) and kept
  going until the end of the minute. In our lab their silence is caused by the visible collector or its paths.
- DeskRAT: connected in both A and B, 12 to 51 s after starting. Its silence in the dataset is the 20-s window.

Limits: one family each, one run per sample and variant. B removed our processes and our telling paths
(/tmp/malware-lab, the runner's directories) together, so the cause is not separated between them; pidof/pgrep
arguments are not recorded. VirtualBox's own helpers were present in both. B has no system-call data. These 60-s
.22 captures are not merged with the dataset or any other collection; no model was fitted.

Files: `runs/20261115T194338586321Z/analysis.json` (`ee487145`), `validation-20261115T201858350096Z.json`
(`228aad06`), phase records under `phases/`, B recordings `phases/collect-b/<sample>/nic.pcap`. Code:
`collect_visibility.py` (`631ade2c`), `build_visibility_payload.py` (`24d2d00a`), `start.sh` (`e0399f10`),
`chain.sh` (`dd655657`).

## Step 2: the five Tsunami with our collector, but in a neutral folder (2026-11-15)

`collect_visibility_v2.py` (`d7344b08`, imports step 1's driver unchanged; `chain_v2.sh` `1a068f9d`), attempt
`runs/20261115T202451651979Z/`, protocol SHA `7118486e...`, user approval "OK". Same as A of step 1 (production batch,
.22 collector in the guest, 60 s), but the batch's work folder is `/tmp/4e5f1629` instead of `/tmp/malware-lab`: the
sample's own file (`/tmp/4e5f1629/extracted/<sha>.elf`) and working folder carry no telling name. Our processes and
their command lines stay visible (python3 running `/home/csci/Downloads/malware_runner.py`, sudo, bpftrace, tcpdump
writing `/tmp/.malware-pcap-<id>.pcap`). All phases passed (20:25-20:36 UTC), 7/7 accepted
(`validation-20261115T203612249758Z.json` `0321b5a5`), analysis `analysis.json` (`6435b05b`); guest restored (off on
`clean-tls-paired-2026-10-19`, only the Sink running).

Result: null silent, poller 12 answered flows, as before. All five Tsunami again exited (code 0) with no traffic,
after 820-840 /proc process-entry reads each (step 1: no traffic in A, 8-16 flows in B).

Reading: the bots do not react to their own path. They react to what they see running: our collector's processes
or their command lines (which still contain "malware"). Which of the two is not separated (pidof/pgrep arguments are
not recorded). Practical consequence: hiding the folder name is not enough; the collector must not be visible in
the process list (capture outside the guest, and an inconspicuous in-kernel host monitor).

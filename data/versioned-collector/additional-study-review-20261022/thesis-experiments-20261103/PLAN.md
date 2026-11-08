# Thesis experiments, November 2026

Written 2026-11-03 before running any of these. Data, features and models are those of the released
dataset and evaluation code (p4-ebpf-malware-detection): 240 executions, 90 host and 145 network columns,
random forests with 500 trees, balanced class weights, seed 42, threshold 0.5; the aggregate analysis uses
ten fold seeds (42, 0-8), inner seed 7 and the logistic-regression stacker. Nothing is tuned on test data.
Every result is reported. Repeated fold assignments are not independent datasets: the number of distinct
runs is stated next to the number of predictions.

Experiments:
- E1  in-kernel monitor versus the dataset collector on matched workloads (VM, running)
- E2  unseen attack types, related-family sensitivity, five fusion rules, bootstrap uncertainty (offline)
- E3  switch-faithful feature model and a readout-cap sweep, versus the idealized model (offline)
- E4  retrain with a benign background workload present, to test whether the network view recovers (VM)
- E5  plaintext-versus-TLS pairs of the benign and attack workloads in the lab (VM)
- E6  public TLS captures scored by the switch model (offline)

Each experiment writes its own result file and a short note here after it runs.

## E1 result (2026-11-03)
Passed. 27 of 28 workloads give feature vectors identical to the dataset collector; 20157 of 20160 window
cells identical. The 3 differing cells are in one 8-thread workload (run-length and transition features),
from thread-interleaving jitter. Total syscall counts match in all 28; every detector decision matches
(max probability difference 0.0); no events lost. Attempt: vm-batches-20261031/kernel_check/20261103T170924343342Z.

## E2 result (2026-11-03)
- E2a: grouping attacks by type (leave-one-type-out) lowers Table V and exposes a generalization gap:
  slowloris recall collapses when held out (stacked 0/50, network 5/50 predictions); goldeneye held out is
  fine (stacked 20/20). Floods held out: network catches nearly all. So network attack detection
  generalizes across volumetric variants but not to the unseen slow-rate type.
- E2b: five fusion rules on identical folds: host 0.784, network 0.756, concat 0.812, stacked 0.823,
  mean-of-probabilities 0.831. The simple mean edges out the stacked rule; both beat concatenation.
- E2c: lineage leakage is small. Table IV without Tsunami/RapperBot test samples: host 0.929, hybrid 0.905.
  Merging Tsunami into Kaiten and RapperBot into Mirai in Table V: stacked 0.837, host 0.799.
- E2d: bootstrap 95% CI. Table IV hybrid-minus-host diff -0.006 [-0.096, 0.086] (indistinguishable).
  Table V stacked-minus-host diff 0.036 [-0.001, 0.081] (marginal). Fusion's edge is small and borderline.

## E3 result (2026-11-03)
Switch-faithful model (CRC-16 buckets with collisions, IPv4 lengths, 32-bit ns timestamps that wrap,
readout cap). About 19% of network feature cells differ from the idealized model, concentrated in flow
duration (the 4.295 s wrap; e.g. slowloris 18.5 s -> 2.4 s) and byte-magnitude features (IPv4 vs Ethernet
length). Detection is essentially unchanged at every readout cap:
  Table IV  host 0.929  network 0.750  hybrid 0.926  (identical to idealized, caps None/5000/1000/350)
  Table V   host 0.784  network 0.754-0.759  stacked 0.821-0.822  (idealized 0.784/0.756/0.823)
The readout cap (down to 350 flows/window against up to 98,000 in a scan) does not change detection here,
because Table IV has no attacks and the floods stay separable under the cap. So the idealized model is a
faithful proxy of the switch for detection, though individual feature values differ. Faithful datasets:
thesis-experiments-20261103/e3_data/. Caveat: on a busy deployment where many benign flows compete for the
readout budget the cap could matter more than this quiet-host data can show.

## E5 result (2026-11-03) -- encrypted traffic, with a confound
18 runs, 9 HTTP/HTTPS pairs; 17 accepted (goldeneye_post-http rejected on a benign capture-counter
discrepancy, dropping that pair). TLS confirmed (HTTPS runs show ClientHellos, HTTP runs none).

Clean part (benign, comparable intensity): for the benign pairs that did the same work over both schemes
(poll 62/62 connections, session 122/122, download 42/42, pool 29/23), the host/network/stacked detectors
fitted on all 240 runs classified the HTTPS run the same as the HTTP run -- benign stayed benign. Feature
values shifted (median 22-71% relative change from the TLS handshake and record overhead) but not enough to
change the decision. This supports that the features are payload-independent and that benign TLS does not
by itself cause false positives.

Confound (attacks and benign_upload): the HTTPS attack runs produced much less traffic than their HTTP
twins -- GoldenEye 12 connections over HTTPS vs 5039 over HTTP (it barely ran), slowloris 693 vs 1603,
benign_upload 3 vs 22. The tools established far fewer TLS connections against INetSim's self-signed service
in the 20 s window, so the HTTPS attacks did not run at full intensity. We therefore cannot conclude from
this that encryption hides a working attack; the attack-side encrypted test is inconclusive in this lab and
needs a TLS endpoint that lets the attacks run at full rate (a real TLS server rather than INetSim). Honest
takeaway for RQ1: features are payload-independent and benign classification is robust to encryption; a
clean encrypted-attack test is future work.

## E5 correction and explanation (2026-11-03)
Correction: the pool pair is not a clean comparison. Both halves failed (HTTP: the Sink's 10-connection
limit; HTTPS: connections reset). Only three benign pairs completed fully over both schemes: poll (60/60),
session (120/120), download (40/40). Their decisions match between HTTP and HTTPS.

Why the other pairs differ: the Sink, not the encryption. Its INetSim services accept at most 10
concurrent connections each. Over HTTP, extra connections receive a plaintext refusal and are closed; over
HTTPS the Sink completes the TLS handshake and then resets them. It also reset the single large TLS upload
(256 KB POST) that succeeded over HTTP. Each TLS connection also costs a handshake, so the clients opened
fewer connections in the 20 s window, and one tool's workers stalled during the handshake. The HTTPS
attack runs therefore generated far less traffic and process activity than their HTTP twins, and both the
network and host scores fell accordingly. This measures the Sink's TLS behaviour, not encryption hiding
an attack. Packet-level analysis: e5_dive_streams.py.

## E5b plan (2026-11-03, before running) -- encrypted pairs without the Sink's connection limit
INetSim caps concurrent connections per service at 30 in code (config and command line both reject values
above 30), so raising its limit cannot remove the bottleneck. For E5b only, the Sink's HTTP and HTTPS
service is nginx (already installed on the Sink) instead of INetSim: same address and ports (10.0.0.1:80
and :443), INetSim's own certificate and key (/usr/share/inetsim/data/certs/), and INetSim's own default
page (fakefiles/sample.html, SHA-256 f0a3eec2..., the body seen in every collection) for every path and
method; up to 16384 concurrent connections. INetSim is stopped for the duration; dnsmasq is unchanged.
The same 18 cases as E5 are rerun (both halves of every pair under the same server). Analysis is the same
as E5. Primary readout: within-pair HTTP-vs-HTTPS differences. The detectors were trained on INetSim-era
runs, so absolute decisions on nginx-era runs carry that domain difference. Afterwards nginx is stopped,
INetSim is restarted as on 2026-10-18, and the original answers are verified before any other experiment.

## E5b result (2026-11-03) -- encrypted pairs with no connection limit
Server: nginx on the Sink (config /tmp/e5b-nginx.conf, SHA-256 18169e5f...), INetSim's certificate
(DER SHA-256 4d68da2a...) and default page (f0a3eec2...). Checked from the guest before the batch: 50
simultaneous requests succeed over HTTP and HTTPS; 256 KB uploads succeed over both. Attempt:
e5-attempts/20261103T180119682644Z (18 runs, batch passed).

Clean pairs: 7 (5 benign, 2 slowloris). Within every pair the connection count is identical (62/62,
202/202, 122/122, 22/22, 42/42, 302/302, 802/802) with zero server resets; every HTTPS connection completes
the handshake and exchanges data; slowloris holds all 300 / 800 sockets over TLS. HTTPS runs carry 1.3-1.5x
the packets (handshake overhead). Encryption is the only difference within a pair.
Excluded: GoldenEye. Its HTTP runs now ran at full rate (149,000-230,000 captured packets) and were rejected
by the collector for kernel capture drops (82,236 and 4,518). Its HTTPS runs still carried only 115-117
packets with no server limit, so the stall is in the tool's own HTTPS mode, not the Sink.

Decisions (detectors fitted on all 240 dataset runs):
- Benign: 5 of 5 pairs unchanged; all benign over HTTP and HTTPS.
- Slowloris 300: host 0.53 -> 0.37, network 0.77 -> 0.41, stacked 0.79 -> 0.41 (caught over HTTP, missed
  over HTTPS by all three).
- Slowloris 800: host 0.49 -> 0.50 (borderline both ways), network 0.78 -> 0.44 (missed over HTTPS),
  stacked 0.78 -> 0.52 (still caught, barely).
Reading: with the attack at equal strength, encryption alone changed the flow statistics (handshake packets,
TLS record framing of the small header lines) enough that a network detector trained only on plaintext slow
attacks did not recognize the encrypted version; benign traffic was unaffected. Payload-independent features
are not automatically encryption-invariant: detecting encrypted attacks needs encrypted examples in training.
Second finding: even over HTTP, slowloris against an unlimited server scored lower than the dataset's
slowloris runs (network about 0.77 vs 0.92-0.98; host about 0.5 vs 0.95). The detectors learned slowloris
as it behaved against the Sink's 10-connection limit, so the dataset's slow attacks partly reflect the Sink.
Caveats: two attack pairs from one tool; indicative only.

Sink restored afterwards: nginx stopped, `systemctl start inetsim`, config 53de0365... unchanged, dnsmasq
unchanged. Checked from the guest: HTTP 200 with body f0a3eec2..., DNS AA/RA/TTL 0/10.0.0.1, and 30
simultaneous requests -> 10 served, 20 refused (the original limit).

## E6 plan (2026-11-03, before running) -- nginx-served dataset
Goal: recollect the dataset against a web server with no connection limit, so network-side features are not
shaped by the Sink refusing connections. Approved: full recollection; nginx for web, INetSim for other
services; HTTPS versions of the network workloads included; E4 run first on the current INetSim Sink.

Sink for this collection: nginx on 10.0.0.1 ports 80 and 443 (INetSim certificate, INetSim default page,
up to 16384 connections); INetSim for its non-web services (DNS via dnsmasq unchanged, plus mail/FTP/etc
with its http and https services not started so nginx can bind them); recorded with hashes. Restored to
the original INetSim configuration afterwards and verified from the guest.

Runs: the same 240 samples and arguments as the released dataset, in dataset order, one batch, no background
workload (driver nginx_dataset.py; payload built, 240 cases). Then a smaller batch of HTTPS network
workloads (benign shapes + slowloris; goldeneye excluded, its HTTPS mode stalls).

Live comparison (user request): every 10 completed runs, each new run is compared to the original INetSim
run of the same sample -- median and p90 relative change of the 90 host and 145 network features, and
detector decision flips (compare_watch.py).

Analysis: nginx_build_and_compare.py builds features_nginx.csv (same columns, metadata from the protocol,
features from the new runs) and comparison.json (paired change by category; Table IV and Table V on the
nginx dataset next to the INetSim dataset). The two datasets are reported side by side, not merged.
Expectation from composition: the ~130 non-networking runs change little; differences concentrate in the
networking malware, attacks and network-active benign.

## E4 result (2026-11-03) -- training with background traffic
150 training executions recollected with the benign background workload present; all 150 accepted with
background traffic. Table IV setting, 150 train / 54 test, four train->test combinations (BA, specificity):
  quiet->quiet  host 0.929(0.86)  network 0.750(1.00)  hybrid 0.926(0.93)   [released Table IV, reproduced]
  quiet->bg     host 0.929(0.86)  network 0.500(0.00)  hybrid 0.500(0.00)   [B1: network+hybrid flag all]
  bg->bg        host 0.911(0.82)  network 0.720(0.79)  hybrid 0.964(0.93)   [recovered; best hybrid]
  bg->quiet     host 0.911(0.82)  network 0.500(0.00)  hybrid 0.946(0.89)
Findings: the network view's collapse on a busy host is a training-data problem, not a feature problem.
Trained with background present (bg->bg), the network view recovers (0.72) and the hybrid is the most
accurate of all combinations (0.964). The network view alone stays sensitive to whether train and test
background conditions match (bg->quiet also collapses), but the hybrid absorbs this and the host view is
stable throughout (0.91-0.93). Takeaway: fusion plus training that matches deployment conditions gives a
detector robust to background traffic. Caveat: single split, 54 test executions, one background pattern.
Attempt: vm-batches-20261031/background_train/20261103T173237830829Z.

## E6 Sink configured (2026-11-03)
INetSim web services commented in /etc/inetsim/inetsim.conf (lines 30-31 #start_service http / https);
original backed up at /tmp/inetsim.conf.orig (SHA-256 53de0365...), edited config 0621545e.... INetSim
restarted (now ftp/ftps/smtp/smtps/pop3/pop3s only); nginx on 80/443 (config 18169e5f...); dnsmasq on 53.
Verified from the guest: 50 concurrent HTTP and HTTPS succeed (body f0a3eec2...); DNS answers 10.0.0.1;
FTP(21) still "220 INetSim FTP Service ready." Recollection launching now.

## E6 result (2026-11-03) -- nginx dataset vs INetSim dataset
240 samples recollected against nginx (web) + INetSim (mail/FTP) + dnsmasq; 238 accepted (2 GoldenEye
rejected for capture overflow against the unlimited server). Sink restored to the original INetSim
configuration afterwards (config hash 53de0365..., 10-connection limit back, verified from the guest).
Attempt: thesis-experiments-20261103/nginx-dataset/20261103T183218692466Z; features_nginx.csv, comparison.json.

Paired change vs the original INetSim run (median relative change; decision flips, detectors fitted on 240):
  malware        99  net 0.00  host 0.00  flips 1
  cli benign    105  net 0.00  host 0.00  flips 0
  null            3  net 0.00  host 0.00  flips 0
  net attack     13  net 0.33  host 0.00  flips 2   (slowloris_800, slowloris_1000: host)
  net benign     18  net 0.62  host 0.67  flips 3   (session_300, bulk1000, bulk1600)
So the server only matters for the Sink-dependent runs (attacks, network-active benign); malware, CLI benign
and nulls are unchanged. 6 of 238 runs flip a decision, all in the networking tail.

Aggregate detection is nearly identical between the two datasets:
  Table IV   host 0.929->0.893   network 0.750->0.750   hybrid 0.926->0.945
  Table V    host 0.784->0.782   network 0.756->0.757   stacked 0.823->0.806
Conclusion: the Sink's connection limit shaped the attack and network-benign feature values (E5b's concern,
confirmed at scale), but removing it does not materially change the headline detection results. The nginx
dataset is a cleaner, more realistic second dataset that gives the same conclusions; the two are reported
side by side, not merged.

## E6b — robust re-check of the nginx Table IV "flip" (2026-11-04)
Observation: nginx Table IV reads hybrid 0.945 vs host 0.893 (vs INetSim host 0.929 / hybrid 0.926), tempting a "hybrid beats host" headline. Table IV is ONE split of 54 test execs (28 benign/26 malware); the whole move is 3 samples: host +2 benign FP (4->6), hybrid +1 malware TP (fn 2->1). Inside the E2d bootstrap band [-0.096,0.086].
Robust estimator (identical repeated grouped CV, 10 fold seeds [42,0-8], inner seed 7, stacker; common.load path-switched to features_nginx.csv; scratchpad/robust_nginx.py):
  host   : INetSim 0.784 +/-0.022  |  nginx 0.782 +/-0.016   (NOT 0.929->0.893; host unchanged)
  network: INetSim 0.756 +/-0.016  |  nginx 0.757 +/-0.013
  stacked: INetSim 0.823 +/-0.015  |  nginx 0.806 +/-0.027   (NOT 0.945; slightly DOWN on nginx)
  concat : 0.812 | 0.822     mean: 0.831 | 0.821
  hybrid-host paired/seed: INetSim +0.039 (9/10)  |  nginx +0.024 (8/10)
Verdict: the Table IV 0.945/0.893 is single-split noise in BOTH directions. The defensible result is the small consistent hybrid edge (+0.02..+0.04 BA, 8-9/10 seeds, both datasets). Do NOT headline the Table IV cell. nginx server backend barely moves the robust detectors (host/network identical, stacked -0.017), which is itself a robustness finding. On nginx, concat/mean (0.822/0.821) edged the stacker (0.806).

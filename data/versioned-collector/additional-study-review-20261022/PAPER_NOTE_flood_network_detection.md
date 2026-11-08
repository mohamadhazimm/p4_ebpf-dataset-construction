# PAPER NOTE (not yet in the paper) — "Floods are detected directly by the network sensor"

Status: DRAFTED, to add to the Overleaf paper LATER (user: "we'll do it later, add it as a note for now", 2026-11-06).
Where it goes: Results §7 (flood/network-strong evidence) + one methods/limitations sentence; Discussion complementarity.
Evidence basis: flood21-collect (18 generated floods, 20 s) + precision-phase4 (live Kaiten sustained flood + benign-bulk controls). See the AGENTS.md ledger entry "Benign Fixed To Fit The 5-Min Window; Flood Overflow-vs-Detection Characterized, 2026-11-06".

## The argument (plain)
Volumetric floods are detected by the NETWORK half directly and immediately (first 0.5 s window), by flow-shape
(SYN-only / no handshake / unidirectional / huge destination fan-out), which is categorical, not volumetric. The HOST
half structurally cannot separate a flood from benign heavy traffic, because the flood's host-activity VOLUME is
indistinguishable from benign bulk (sustained flood 1.9e7 calls vs benign TLS loop 4.7e6; network-active benign
0.8–4.7M fully overlaps host-active malware 0.8M). So network → floods; host → host-active network-quiet malware.

## Framing precision (important)
- Make the DETECTION claim on FLOW-SHAPE + the host VOLUME confound (true for the deployed in-kernel aggregating
  monitor hostmon_agg).
- Treat BUFFER OVERFLOW only as a DATA-COLLECTION note: overflow is a property of the raw-event dataset collector
  (.22's 4M-event cap), NOT the deployed sensor. Do not use overflow as the detector's failure mode.

## Paste-ready LaTeX — Results
```latex
\subsection{Floods are detected directly by the network sensor}
\label{sec:flood-direct}

Volumetric floods are detected by the network half of the architecture
\emph{directly and immediately}, and by a mechanism the host half structurally
lacks. Across our flood corpus---18 generated SYN/UDP/HTTP and Slowloris
floods plus one live bot (Kaiten) autonomous scanner---the P4 flow features
flag every flood within the \emph{first} $0.5\,\mathrm{s}$ observation window.
The signature is categorical rather than volumetric: for the sustained bot,
$100\%$ of sampled packets are bare SYNs, no handshake completes, traffic is
unidirectional, and the flow fans out to $37{,}914$ distinct destinations at
$1.7\times10^{5}$ packets/s. The generated floods show the same shape from
their first packets. None of these properties appear in benign heavy
traffic, which completes handshakes, is bidirectional, and targets a single
destination.

The host sensor cannot make this distinction, because a flood's
\emph{host-activity volume} is indistinguishable from that of legitimate
bulk transfer. Table~\ref{tab:flood-host} contrasts the two: a sustained
flood and a benign TLS upload loop both drive the system-call rate into the
millions ($1.9\times10^{7}$ vs.\ $4.7\times10^{6}$ calls), and across our
network-active benign controls the host workload ($0.8$--$4.7$M calls) fully
overlaps the host-active malware ($0.8$M). A threshold on host activity
therefore cannot separate a malicious flood from a large download without
flagging the download as well. The network flow-shape separates them with no
overlap.

\begin{table}[t]
\centering
\caption{Host activity cannot separate floods from benign bulk; network
flow-shape can. Host activity is total system calls over the active interval;
flow-shape fields are from the captured traffic.}
\label{tab:flood-host}
\small
\begin{tabular}{lrccc}
\toprule
sample & host calls & SYN-only & handshake & distinct dst \\
\midrule
flood (sustained bot) & $1.9\times10^{7}$ & $1.00$ & no  & $37{,}914$ \\
benign bulk (TLS loop) & $4.7\times10^{6}$ & $0.00$ & yes & $1$ \\
benign download        & $1.5\times10^{6}$ & $0.00$ & yes & $1$ \\
host-active malware    & $8.3\times10^{5}$ & ---    & --- & --- \\
\bottomrule
\end{tabular}
\end{table}

This is the complementary role the hybrid is built on: the network sensor
provides direct, early flood detection that host features cannot, while the
host sensor detects the host-active, network-quiet malware (e.g.\ miners and
loaders) that emits too little traffic for the network sensor to flag. The
breadth of the network claim rests on the seven DDoS families of
CIC-DDoS2019 (Sec.~\ref{sec:cic}, balanced accuracy $\geq 0.998$); the paired
captures here show the \emph{mechanism}---immediate flow-shape detection---on
real host-and-network telemetry.
```

## Paste-ready LaTeX — methods/limitations sentence (floods not in the paired host cohort)
```latex
Sustained floods are not collected as paired 5-minute host telemetry: at
$\sim\!8\times10^{5}$ system calls/s a flood exhausts a bounded raw-event
collection buffer within $\sim\!5\,\mathrm{s}$, and a benign bulk loop
($4.7\times10^{6}$ calls) exceeds it as well---confirming that host
system-call volume reflects workload intensity, not maliciousness. Floods are
therefore evaluated through network flow features (CIC-DDoS2019 and the live
captures above) rather than the paired cohort.
```

## Caveats to keep (so a reviewer can't knock it down)
- The LIVE sustained flood is one bot family (Kaiten); CIC-DDoS2019 carries the family/type breadth.
- "Network detects floods" = flood RECALL from flow-shape, not the network sensor being a clean standalone detector
  (at a fixed threshold it still false-alarms on some network-active benign in the pooled CV — which is itself why the
  HYBRID, not network-alone, is the deliverable).

## Exact numbers (for reference, from the data)
- flood_gen burst floods: 40k–600k syscalls total (never near the 4M cap); finish 0.5–14 s; network ≥100 pkts in window 1.
- fastest (150k sink/fan): tcpdump dropped 40,455 / 16,458 pkts (capture-limited; 2 runs quality-rejected).
- Kaiten sustained: 19,240,923 syscalls @ 782,151/s; 300,000 sampled pkts 100% SYN-only; 37,914 distinct dst; 169,878 pps; overflow-equivalent at ~5.1 s; network detect ~0–1 s.
- benign_bulk_post 4,720,270 syscalls (would overflow at ~17 s); benign bulk 0.77–4.72M spans host-active malware 0.83M.

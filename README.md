# Hybrid Malware Detection Study

This repository contains a research pipeline for comparing network-only,
host/eBPF-only, and combined malware classifiers. The paper-facing analysis
uses one grouped cohort. Other collections and exploratory experiments remain
separate and are not interchangeable with that cohort.

## Start Here

| Need | Location |
| --- | --- |
| Malware type labels and cohort membership | `data/malware/catalog/malware_classification.csv` |
| Encrypted archive checksums and locations | `data/malware/catalog/archive_manifest.csv` |
| Malware archive files, grouped by type | `data/malware/catalog/samples/<type>/` |
| Primary paper cohort dataset and CSV reports | `data/malware/cohorts/primary_grouped_cv/` |
| Separate fixed-split class counts | `data/malware/cohorts/expanded_fixed_split/class_counts.csv` |
| Study scripts and analysis code | `scripts/`, `src/`, `workloads/` |
| Historical exploratory CSV reports | `reports/csv_archive/` |

The primary cohort has 224 malware samples, 138 benign workloads, and 57
signature/package groups. Its CSV folder contains the engineered dataset,
out-of-fold predictions, category summaries, execution outcomes, and malware
type counts. The separate fixed split has 521 malware and 500 benign training
records, plus 319 malware and 138 benign captured test records. Its counts are
source metadata only; it is not part of the primary model comparison.

## Malware Catalog

`malware_classification.csv` contains cohort membership and source labels. A
sample may have more than one row when it belongs to more than one cohort.
Labels describe source metadata, not independently verified runtime behavior.
Eleven Mirai samples without individual category sidecars are marked as
provisional, based on intake tags and source directory only.

`archive_manifest.csv` has one row per encrypted ZIP wrapper. The sample hash
identifies the payload; the archive hash identifies that particular ZIP
wrapper. Multiple wrappers for one payload are preserved. `storage_path` is
relative to this repository. Archives are grouped under
`catalog/samples/<type>/` and remain encrypted. Do not extract or run them on
the host. Git ignores the archive files.

## File Structure

```text
.
├── README.md                 Project overview and this map
├── requirements.txt          Python dependencies
├── data/
│   ├── malware/
│   │   ├── catalog/
│   │   │   ├── malware_classification.csv  Sample types and cohort membership
│   │   │   ├── archive_manifest.csv        ZIP hashes and storage paths
│   │   │   └── samples/<type>/*.zip        Encrypted malware archives
│   │   ├── cohorts/
│   │   │   ├── primary_grouped_cv/         Paper dataset and CSV reports
│   │   │   └── expanded_fixed_split/      Separate class-count CSV
│   │   ├── revision*/                     Collection records and run outputs
│   │   └── full-cohort-323/                Separate collection and manifests
│   ├── benign/                             Benign workload data and runs
│   ├── hybrid_scenarios/                  Controlled scenario data and runs
│   ├── packages/                           Package inputs and manifests
│   ├── runs/                               General collector output
│   └── versioned-collector/                Versioned collection output
├── src/                                    Python acquisition and analysis
├── scripts/                                Collection and workflow commands
├── workloads/                              Benign workload generators
├── reports/
│   ├── csv_archive/                        CSV-only exploratory report copies
│   └── ...                                 Other experiment reports
├── models/                                 Model artifacts
├── presentations/                          Generated presentation materials
├── docs/                                   Study notes and walkthroughs
└── tests/                                  Automated tests
```

Start with `data/malware/catalog/` to inspect labels and archive locations,
then use `data/malware/cohorts/` for the compact paper-facing CSVs. The
collection and run folders hold source records and larger outputs; use the
CSV archive for older exploratory reports. Malware ZIPs remain encrypted and
are excluded from Git.

## Workflow

1. Inspect the catalog and cohort CSVs before using a dataset. Check the
   cohort column, classification basis, and confidence fields.
2. Build or validate a dataset with the tools in `src/` and the manifests
   beside the relevant collection.
3. Run unit tests with `python3 -m unittest discover -s tests`.
4. Use the VirtualBox scripts in `scripts/` only with the malware VM attached
   to the isolated `malnet` internal network.

Never treat execution outcome as the malware label. Never interpret the
source category as confirmed behavior. The packet-derived features are not
measurements from a live P4 switch, and run-level pairing does not establish
process-to-flow causality.

## Safety

Keep API keys and VM credentials in the local environment or a private `.env`
file. Never commit credentials, malware archives, executable payloads, PCAPs,
or detailed per-run telemetry. The malware VM must not have NAT, bridged, or
public network access. Encrypted samples are stored for controlled isolated
collection; do not extract or execute them on the host.

## Related Workspaces

- The [research manuscript and thesis](https://github.com/mohamadhazimm/a-unified-p4-ebpf-architecture-for-host-and-network-malware-detection)
  describe the broader architecture and study context.
- The [P4 and eBPF implementation](https://github.com/MohamadMHazim/p4_ebpf)
  contains the data-plane and host-monitor code.

These projects are maintained separately. This repository focuses on cohort
construction and offline model evaluation.

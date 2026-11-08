# Offline Remediation Audit

## Scope

All 417 accepted host cases (366 common-aligned) were audited without reading model predictions, fitting models, modifying splits, executing sample code or operating a VM. Existing .18 data, global exclusions and historical results remain unchanged. All prior evaluation is consumed/exploratory. This is not a new capture/archive/PCAP completeness audit.

## Binary And Behavioral Relationships

Verified original executable hashes for 417/417 cases, screened 43284 same-mode binary pairs, and reconciled every recorded exact-target boundary/post-target syscall count. Malware archive members were streamed into bounded memory only, never written to disk or executed. Benign code was also only read.

| Evidence | Clusters | Cross Resplit | Cross Original | Cross Acquisition Groups |
| --- | ---: | ---: | ---: | ---: |
| identical_executable_regions | 15 | 12 | 0 | 0 |
| identical_host175 | 31 | 18 | 0 | 1 |
| identical_nonempty_post_sequence | 16 | 9 | 1 | 2 |
| same_program_or_hash_unit | 14 | 0 | 0 | 0 |
| tlsh_review_candidate | 35 | 19 | 2 | 11 |
| combined_exact_evidence_review_units | 42 | 25 | 1 | 2 |

Executable-region identity means identical selected file-backed code regions, not identical whole programs, arguments, data or malicious intent. TLSH distances <=30 and <=60 are frozen heuristic close/review tiers, NOT validated malware-lineage thresholds. Static runtimes and toolchains can dominate similarity. Conversely no match cannot establish independence, particularly across modes, packers or rebuilt variants. Similarity graphs can chain; fuzzy edges are not automatically promoted into split units. Exact behavioral identity also does not certify source lineage. No case is deleted or reassigned here.

`binary_and_behavior_cases.json` gives original source/manifests, executable hashes, section/segment fingerprints, TLSH and archived-trace fingerprints. `relationship_edges.json` retains distances and reasons; `relationship_clusters.json` retains exact identities and partition effects. Original roles and within-family resplit roles are both shown, not conflated. Acquisition signatures/categories are provider evidence, not independently verified attack taxonomies. Source gaps: 0; unavailable code TLSH: 0.

## Coverage And Remaining Gates

400/417 cases fall in mode/activity cells containing both labels; 13/18 declared cells contain both. This is descriptive coarse support, NOT corrected performance, task equivalence or a causal estimate. Counts and independent project/signature coverage are in `activity_mode_coverage.json`; no case was removed. Activity is target progress, not malicious activation. Per-event ABI, arguments and general packet ownership remain unavailable from these fingerprints; mixed-ABI descendants remain possible.

The frozen `remediation_protocol.json` separates eight gates: reviewed lineage units, independent overlapping tasks, process/flow attribution, schema compatibility, prospective evaluation design, capture release, nested development selection, and one locked final test. All launch/model gates remain false. Historical missing events and consumed validation cannot be repaired retrospectively. Exact future inputs, meaningful task diversity, independent group counts and a precision/power target must be reviewed before a collection release; no arbitrary new sample quota is asserted.

Keep the primary 145/145/290 comparison, sample-weighted BA, RF500/seed42/threshold0.5 and fold-local host MI unless explicitly amended. Do not choose a favorable grouping, seed or metric, force hybrid superiority, or deploy the highest score from the prior exploratory battery. Host-only remains a valid comparator/candidate. Newly attributed traffic would change feature semantics and needs explicit review, not silent filtering of .18 captures. Prior benign attribution/quality evidence is reused, not rerun or upgraded into general completeness.

## Next Action

Review the exact candidate pairs and source/task feasibility offline, then seek separate approval for a new-schema benign-only attribution pilot. No sample/VM/collector/model operation is authorized by this artifact. Genuinely new independent evaluation must be reserved before model selection; existing data may support development but cannot become fresh confirmation through resplitting. No fresh VM-state claim is made.

## Reproduction

From the study root, run `python3 data/versioned-collector/additional-study-review-20261022/audit_remediation.py --self-test`, `--run`, or `--verify <attempt>`. The audit depends on workspace-local pyelftools0.32 and python-tlsh4.5.0, pinned with input hashes. Inputs and outputs are rehashed on verification; output directories refuse overwrite.

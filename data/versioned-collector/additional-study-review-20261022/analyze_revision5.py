"""Held-out family/project-held-out fit on the matched-cohort (revision5-matched) quiet collection ALONE.

Reuses analyze_v21's exact pipeline (frozen trainer: RF500/balanced/seed42, training-only 29-family host MI, grouped
OOF, 145/145/290 P4/host/hybrid; plus activity-only / return-code(nuisance) / mode baselines, group-weighted BA,
2000-replicate group bootstrap, and the 100 training-only whole-group label-permutation null). Only the inputs change:
the revision5 attempt, its accepted classifier cases (benign + malware; nulls are controls), and the matched-cohort
family-held-out (malware) + project-held-out (benign) split read from the frozen payload order (cases.json). Any
malware family that straddles the split is folded wholly into training so every validation malware family is strictly
never-seen. POST-HOC single examined cohort -- not blind, not a generalization/superiority claim; validation consumed
once scored. No VM, no capture change, no dataset merge, no model promotion.
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import analyze_v21 as base  # noqa: E402  reuse the full held-out pipeline; override only the cohort + split source

ATTEMPT = ROOT / "revision5-collection/20261025T100025568989Z"


def case_metadata():
    """sample -> {class,label,mode,group_id,split,family} from the frozen payload order (cases.json).

    Malware groups by signature family, benign by project. Families straddling the split are folded into training
    (recorded in base.FOLD_FAMILIES_INTO_TRAINING) so validation malware families are strictly held-out.
    """
    cases = json.loads((ATTEMPT / "payload/cases.json").read_text())
    straddle = defaultdict(set)
    for c in cases:
        if c["label"] == "malware":
            straddle[c["family"]].add(c["split"])
    folded = {fam for fam, s in straddle.items() if len(s) > 1}
    base.FOLD_FAMILIES_INTO_TRAINING = folded
    meta = {}
    for c in cases:
        if c["label"] == "malware":
            split = "training" if c["family"] in folded else c["split"]
            meta[c["sample"]] = {"class": "malware", "label": 1, "mode": c["mode"],
                                 "group_id": "malware_signature::" + c["family"], "split": split,
                                 "frozen_split": c["split"], "family": c["family"]}
        elif c["label"] == "benign":
            meta[c["sample"]] = {"class": "benign", "label": 0, "mode": c["mode"],
                                 "group_id": "benign_project::" + c["project"], "split": c["split"],
                                 "frozen_split": c["split"], "family": c["project"]}
        # null: environment control, never a classifier input
    return meta


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--host-contract", default=None,
                        help="alternate host feature-columns JSON (e.g. the ADFA-validated descriptor contract)")
    args = parser.parse_args()
    base.V21_ATTEMPT = ATTEMPT
    base.CASES_ORDER = ATTEMPT / "payload/cases.json"
    base.OUT_DIR = ROOT / "revision5-model-fit"
    base.case_metadata = case_metadata
    base.HOST_CONTRACT = args.host_contract
    base.run()


if __name__ == "__main__":
    main()

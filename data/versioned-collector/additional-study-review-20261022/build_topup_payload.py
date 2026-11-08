"""Top-up payload for the full 5-min cohort: the 62 revision5 malware NOT already collected in the 87-case scale run
(disjoint by member sha, CatStorm excluded as overflow/PCAP-prone) + all 68 fixed host-active benign variants + 3 null.
Reuses build_scale_payload.build unchanged, with the top-up malware selection and the full benign set patched in via
module globals. Malware are reused VERBATIM from the frozen revision5 payload (never executed on the host). Combined
with the 42 malware + 3 null already collected, this completes the ~104-malware (all revision5 except CatStorm) 5-min
cohort. No VM, no sample execution here."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import build_scale_payload as s          # noqa: E402  reuse the tested assembler

s.MALWARE_SEL = ROOT / "topup_malware_selection.json"   # 62 disjoint revision5 malware
s.N_BENIGN = 68                                         # all fixed host-active variants (rsync/wget/ping)
build = s.build


if __name__ == "__main__":
    import json, tempfile
    from collections import Counter
    with tempfile.TemporaryDirectory() as d:
        manifest, order = build(Path(d) / "payload", "/home/csci/Downloads/topup5min-selftest")
        print("counts:", manifest["counts"])
        print("by mode/label:", manifest["by_mode_label"])
        print("benign programs:", dict(Counter(c.get("program") for c in order if c["label"] == "benign")))
        assert manifest["counts"]["null"] == 3 and manifest["counts"]["malware"] == 62 and manifest["counts"]["benign"] == 68
        print("total cases:", len(order), "| unique:", len({c["sample"] for c in order}))

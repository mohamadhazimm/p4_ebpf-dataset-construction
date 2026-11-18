#!/usr/bin/env python3
"""Second census pass: the census_network.py procedure, unchanged, for the Linux families that enumerate_triage.py
found by behaviour category and that the first pass did not cover. Writes census2.json / census2_candidates.csv.

    /usr/bin/python3 -I census_network2.py
"""
import site
import sys
from pathlib import Path

sys.path.append(site.getusersitepackages())
sys.path.insert(0, str(Path(__file__).resolve().parent))
import census_network as CN     # noqa: E402

CN.FAMILIES = {
    "vshell": ("VShell", "RAT / C2 implant (Go)", False),
    "fritzfrog": ("FritzFrog", "P2P botnet, SSH brute force (Go)", False),
    "panchan": ("Panchan", "P2P botnet and miner, SSH worm (Go)", False),
    "xmrig_linux": ("XMRIG", "cryptominer", False),
    "echobot": ("Echobot", "DDoS bot (Mirai variant)", False),
    "goddosagent": ("DDoSAgent", "DDoS agent (Go)", True),
    "adaptixc2": ("AdaptixC2", "C2 framework agent", False),
    "ladvix": ("Ladvix", "trojan", False),
    "sshdkit": ("sshdkit", "SSH backdoor kit", False),
    "deimosc2": ("DeimosC2", "C2 framework agent (Go)", False),
}
CN.OUT_JSON = CN.HERE / "census2.json"
CN.OUT_CSV = CN.HERE / "census2_candidates.csv"

if __name__ == "__main__":
    CN.main()

"""Do the six unchanged dataset tasks of the toolchain collection reproduce their dataset rows? Offline.

Each control is a dataset benign task re-run (same binary, arguments and fixtures) in the toolchain collection.
Its 90 host and 145 network columns are built exactly as the dataset's (common.per_window / common.summarize)
and compared with the dataset row of the same task.

    /usr/bin/python3 toolchain/controls_check.py ../toolchain21-collect/<attempt>
"""
import json
import sys
from pathlib import Path

import numpy as np
from scipy.stats import spearmanr

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent)); sys.path.insert(0, str(HERE.parent / "evasion")); sys.path.insert(0, str(HERE))
import common as C  # noqa: E402
import score_toolchain as S  # noqa: E402


def main():
    attempt = Path(sys.argv[1]).resolve()
    prot = json.loads((attempt / "protocol.json").read_text())
    rows, hc, nc = C.load()
    hs, ns = C.signals(hc), C.signals(nc)
    H, N, _, _ = C.per_window(rows, hc, nc)
    X = np.hstack([C.summarize(H), C.summarize(N)])
    by_sample = {}
    for i, r in enumerate(rows):
        by_sample[C.run_dirs(rows)[i].name] = i
    out = []
    for c in prot["cases"]:
        src = c.get("source", "")
        if not src.startswith("dataset case "):
            continue
        ds = src.removeprefix("dataset case ")
        i = by_sample.get(ds)
        runs = sorted((attempt / "runs" / c["sample"] / "output").glob("run_*"))
        Hn, Nn, _ = S.new_run(runs[-1], c["mode"], hs, ns)
        x = np.hstack([C.summarize(Hn[None])[0], C.summarize(Nn[None])[0]])
        y = X[i]
        rho = spearmanr(x, y).correlation
        out.append({"control": c["sample"], "dataset_row": ds, "network": c["network"],
                    "host_calls_new": int(Hn[:, hs.index("host_total_syscalls_total")].sum()),
                    "host_calls_dataset": int(H[i][:, hs.index("host_total_syscalls_total")].sum()),
                    "packets_new": int(Nn[:, ns.index("net_pkts_total_delta")].sum()),
                    "packets_dataset": int(N[i][:, ns.index("net_pkts_total_delta")].sum()),
                    "columns_identical": int(np.sum(np.isclose(x, y, rtol=0, atol=1e-9))),
                    "columns": int(len(x)), "spearman_all_235": round(float(rho), 4)})
    res = {"attempt": str(attempt), "controls": out}
    p = HERE.parent / "results" / "toolchain_controls.json"
    p.write_text(json.dumps(res, indent=1))
    for o in out:
        print(o)


if __name__ == "__main__":
    main()

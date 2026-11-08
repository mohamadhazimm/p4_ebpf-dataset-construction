"""Local complete-driver regression and guest entry point for the V4 capture-path-probe adapter."""

import argparse
import ast
import copy
import inspect
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import check_performance_v3 as frozen
import performance_v4 as performance


ROOT = Path(__file__).resolve().parent
gate = frozen.gate
identity = performance.identity
FROZEN_DRIVER_SHA256 = "d09e5ad186d44961a4149b6515da2ac1b719500d86356c5b7d2cfa367f21a5b4"
ORIGINAL_AUDIT_RUN = gate.audit_run


def require(condition, message):
    if not condition:
        raise ValueError(message)


def require_probe(directory, case):
    if case["condition"] != "baseline":
        metadata = json.loads((Path(directory) / "run.json").read_text())
        probe = metadata.get("capture_path_probe") or {}
        saved = json.loads((Path(directory) / performance.PROBE_FILE).read_text())
        require(probe == saved and probe.get("status") == "recovered" and not probe.get("findings")
                and all(probe["recovery"][phase]["recovered"] for phase in ("pre", "post")),
                "capture_path_probe_not_recovered")
    else:
        require(not (Path(directory) / performance.PROBE_FILE).exists(), "Baseline unexpectedly probed")


def audit_run(directory, manifest, case, inner=None):
    row = (inner or ORIGINAL_AUDIT_RUN)(directory, manifest, case)
    require_probe(directory, case)
    return row


def guest(root):
    # Wrap the auditor installed at call time: the real original in production, a stub in simulation.
    inner = gate.audit_run
    with patch.object(gate, "performance", performance), \
            patch.object(gate, "audit_run", lambda directory, manifest, case: audit_run(directory, manifest, case, inner)):
        return gate.guest(root)


def load_driver():
    if identity.digest(Path(frozen.__file__)) != FROZEN_DRIVER_SHA256:
        raise ValueError("Measured V3 driver changed")
    tree = ast.parse(inspect.getsource(frozen.load_driver))
    namespace = {**vars(frozen), "__file__": __file__, "performance": performance,
                 "adapt_tree": adapt_tree, "types_namespace": types_namespace}
    exec(compile(tree, "<performance-v4-loader>", "exec"), namespace)
    return namespace["load_driver"]()


def types_namespace():
    return SimpleNamespace(**{**vars(identity), "generate": performance.generate,
                              "self_test": performance.self_test, "SCHEMA": performance.SCHEMA,
                              "__file__": str(ROOT / "integrated_attribution.py")})


def adapt_tree(tree):
    tree = frozen.adapt_tree(tree)
    substitutions = {"scoped-performance-v3": "scoped-performance-v4",
                     "clean-performance-v3-": "clean-performance-v4-",
                     "/home/csci/Downloads/performance-v3-": "/home/csci/Downloads/performance-v4-"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            node.value = substitutions.get(node.value, node.value)
    freeze = next(node for node in tree.body if node.name == "freeze")
    payload = next(node for node in freeze.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "payload" for target in node.targets))
    for name in ("performance_v4.py", "check_performance_v3.py", "PERFORMANCE_PROTOCOL_V4.md"):
        payload.value.keys.append(ast.Constant(name))
        payload.value.values.append(ast.parse("ROOT / " + repr(name), mode="eval").body)
    return tree


def self_test():
    import tempfile

    performance.self_test()
    frozen.self_test()
    driver = load_driver()
    assert callable(driver["freeze"]) and callable(driver["execute"])
    assert driver["integration"].SCHEMA == performance.SCHEMA
    assert driver["integration"].generate is performance.generate
    tree = ast.parse((ROOT / "check_integrated_attribution.py").read_text())
    tree.body = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name in ("freeze", "execute", "runner_command")]
    payload_tree = adapt_tree(tree)
    text = ast.unparse(payload_tree)
    assert "scoped-performance-v4" in text and "scoped-performance-v3" not in text and "performance-v4-" in text
    freeze = next(node for node in payload_tree.body if node.name == "freeze")
    payload = next(node for node in freeze.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "payload" for target in node.targets))
    names = [node.value for node in payload.value.keys if isinstance(node, ast.Constant)]
    assert all(name in names for name in ("performance_v4.py", "check_performance_v3.py", "performance_v3.py",
                                          "check_performance_v2.py", "performance_v2.py", "check_scoped_performance.py"))
    assert len(names) == len(set(names))

    rows = [{**case, "usage": {"returncode": 0, "wall_ns": 100, "user_seconds": .1, "system_seconds": .01,
                               "peak_rss_kib": 1024}, "recorder_usage": {"peak_rss_kib": 1024}} for case in gate.plan()]
    probed = []
    with patch.object(frozen, "guest", guest), \
            patch.dict(globals(), require_probe=lambda _directory, case: probed.append(case["condition"])):
        accepted, report, count = frozen.simulate_guest(rows)
    assert accepted and count == 84 and report["measurements"] == rows
    assert probed == [case["condition"] for case in gate.plan()]
    assert probed.count("baseline") == 28 and len(probed) - probed.count("baseline") == 56

    def failing_probe(_directory, case):
        probed.append(case["condition"])
        if len(probed) == 8:
            raise ValueError("capture_path_probe_not_recovered")
    probed.clear()
    with patch.object(frozen, "guest", guest), patch.dict(globals(), require_probe=failing_probe):
        accepted, report, count = frozen.simulate_guest(rows)
    assert not accepted and count == 8 and len(report["measurements"]) == 7
    assert "capture_path_probe_not_recovered" in report["error"]

    recovered = {"status": "recovered", "findings": [], "recovery": {"pre": {"recovered": True}, "post": {"recovered": True}}}
    inner = lambda *_arguments: {"row": 1}
    with tempfile.TemporaryDirectory(prefix="hazim-performance-v4-audit-") as directory:
        run = Path(directory)
        case = next(item for item in gate.plan() if item["condition"] == "original")
        baseline = next(item for item in gate.plan() if item["condition"] == "baseline")
        variants = {"accepted": (recovered, recovered, True), "absent": (None, None, False),
                    "rejected": ({**recovered, "status": "rejected", "findings": ["x"]}, None, False),
                    "post_missing": ({**recovered, "recovery": {"pre": {"recovered": True}, "post": {"recovered": False}}}, None, False),
                    "mismatch": (recovered, {**recovered, "status": "other"}, False)}
        for name, (metadata_probe, file_probe, expected) in variants.items():
            metadata = {} if metadata_probe is None else {"capture_path_probe": metadata_probe}
            (run / "run.json").write_text(json.dumps(metadata))
            probe_path = run / performance.PROBE_FILE
            probe_path.unlink(missing_ok=True)
            if metadata_probe is not None:
                probe_path.write_text(json.dumps(file_probe or metadata_probe))
            try:
                audit_run(run, {}, case, inner)
                outcome = True
            except (ValueError, FileNotFoundError):
                outcome = False
            assert outcome == expected, name
        probe_path.write_text("{}")
        try:
            audit_run(run, {}, baseline, inner)
            raise AssertionError("baseline with probe file accepted")
        except ValueError:
            pass
        probe_path.unlink()
        assert audit_run(run, {}, baseline, inner) == {"row": 1}
    print("PASS V4 driver/payload binding, 84-case simulated completion (probe check on 56 sensor cases, 0 baseline), "
          "probe-failure stop at position8, and probe-evidence audit guards; SIMULATED, no VM")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--guest", type=Path)
    options = parser.parse_args()
    if options.self_test:
        self_test()
    else:
        import signal
        signal.signal(signal.SIGTERM, lambda *_arguments: (_ for _ in ()).throw(KeyboardInterrupt()))
        raise SystemExit(0 if guest(options.guest.resolve()) else 2)

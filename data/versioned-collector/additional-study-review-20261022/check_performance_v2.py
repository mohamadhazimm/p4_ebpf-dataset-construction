"""Freeze one separately approved performance attempt; preserve the failed .21 run."""

import argparse
import ast
import copy
import inspect
import json
import signal
from pathlib import Path
from types import SimpleNamespace

import check_scoped_performance as gate
import performance_v2 as performance


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
identity = performance.identity
gate.performance = performance
PINS = {
    "scoped-performance/20261023T082811709603Z/protocol.json": "18b2e85ddf98da6629a4887943a9fab172fc2853eab5bb5bd881a389492fc9bd",
    "capture-liveness-v4-readiness/20261023T114938416460Z/protocol.json": "7a9c01f813de04901ad2697e9a7580d977f508cb119567691309bd22d97e6023",
}


def verify_inputs():
    hashes = {}
    for relative, expected in PINS.items():
        path = ROOT / relative
        if identity.digest(path) != expected:
            raise ValueError("Frozen input protocol changed: " + relative)
        hashes[str(path)] = expected
        for name, expected_source in json.loads(path.read_text())["source_hashes"].items():
            if identity.digest(name) != expected_source:
                raise ValueError("Frozen input source changed: " + name)
            hashes[name] = expected_source
    return hashes


def adapt_tree(tree):
    changes = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "export_original_sources":
            names = [alias.name for alias in node.names]
            if "wait_guest" in names:
                node.names = [alias for alias in node.names if alias.name != "wait_guest"]
                changes += 1
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            node.value = {"integrated-collector-readiness": "scoped-performance-v2",
                          "clean-integrated-": "clean-performance-v2-",
                          "/home/csci/Downloads/integrated-": "/home/csci/Downloads/performance-v2-"}.get(node.value, node.value)
    if changes != 1:
        raise ValueError("Frozen startup import anchor differs")
    freeze = next(node for node in tree.body if node.name == "freeze")
    payload = next(node for node in freeze.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "payload" for target in node.targets))
    for name in ("check_scoped_performance.py", "performance_v2.py", "PERFORMANCE_PROTOCOL_V2.md",
                 "audit_performance_v2.py", "audit_scoped_performance.py"):
        payload.value.keys.append(ast.Constant(name))
        payload.value.values.append(ast.parse("ROOT / " + repr(name), mode="eval").body)
    return tree


def types_namespace():
    return SimpleNamespace(**{**vars(identity), "generate": performance.generate, "self_test": performance.self_test,
                              "SCHEMA": performance.SCHEMA, "__file__": str(ROOT / "integrated_attribution.py")})


def load_driver():
    tree = ast.parse(inspect.getsource(gate.load_driver))
    function = tree.body[0]
    for index, node in enumerate(function.body):
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Attribute) and ast.unparse(target) == "tree.body" for target in node.targets):
            function.body[index + 1:index + 1] = ast.parse("tree = adapt_tree(tree)").body
            break
    else:
        raise ValueError("Frozen loader filter anchor differs")
    namespace = {**vars(gate), "__file__": __file__, "performance": performance,
                 "types_namespace": types_namespace, "adapt_tree": adapt_tree}
    exec(compile(ast.fix_missing_locations(tree), "<versioned-performance-loader>", "exec"), namespace)
    result = namespace["load_driver"]()
    result["wait_guest"] = wait_guest
    return result


def wait_guest(helper, auth, log):
    import capture_liveness_v4
    return capture_liveness_v4.wait_guest(helper, auth, log)


def freeze():
    source_hashes = verify_inputs()
    driver = load_driver()
    attempt, manifest = driver["freeze"]()
    protocol_path = attempt / "protocol.json"
    protocol = json.loads(protocol_path.read_text())
    protocol["source_hashes"].update(source_hashes)
    protocol.update(approval="Explicit Approve Versioned Harness And One Benign Performance Attempt",
                    fresh_attempts_authorized=1, recorder_seconds=22, acknowledgement_seconds=12,
                    diagnostic_28s_lifetime_imported=False, helper_transactions=0,
                    timing_boundary_unchanged=True, task_source_unchanged=True,
                    malware_launch_authorized=False, fitting_authorized=False)
    protocol_path.write_text(json.dumps(protocol, indent=2, sort_keys=True) + "\n")
    return attempt, manifest, driver


def self_test():
    verify_inputs()
    performance.self_test()
    assert gate.plan() == json.loads((ROOT / "scoped-performance/20261023T082811709603Z/manifest.json").read_text())["cases"]
    driver = load_driver()
    assert "wait_guest" in driver
    generated = performance.generate(STUDY / "src/malware_runner.py")
    assert "performance_v2.launch" in generated and "scoped_performance.launch" not in generated
    assert generated.index("attribution.observation_end(") < generated.index("observation_ended_ns = min(")
    import sys
    from unittest.mock import patch
    sys.path.insert(0, str(STUDY))
    from tests.test_malware_runner_hostmon import malware_runner
    for case in gate.plan():
        command = gate.runner_command(Path("/owned"), case)
        with patch.object(sys, "argv", command[1:]):
            args = malware_runner.parse_args()
        assert args.timeout == 20 and args.window_sec == 0.5 and args.fixed_observation and args.common_launch_wrapper
    import capture_liveness_v4
    capture_liveness_v4.startup_self_test()
    print("PASS unchanged84-case order, all original runner argv, separate startup binding, unchanged22s recorder request and12s acknowledgement contract")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--freeze-only", action="store_true")
    action.add_argument("--execute-benign-checks", action="store_true")
    action.add_argument("--guest", type=Path)
    options = parser.parse_args()
    if options.guest:
        signal.signal(signal.SIGTERM, lambda *_arguments: (_ for _ in ()).throw(KeyboardInterrupt()))
        raise SystemExit(0 if gate.guest(options.guest.resolve()) else 2)
    else:
        self_test()
        if not options.self_test:
            attempt, manifest, driver = freeze()
            if options.execute_benign_checks:
                signal.signal(signal.SIGTERM, lambda *_arguments: (_ for _ in ()).throw(KeyboardInterrupt()))
                driver["execute"](attempt, manifest)
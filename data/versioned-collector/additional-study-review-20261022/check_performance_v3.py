"""Local complete-driver regression for the separately versioned V3 adapter."""

import argparse
import ast
import copy
import inspect
import json
import tarfile
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import audit_performance_v2 as independent
import check_performance_v2 as frozen
import performance_v3 as performance


ROOT = Path(__file__).resolve().parent
gate = frozen.gate
identity = performance.identity
FROZEN_DRIVER_SHA256 = "aad3391ff581c213a22e638e5396050f3163d64fb5027c4d1f74805c24a64564"


def guest(root):
    with patch.object(gate, "performance", performance):
        return gate.guest(root)


def load_driver():
    if identity.digest(Path(frozen.__file__)) != FROZEN_DRIVER_SHA256:
        raise ValueError("Measured V2 driver changed")
    tree = ast.parse(inspect.getsource(frozen.load_driver))
    namespace = {**vars(frozen), "__file__": __file__, "performance": performance,
                 "adapt_tree": adapt_tree, "types_namespace": types_namespace}
    exec(compile(tree, "<performance-v3-loader>", "exec"), namespace)
    return namespace["load_driver"]()


def types_namespace():
    return SimpleNamespace(**{**vars(identity), "generate": performance.generate,
                              "self_test": performance.self_test, "SCHEMA": performance.SCHEMA,
                              "__file__": str(ROOT / "integrated_attribution.py")})


def adapt_tree(tree):
    tree = frozen.adapt_tree(tree)
    substitutions = {"scoped-performance-v2": "scoped-performance-v3",
                     "clean-performance-v2-": "clean-performance-v3-",
                     "/home/csci/Downloads/performance-v2-": "/home/csci/Downloads/performance-v3-"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            node.value = substitutions.get(node.value, node.value)
    freeze = next(node for node in tree.body if node.name == "freeze")
    payload = next(node for node in freeze.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "payload" for target in node.targets))
    for name in ("performance_v3.py", "check_performance_v2.py", "PERFORMANCE_PROTOCOL_V3.md"):
        payload.value.keys.append(ast.Constant(name))
        payload.value.values.append(ast.parse("ROOT / " + repr(name), mode="eval").body)
    return tree


def simulate_guest(rows, fault=None):
    with tempfile.TemporaryDirectory(prefix="hazim-performance-v3-driver-") as directory:
        root = Path(directory)
        for name in ("attribution-v6", "lifecycle.bpf.o", ".sudo-password"):
            (root / name).write_bytes(b"synthetic fixture only\n")
        manifest = {"files": {name: identity.digest(root / name)
                              for name in ("attribution-v6", "lifecycle.bpf.o")},
                    "guest_btf_sha256": "0" * 64, "cases": gate.plan()}
        identity.save(root / "manifest.json", manifest)
        identity.save(root / "contract.json", gate.approved_contract())
        executed = []

        def popen(command, **kwargs):
            case = manifest["cases"][len(executed)]
            expected = gate.runner_command(root, case)
            if case["condition"] == "baseline":
                position = expected.index("--iface")
                del expected[position:position + 2]
            assert command == expected
            assert kwargs["env"]["HAZIM_PERFORMANCE_CONDITION"] == case["condition"]
            assert kwargs["start_new_session"]
            assert json.loads((root / (case["mode"] + "-args.json")).read_text()) == [case["task"]]
            for name in (".pcap-auth", ".ebpf-auth"):
                assert (root / name).stat().st_mode & 0o777 == 0o600
            run = root / ("output-" + case["mode"]) / "run"
            run.mkdir(parents=True)
            executed.append(case)
            process = MagicMock()
            process.wait.return_value = 1 if fault == "runner" and len(executed) == 8 else 0
            process.poll.return_value = 0
            return process

        def audit_run(_directory, _manifest, case):
            assert case == executed[-1]
            if fault == "quiet" and len(executed) == 8:
                raise ValueError("packet_capture_interface_no_traffic")
            return copy.deepcopy(rows[len(executed) - 1])

        with patch.object(gate.subprocess, "Popen", side_effect=popen), \
                patch.object(gate, "audit_run", side_effect=audit_run), patch("builtins.print"):
            accepted = guest(root)
        report = json.loads((root / "guest_result.json").read_text())
        assert not report["collection_ready"] and report["malware_executions"] == 0
        assert all(not (root / name).exists() for name in (".sudo-password", ".pcap-auth", ".ebpf-auth"))
        with tarfile.open(root / "evidence.tgz", "r:gz") as archive:
            members = archive.getmembers()
            assert all(member.isfile() and not member.name.startswith("/")
                       and ".." not in Path(member.name).parts for member in members)
            assert "guest_result.json" in archive.getnames()
            assert not any(Path(member.name).name in (".sudo-password", ".pcap-auth", ".ebpf-auth")
                           for member in members)
            assert json.load(archive.extractfile("guest_result.json")) == report
        return accepted, report, len(executed)


def self_test():
    performance.self_test()
    frozen.self_test()
    independent.self_test()
    driver = load_driver()
    assert callable(driver["freeze"]) and callable(driver["execute"])
    assert driver["integration"].SCHEMA == performance.SCHEMA
    assert driver["integration"].generate is performance.generate
    tree = ast.parse((ROOT / "check_integrated_attribution.py").read_text())
    tree.body = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name in ("freeze", "execute", "runner_command")]
    payload_tree = adapt_tree(tree)
    freeze = next(node for node in payload_tree.body if node.name == "freeze")
    payload = next(node for node in freeze.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "payload" for target in node.targets))
    names = [node.value for node in payload.value.keys if isinstance(node, ast.Constant)]
    assert all(name in names for name in ("performance_v3.py", "check_performance_v2.py",
                                          "performance_v2.py", "check_scoped_performance.py"))
    assert len(names) == len(set(names))
    rows = [{**case, "usage": {"returncode": 0, "wall_ns": 100,
                              "user_seconds": .1, "system_seconds": .01, "peak_rss_kib": 1024},
             "recorder_usage": {"peak_rss_kib": 1024}} for case in gate.plan()]
    accepted, report, count = simulate_guest(rows)
    assert accepted and count == 84 and report["status"] == "accepted_bounded_performance"
    assert report["measurements"] == rows and len(report["groups"]) == 4
    assert independent.summary(report["measurements"], gate.approved_contract()["performance_limits"])["performance_accepted"]
    with patch.dict(vars(performance)):
        del performance.summarize
        accepted, report, count = simulate_guest(rows)
    assert not accepted and count == 84 and "AttributeError" in report["error"]
    for fault in ("quiet", "runner"):
        accepted, report, count = simulate_guest(rows, fault)
        assert not accepted and count == 8 and len(report["measurements"]) == 7
        assert report["status"] == "failed_preserved"
    changed = copy.deepcopy(rows)
    next(row for row in changed if not row["warmup"] and row["condition"] == "full")["usage"]["wall_ns"] = 126
    accepted, report, count = simulate_guest(changed)
    assert not accepted and count == 9 and report["status"] == "performance_budget_failed_preserved"
    for metric, value in (("wall_ns", 111), ("user_seconds", .2), ("peak_rss_kib", 256 * 1024 + 1)):
        changed = copy.deepcopy(rows)
        for row in changed:
            if not row["warmup"] and row["condition"] == "full":
                target = row["recorder_usage"] if metric == "peak_rss_kib" else row["usage"]
                target[metric] = value
        accepted, report, count = simulate_guest(changed)
        assert not accepted and count == 84 and report["status"] == "performance_budget_failed_preserved"
    print("PASS actual guest-driver84-case completion, independent summary, missing-API/quiet/runner/any-pair/median/CPU/RSS guards and credential/archive cleanup; SIMULATED, no VM or performance acceptance")


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
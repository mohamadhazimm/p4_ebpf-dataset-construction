"""Derive the DRAFT production runner schema .19 from the hash-pinned .18 runner.

.19 = .18 plus per-sample capture-path probes (the guest-tested V4 benchmark design): one bounded TCP probe to
the internal Sink after tcpdump readiness and one after eBPF shutdown, both required to be recovered from the
published PCAP outside the feature windows. Every original function/class is byte-identical in AST; main()
gains exactly three statements. The draft is written to collector-v19/ and never replaces src/malware_runner.py;
promoting it is a separate, explicitly approved step (frozen tools pin the .18 hash).
"""

import argparse
import ast
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import performance_v4


ROOT = Path(__file__).resolve().parent
STUDY = ROOT.parents[2]
SOURCE = STUDY / "src/malware_runner.py"
SOURCE_SHA256 = "3bc8f91bec262bee4e5c4ae4a26ae6d7525b8b40ddddc17c5a2f39903e17fe49"
OUTPUT = ROOT / "collector-v19/malware_runner.py"
SCHEMA = "2026-10-24.19"
RENAME = {"TARGET": "CAPTURE_PATH_TARGET", "CONNECT_TIMEOUT_SECONDS": "CAPTURE_PATH_CONNECT_TIMEOUT_SECONDS",
          "SETTLE_SECONDS": "CAPTURE_PATH_SETTLE_SECONDS", "MATCH_SLACK_NS": "CAPTURE_PATH_MATCH_SLACK_NS",
          "PROBE_FILE": "CAPTURE_PATH_PROBE_FILE", "PROBES": "CAPTURE_PATH_PROBES",
          "capture_path_probe": "capture_path_probe", "pcap_frames": "capture_path_pcap_frames",
          "tcp_frames": "capture_path_tcp_frames", "recover": "capture_path_recover",
          "probe_quality": "capture_path_probe_quality", "SCHEMA": "TELEMETRY_SCHEMA_VERSION"}
CALLS = ["capture_path_probe('pre', packet_collector)", "capture_path_probe('post', packet_collector)",
         "(quality_status, quality_reasons) = capture_path_probe_quality(run_dir, metadata, args.iface is not None, "
         "sample_started_wall, args.window_sec, rows, quality_status, quality_reasons)"]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def probe_block():
    """Probe constants/functions copied from the guest-tested V4 adapter, renamed into the runner namespace."""
    tree = ast.parse(Path(performance_v4.__file__).read_text())
    wanted = {"TARGET", "CONNECT_TIMEOUT_SECONDS", "SETTLE_SECONDS", "MATCH_SLACK_NS", "PROBE_FILE", "PROBES"}
    functions = {"capture_path_probe", "pcap_frames", "tcp_frames", "recover", "probe_quality"}
    nodes = [node for node in tree.body if (isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
             and node.targets[0].id in wanted) or (isinstance(node, ast.FunctionDef) and node.name in functions)]
    if len(nodes) != len(wanted) + len(functions):
        raise ValueError("V4 probe source anchors differ")

    class Rename(ast.NodeTransformer):
        def visit_Name(self, node):
            node.id = RENAME.get(node.id, node.id)
            return node

        def visit_FunctionDef(self, node):
            node.name = RENAME.get(node.name, node.name)
            self.generic_visit(node)
            return node

    return [ast.parse("import socket").body[0]] + [Rename().visit(node) for node in nodes]


def generate():
    if digest(SOURCE) != SOURCE_SHA256:
        raise ValueError("Production .18 runner changed; refusing to derive .19")
    tree = ast.parse(SOURCE.read_text())
    schema = [node for node in tree.body if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
              and node.targets[0].id == "TELEMETRY_SCHEMA_VERSION"]
    if len(schema) != 1:
        raise ValueError("Schema anchor differs")
    schema[0].value = ast.Constant(SCHEMA)
    index = next(i for i, node in enumerate(tree.body) if isinstance(node, ast.FunctionDef) and node.name == "main")
    tree.body[index:index] = probe_block()
    main = tree.body[index + len(probe_block())]
    block, position = performance_v4._locate(main, lambda node: performance_v4._is_call(node, "packet_collector.start()"), "start")
    block.insert(position + 1, ast.parse(CALLS[0]).body[0])
    block, position = performance_v4._locate(main, lambda node: isinstance(node, ast.If)
                                             and ast.unparse(node.test) == "packet_collector is not None"
                                             and len(node.body) == 1
                                             and performance_v4._is_call(node.body[0], "packet_collector.stop()"), "stop")
    block.insert(position, ast.parse(CALLS[1]).body[0])
    block, position = performance_v4._locate(main, lambda node: isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                                             and ast.unparse(node.value.func) == "assess_collection_quality", "quality")
    block.insert(position + 1, ast.parse(CALLS[2]).body[0])
    text = '"""Malware runner schema ' + SCHEMA + ' DRAFT, derived by build_runner_v19.py from .18 ' + SOURCE_SHA256 + '."""\n' \
        + ast.unparse(ast.fix_missing_locations(tree)) + "\n"
    compile(text, "malware_runner_v19", "exec")
    return text


def self_test():
    text = generate()
    old, new = ast.parse(SOURCE.read_text()), ast.parse(text)
    keep = lambda tree: {node.name: ast.dump(node) for node in tree.body
                         if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name != "main"}
    added = set(keep(new)) - set(keep(old))
    assert added == {"capture_path_probe", "capture_path_pcap_frames", "capture_path_tcp_frames",
                     "capture_path_recover", "capture_path_probe_quality"}, added
    assert all(keep(new)[name] == dump for name, dump in keep(old).items()), "An original function/class changed"
    old_main = next(node for node in old.body if isinstance(node, ast.FunctionDef) and node.name == "main")
    new_main = next(node for node in new.body if isinstance(node, ast.FunctionDef) and node.name == "main")
    removed = {ast.unparse(node) for node in ast.walk(old_main) if isinstance(node, ast.stmt)}
    extra = [ast.unparse(node) for node in ast.walk(new_main) if isinstance(node, ast.stmt) and ast.unparse(node) not in removed]
    assert all(any(call in item for call in CALLS) or "\n" in item for item in extra), extra
    assert sum(text.count(call) for call in CALLS) == 3
    order = ["packet_collector.start()", "capture_path_probe('pre', packet_collector)", "ebpf_collector.start()",
             "sample_started_wall = time.time()", "ebpf_collector.stop()", "capture_path_probe('post', packet_collector)",
             "packet_collector.stop()", "= assess_collection_quality(", "capture_path_probe_quality(run_dir"]
    main_text = ast.unparse(new_main)
    positions = [main_text.index(item) for item in order]
    assert positions == sorted(positions), "Probe ordering differs"
    assert "performance_v4" not in text and "TELEMETRY_SCHEMA_VERSION = '%s'" % SCHEMA in text

    # Existing runner suite against the draft. Only src/ is copied; every other study entry (tests, scripts, ...)
    # is symlinked so imports resolve exactly as in the real repository. Control run: the copied unchanged .18
    # must pass everything; the draft may differ only in the two explicit .18 schema-string assertions.
    expected = {"test_capture_loss_configuration_and_quality_gate", "test_print_feature_schema_does_not_require_or_execute_a_sample"}
    outcomes = {}
    for label, runner in (("v18_control", SOURCE.read_text()), ("v19_draft", text)):
        with tempfile.TemporaryDirectory(prefix="hazim-runner-v19-") as directory:
            work = Path(directory)
            for entry in STUDY.iterdir():
                if entry.name != "src":
                    (work / entry.name).symlink_to(entry)
            shutil.copytree(STUDY / "src", work / "src", ignore=shutil.ignore_patterns("__pycache__"))
            (work / "src/malware_runner.py").write_text(runner)
            result = subprocess.run([sys.executable, "-m", "unittest", "tests.test_malware_runner_hostmon", "tests.test_exec_boundary"],
                                    cwd=work, capture_output=True, text=True)
        failures = [line.split()[1] for line in result.stderr.splitlines() if line.startswith(("FAIL:", "ERROR:"))]
        outcomes[label] = {"ran": [line for line in result.stderr.splitlines() if line.startswith("Ran ")], "failures": failures}
    assert outcomes["v18_control"]["failures"] == [], outcomes["v18_control"]
    assert set(outcomes["v19_draft"]["failures"]) == expected, outcomes["v19_draft"]
    return {"suite": outcomes, "expected_schema_failures": sorted(expected)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--build", action="store_true")
    options = parser.parse_args()
    report = self_test()
    print("PASS .19 derivation: unchanged original functions/classes, three main statements, probe ordering; existing suite",
          report["suite"], "with only the expected schema-string failures:", report["expected_schema_failures"])
    if options.build:
        OUTPUT.parent.mkdir(exist_ok=True)
        if OUTPUT.exists():
            raise FileExistsError(OUTPUT)
        OUTPUT.write_text(generate())
        build = {"schema": SCHEMA, "source": str(SOURCE), "source_sha256": SOURCE_SHA256, "output_sha256": digest(OUTPUT),
                 "builder_sha256": digest(__file__), "probe_source": str(Path(performance_v4.__file__)),
                 "probe_source_sha256": digest(performance_v4.__file__), "promoted_to_src": False, **report}
        (OUTPUT.parent / "build.json").write_text(json.dumps(build, indent=2, sort_keys=True) + "\n")
        print(OUTPUT, build["output_sha256"])


if __name__ == "__main__":
    main()

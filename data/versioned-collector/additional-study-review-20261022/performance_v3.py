"""Completion API correction over the immutable performance V2 lifecycle."""

import argparse
import ast
import hashlib
import signal
from pathlib import Path

import performance_v2 as frozen


ROOT = Path(__file__).resolve().parent
SCHEMA = "2026-10-23.26-performance-completion-harness"
FROZEN_SHA256 = "bc5a337dd08854dddb106c2909f53857ca78fd323dab049c605cadce949b57e5"
if hashlib.sha256(Path(frozen.__file__).read_bytes()).hexdigest() != FROZEN_SHA256:
    raise ValueError("Measured performance V2 source changed")

identity = frozen.identity
launch = frozen.launch
write_task_usage = frozen.write_task_usage
original_sensors_enabled = frozen.original_sensors_enabled
broker = frozen.broker
summarize = frozen.previous.summarize


class Session(frozen.Session):
    def prepare(self, run_dir, sample):
        original_file = frozen.__file__
        frozen.__file__ = __file__
        try:
            return super().prepare(run_dir, sample)
        finally:
            frozen.__file__ = original_file


def generate(base):
    tree = ast.parse(frozen.generate(base))
    imports = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "performance_v2":
                    alias.name = "performance_v3"
                    imports += 1
        elif isinstance(node, ast.Name) and node.id == "performance_v2":
            node.id = "performance_v3"
        elif isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "TELEMETRY_SCHEMA_VERSION"
            for target in node.targets
        ):
            node.value = ast.Constant(SCHEMA)
    if imports != 1:
        raise ValueError("Frozen performance import anchor differs")
    generated = ast.unparse(ast.fix_missing_locations(tree)) + "\n"
    compile(generated, "performance-v3-runner", "exec")
    return generated


def self_test(base=None):
    from unittest.mock import patch

    base = Path(base) if base is not None else ROOT.parents[2] / "src/malware_runner.py"
    assert not hasattr(frozen, "summarize")
    assert summarize is frozen.previous.summarize
    generated = generate(base)
    assert "performance_v3.launch" in generated
    assert "performance_v2.launch" not in generated
    assert generated.index("attribution.observation_end(") < generated.index("observation_ended_ns = min(")
    before = {node.name: ast.dump(node) for node in ast.parse(base.read_text()).body
              if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name != "main"}
    after = {node.name: ast.dump(node) for node in ast.parse(generated).body
             if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name != "main"}
    assert before == after
    original_file = frozen.__file__
    session = Session.__new__(Session)
    for failure in (False, True):
        def prepare(_session, _run_dir, _sample):
            assert frozen.previous.__file__ == __file__
            if failure:
                raise ValueError("Injected prepare failure")
            return "prepared"
        with patch.object(frozen.previous.Session, "prepare", prepare):
            try:
                assert session.prepare(Path("/owned"), "sample") == "prepared"
                assert not failure
            except ValueError:
                assert failure
        assert frozen.__file__ == original_file
    print("PASS V3 completion export, unchanged feature helpers, generated binding and broker routing/restoration")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--self-test", action="store_true")
    action.add_argument("--broker", type=Path)
    options = parser.parse_args()
    if options.self_test:
        self_test()
    else:
        signal.signal(signal.SIGTERM, lambda *_arguments: (_ for _ in ()).throw(KeyboardInterrupt()))
        broker(options.broker)
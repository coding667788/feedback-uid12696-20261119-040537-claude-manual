"""命令行端到端测试：python -m solution --input ... --output ..."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

import _bootstrap  # noqa: F401
from _bootstrap import CASES_PATH, ROOT


def _run_cli(input_path: str, output_path: str) -> subprocess.CompletedProcess:
    # -I 隔离模式会忽略 PYTHONPATH，因此用 -c 先把仓库根注入 sys.path，
    # 再调用 solution 的 main()，等价于 python -m solution。
    bootstrap = (
        "import sys; sys.path.insert(0, r'%s'); "
        "from solution.__main__ import main; "
        "sys.exit(main(['--input', r'%s', '--output', r'%s']))"
        % (ROOT, input_path, output_path))
    return subprocess.run(
        [sys.executable, "-I", "-c", bootstrap],
        cwd=ROOT, capture_output=True, text=True)


class TestCli(unittest.TestCase):

    def test_cli_multi_case_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "result.json")
            proc = _run_cli(CASES_PATH, out_path)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            with open(out_path, "r", encoding="utf-8") as f:
                report = json.load(f)
        self.assertEqual(report["schema"], "forensic-package-results/1")
        statuses = {r["case_id"]: r["status"] for r in report["results"]}
        self.assertEqual(statuses["basic_sat"], "SAT")
        self.assertEqual(statuses["joint_clock_conflict"], "UNSAT")
        self.assertEqual(len(report["results"]), 12)

    def test_cli_single_package_input(self):
        with open(CASES_PATH, "r", encoding="utf-8") as f:
            single = json.load(f)["cases"][0]
        with tempfile.TemporaryDirectory() as tmp:
            in_path = os.path.join(tmp, "one.json")
            out_path = os.path.join(tmp, "result.json")
            with open(in_path, "w", encoding="utf-8") as f:
                json.dump(single, f, ensure_ascii=False)
            proc = _run_cli(in_path, out_path)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            with open(out_path, "r", encoding="utf-8") as f:
                report = json.load(f)
        self.assertEqual(report["schema"], "forensic-package-result/1")
        self.assertEqual(report["result"]["status"], "SAT")


if __name__ == "__main__":
    unittest.main(verbosity=2)

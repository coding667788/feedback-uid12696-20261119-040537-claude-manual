"""命令行入口：

    python -m solution --input cases.json --output result.json

输入支持单个保全包对象，或带 ``cases`` 数组的多包文件；
后者对每个包分别求解并在 ``results`` 中按序输出。
"""

from __future__ import annotations

import argparse
import json
import sys

from .errors import INVALID_CASE, PACKAGE_TOO_LARGE
from .model import CaseError, load_package
from .report import build_report
from .solver import SolverLimitError, solve


def _solve_one(case: dict) -> dict:
    try:
        pkg = load_package(case)
        result = solve(pkg)
    except CaseError as exc:
        return {
            "case_id": case.get("case_id", "unknown"),
            "status": "INVALID",
            "error": {"code": INVALID_CASE, "detail": str(exc)},
        }
    except SolverLimitError as exc:
        return {
            "case_id": case.get("case_id", "unknown"),
            "status": "ERROR",
            "error": {"code": exc.code, "detail": str(exc)},
        }
    return build_report(pkg, result)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="本地数字取证保全包核验器（合成数据，离线）")
    parser.add_argument("--input", required=True, help="输入 JSON 文件")
    parser.add_argument("--output", required=True, help="输出 JSON 文件")
    args = parser.parse_args(argv)

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict) and "cases" in data:
        out = {
            "schema": "forensic-package-results/1",
            "results": [_solve_one(case) for case in data["cases"]],
        }
        exit_code = 0
    else:
        report = _solve_one(data)
        out = {"schema": "forensic-package-result/1", "result": report}
        exit_code = 0 if report.get("status") in ("SAT", "UNSAT") else 2

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
        f.write("\n")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

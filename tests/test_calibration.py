"""差约束时钟校准的单元测试（手工构造的小约束系统）。"""

from __future__ import annotations

import json
import unittest

import _bootstrap  # noqa: F401
from _bootstrap import CASES_PATH

from solution.calibration import (
    enumerate_chains,
    feasible,
    lex_min_offsets,
)
from solution.model import load_package
from solution.solver import Constraints

with open(CASES_PATH, "r", encoding="utf-8") as f:
    _CASES = {c["case_id"]: c for c in json.load(f)["cases"]}


class TestCalibration(unittest.TestCase):

    def test_basic_chain_feasible(self):
        pkg = load_package(_CASES["basic_sat"])
        chains = enumerate_chains(pkg, pkg.evidences["E1"])
        self.assertEqual(len(chains), 1)
        self.assertTrue(feasible(pkg, chains))

    def test_lex_min_offsets_picks_lower_bounds(self):
        pkg = load_package(_CASES["basic_sat"])
        chains = enumerate_chains(pkg, pkg.evidences["E1"])
        offsets = lex_min_offsets(pkg, chains)
        self.assertEqual(offsets, {"INST_A": -50, "INST_B": -50})

    def test_reversal_needs_positive_offset_gap(self):
        pkg = load_package(_CASES["clock_reversal"])
        chains = enumerate_chains(pkg, pkg.evidences["E1"])
        offsets = lex_min_offsets(pkg, chains)
        self.assertGreaterEqual(offsets["INST_A"] - offsets["INST_B"], 50)

    def test_uncalibratable_chain_detected(self):
        pkg = load_package(_CASES["uncalibratable"])
        chains = enumerate_chains(pkg, pkg.evidences["E1"])
        self.assertFalse(feasible(pkg, chains))

    def test_joint_constraints_negative_cycle(self):
        pkg = load_package(_CASES["joint_clock_conflict"])
        all_chains = []
        for eid in sorted(pkg.evidences):
            all_chains += enumerate_chains(pkg, pkg.evidences[eid])
        # 单件各自可行
        for eid in sorted(pkg.evidences):
            self.assertTrue(
                feasible(pkg, enumerate_chains(pkg, pkg.evidences[eid])))
        # 联合出现负环，不可行
        self.assertFalse(feasible(pkg, all_chains))

    def test_upper_bound_deadline_enforced(self):
        # 构造一个签名必然晚于截止时刻的包：截止时刻压到极低
        case = json.loads(json.dumps(_CASES["basic_sat"]))
        case["deadline"] = 0
        pkg = load_package(case)
        chains = enumerate_chains(pkg, pkg.evidences["E1"])
        self.assertFalse(Constraints(pkg, chains).feasible())

    def test_fixed_offset_outside_range_rejected(self):
        pkg = load_package(_CASES["basic_sat"])
        chains = enumerate_chains(pkg, pkg.evidences["E1"])
        self.assertFalse(
            Constraints(pkg, chains).feasible(
                fixed_offsets={"INST_A": 999}))


if __name__ == "__main__":
    unittest.main(verbosity=2)

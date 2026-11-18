"""对 cases.json 全部合成用例断言具体求解结果。

运行：python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import unittest

import _bootstrap  # noqa: F401
from _bootstrap import CASES_PATH

from solution.model import load_package
from solution.solver import solve

with open(CASES_PATH, "r", encoding="utf-8") as f:
    _DATA = json.load(f)
_CASES = {c["case_id"]: c for c in _DATA["cases"]}


def _solve(case_id: str):
    return solve(load_package(_CASES[case_id]))


def _chain_ids(result):
    return {c.evidence_id: [h.handover_id for h in c.handovers]
            for c in result.chains}


def _flat_times(result):
    return [t for seq in result.times for t in seq]


class TestSatisfiableCases(unittest.TestCase):

    def test_basic_sat(self):
        r = _solve("basic_sat")
        self.assertTrue(r.ok)
        self.assertEqual(_chain_ids(r), {"E1": ["H1", "H2"]})
        # 字典序最小偏移：两机构均取下界 -50
        self.assertEqual(r.offsets, {"INST_A": -50, "INST_B": -50})
        times = r.times[0]
        self.assertEqual(times, [50, 150, 160, 250, 270])
        self.assertTrue(all(times[i] <= times[i + 1]
                            for i in range(len(times) - 1)))
        outbound_ids = {
            h.handover_id for c in r.chains for h in c.handovers
            if "outbound" in (h.release.auth_kind, h.receive.auth_kind)}
        self.assertEqual(len(outbound_ids), 1)

    def test_fork_tie_chooses_lex_smaller_chain(self):
        r = _solve("fork_tie")
        self.assertTrue(r.ok)
        # H2A < H2B，按交接 ID 序列决胜选 H2A
        self.assertEqual(_chain_ids(r), {"E1": ["H1", "H2A"]})
        self.assertEqual(r.offsets, {"INST_A": -20, "INST_B": -20})
        self.assertEqual(r.times[0], [80, 100, 110, 120, 130])

    def test_voucher_coupling_picks_long_chain(self):
        # 局部最短链 E1=[H10,H11] 占用 E2 唯一凭单 V_SHARED
        r = _solve("voucher_coupling")
        self.assertTrue(r.ok)
        ids = _chain_ids(r)
        self.assertEqual(ids["E1"], ["H12", "H13", "H14"])
        self.assertEqual(ids["E2"], ["H20", "H21"])
        # 两条链各一个出库项，共 2 个不同出库交接
        outbound_ids = {
            h.handover_id for c in r.chains for h in c.handovers
            if "outbound" in (h.release.auth_kind, h.receive.auth_kind)}
        self.assertEqual(len(outbound_ids), 2)
        # 物理凭单互不重叠
        vouchers = [h.voucher_id for c in r.chains for h in c.handovers]
        self.assertEqual(len(vouchers), len(set(vouchers)))

    def test_clock_reversal_is_calibratable(self):
        r = _solve("clock_reversal")
        self.assertTrue(r.ok)
        self.assertEqual(_chain_ids(r), {"E1": ["H1", "H2"]})
        # 非递减全局时刻；朴素本地读数 200 > 150 的反转被偏移理顺
        times = r.times[0]
        self.assertEqual(times, [100, 120, 120, 150, 160])
        self.assertTrue(all(times[i] <= times[i + 1]
                            for i in range(len(times) - 1)))
        self.assertEqual(r.offsets["INST_A"] - r.offsets["INST_B"], 80)

    def test_forged_fork_excluded(self):
        pkg = load_package(_CASES["forged_fork"])
        bad = pkg.handovers["F2BAD"]
        self.assertFalse(bad.digest_ok)
        self.assertTrue(pkg.handovers["F2OK"].digest_ok)
        r = solve(pkg)
        self.assertTrue(r.ok)
        self.assertEqual(_chain_ids(r), {"E1": ["F1", "F2OK"]})

    def test_out_of_order_and_duplicate(self):
        pkg = load_package(_CASES["out_of_order_dup"])
        # 重复候选被去重，记录在核验说明中
        self.assertTrue(any("D1" in note and "去重" in note
                            for note in pkg.notes))
        self.assertEqual(set(pkg.handovers), {"D1", "D2"})
        r = solve(pkg)
        self.assertTrue(r.ok)
        self.assertEqual(_chain_ids(r), {"E1": ["D1", "D2"]})

    def test_brute_force_oracle_case_sat(self):
        r = _solve("brute_force_oracle")
        self.assertTrue(r.ok)
        ids = _chain_ids(r)
        self.assertEqual(ids, {"E1": ["B1"], "E2": ["B2"]})
        self.assertEqual(r.offsets, {"INST_A": -30, "INST_B": -30})


class TestUnsatisfiableCases(unittest.TestCase):

    def test_joint_clock_conflict(self):
        r = _solve("joint_clock_conflict")
        self.assertFalse(r.ok)
        self.assertEqual(r.code, "GLOBAL_VOUCHER_CONFLICT")
        self.assertEqual(r.detail, "joint_clock_calibration_conflict")

    def test_voucher_conflict(self):
        r = _solve("voucher_conflict")
        self.assertFalse(r.ok)
        self.assertEqual(r.code, "GLOBAL_VOUCHER_CONFLICT")
        self.assertEqual(r.detail, "voucher_occupancy_conflict")

    def test_witness_insufficient(self):
        r = _solve("witness_insufficient")
        self.assertFalse(r.ok)
        self.assertEqual(r.code, "WITNESS_INSUFFICIENT")

    def test_repeated_witness_still_insufficient(self):
        r = _solve("repeated_witness")
        self.assertFalse(r.ok)
        self.assertEqual(r.code, "WITNESS_INSUFFICIENT")

    def test_uncalibratable_reports_per_evidence(self):
        r = _solve("uncalibratable")
        self.assertFalse(r.ok)
        self.assertEqual(r.code, "EVIDENCE_UNCALIBRATABLE")
        self.assertEqual(r.reason_evidence["E2"], "no_structural_chain")
        self.assertEqual(r.reason_evidence["E1"], "clock_not_calibratable")


class TestWitnessCoverage(unittest.TestCase):

    def test_coverage_counts_institutions(self):
        r = _solve("basic_sat")
        self.assertTrue(r.ok)
        from solution.solver import witness_coverage
        cov = witness_coverage(load_package(_CASES["basic_sat"]), r.chains)
        self.assertEqual(set(cov["E1"]), {"INST_A", "INST_B"})


if __name__ == "__main__":
    unittest.main(verbosity=2)

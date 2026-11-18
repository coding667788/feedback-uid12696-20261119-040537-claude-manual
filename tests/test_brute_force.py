"""独立组合穷举交叉验证 + 手工时间/见证核对。"""

from __future__ import annotations

import json
import unittest

import _bootstrap  # noqa: F401
from _bootstrap import CASES_PATH

from solution.model import AUTH_OUTBOUND, load_package
from solution.solver import solve
from tools.brute_force import brute_solve

with open(CASES_PATH, "r", encoding="utf-8") as f:
    _DATA = json.load(f)
_CASES = {c["case_id"]: c for c in _DATA["cases"]}


class TestBruteForceOracle(unittest.TestCase):
    """主求解器与独立穷举器在每个小用例上必须给出同一结论与同一最优解。"""

    def test_every_case_matches_brute_force(self):
        for case in _DATA["cases"]:
            with self.subTest(case=case["case_id"]):
                pkg = load_package(case)
                result = solve(pkg)
                b_status, b_info = brute_solve(pkg)
                if result.ok:
                    self.assertEqual(b_status, "SAT")
                    engine_chain = tuple(
                        tuple(h.handover_id for h in c.handovers)
                        for c in result.chains)
                    engine_flat = [t for seq in result.times for t in seq]
                    engine_ob = len({
                        h.handover_id for c in result.chains for h in c.handovers
                        if AUTH_OUTBOUND in (h.release.auth_kind,
                                             h.receive.auth_kind)})
                    b_out, b_seq, b_flat, _b_off, _b_assign = b_info
                    self.assertEqual(engine_chain, b_seq)
                    self.assertEqual(engine_flat, b_flat)
                    self.assertEqual(engine_ob, len(b_out))
                else:
                    self.assertEqual(result.code, b_status)
                    self.assertEqual(result.detail or "", b_info or "")


class TestHandCheckedTimes(unittest.TestCase):
    """对两个关键 SAT 用例手工核对每一事件的全局时刻与非递减性。"""

    def test_clock_reversal_hand_checked(self):
        r = solve(load_package(_CASES["clock_reversal"]))
        self.assertTrue(r.ok)
        oa, ob = r.offsets["INST_A"], r.offsets["INST_B"]
        # 本地事件：采集 A100；H1 交出 A120 接收 B200；H2 交出 A150 接收 B240
        expected = [100 + oa, 120 + oa, 200 + ob, 150 + oa, 240 + ob]
        self.assertEqual(r.times[0], expected)
        for i in range(len(expected) - 1):
            self.assertLessEqual(expected[i], expected[i + 1])
        # 朴素读法下 H1 接收 200 > H2 交出 150，确实是表面反转
        self.assertGreater(200, 150)
        # 所有签名先于入保全库时刻
        self.assertLessEqual(max(expected), 1000)

    def test_basic_sat_hand_checked_witnesses(self):
        pkg = load_package(_CASES["basic_sat"])
        r = solve(pkg)
        self.assertTrue(r.ok)
        signers = {
            pkg.persons[s.person_id].inst_id
            for c in r.chains for h in c.handovers
            for s in (h.release, h.receive)
        }
        # 至少两类不同机构的独立人员覆盖
        self.assertGreaterEqual(len(signers), pkg.min_witness_kinds)
        self.assertEqual(signers, {"INST_A", "INST_B"})


if __name__ == "__main__":
    unittest.main(verbosity=2)

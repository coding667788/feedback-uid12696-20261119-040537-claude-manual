"""摘要完整性、授权与连接校验的单元测试。"""

from __future__ import annotations

import json
import unittest

import _bootstrap  # noqa: F401
from _bootstrap import CASES_PATH

from solution.model import (
    canonical_handover_digest,
    load_package,
    sha256_hex,
)

with open(CASES_PATH, "r", encoding="utf-8") as f:
    _CASES = {c["case_id"]: c for c in json.load(f)["cases"]}


class TestDigest(unittest.TestCase):

    def test_evidence_sha256_matches_payload(self):
        case = _CASES["basic_sat"]
        ev = case["evidences"][0]
        self.assertEqual(sha256_hex(bytes.fromhex(ev["payload_hex"])),
                         ev["evidence_sha256"])

    def test_handover_digest_is_canonical_sha256(self):
        case = _CASES["basic_sat"]
        for raw in case["handovers"]:
            self.assertEqual(raw["digest"], canonical_handover_digest(raw))

    def test_forged_record_fails_digest_check(self):
        pkg = load_package(_CASES["forged_fork"])
        self.assertFalse(pkg.handovers["F2BAD"].digest_ok)
        # 伪造记录被排除在可用候选之外
        self.assertNotIn("F2BAD",
                         [h.handover_id for h in pkg.usable_handovers()])

    def test_tampering_breaks_digest(self):
        case = json.loads(json.dumps(_CASES["basic_sat"]))
        original = case["handovers"][0]["digest"]
        case["handovers"][0]["voucher_id"] = "V9-TAMPERED"
        # 内容改了但摘要没改 => 核验失败
        case["handovers"][0]["digest"] = original
        pkg = load_package(case)
        self.assertFalse(pkg.handovers["H1"].digest_ok)

    def test_unregistered_person_rejected(self):
        case = json.loads(json.dumps(_CASES["basic_sat"]))
        case["handovers"][0]["release"]["person_id"] = "ghost"
        pkg = load_package(case)
        self.assertFalse(pkg.handovers["H1"].auth_ok)

    def test_missing_authorization_rejected(self):
        case = json.loads(json.dumps(_CASES["basic_sat"]))
        # pa2 只有 inbound 授权，把其签名改成 transfer
        for h in case["handovers"]:
            if h["handover_id"] == "H2":
                h["receive"]["auth_kind"] = "transfer"
                h["digest"] = canonical_handover_digest(h)
        pkg = load_package(case)
        self.assertFalse(pkg.handovers["H2"].auth_ok)

    def test_dangling_prev_digest_linkage_fails(self):
        pkg = load_package(_CASES["uncalibratable"])
        self.assertFalse(pkg.handovers["U2"].linkage_ok)


if __name__ == "__main__":
    unittest.main(verbosity=2)

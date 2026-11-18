"""确定性合成保全包生成器。

运行：

    python -I tools/generate_cases.py

产出同目录下的 cases.json。所有数据均为合成数据：证物字节是构造的
短 ASCII 串，签名是模拟字符串，完全离线、不接触真实取证数据。
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from solution.model import (  # noqa: E402
    AUTH_COLLECT,
    AUTH_INBOUND,
    AUTH_INSPECT,
    AUTH_OUTBOUND,
    AUTH_TRANSFER,
    canonical_handover_digest,
    sha256_hex,
)

# 机构
A = "INST_A"
B = "INST_B"
C = "INST_C"


def inst(iid: str, lo: int, hi: int, name: str | None = None) -> dict:
    return {"inst_id": iid, "name": name or iid,
            "offset_min": lo, "offset_max": hi}


def person(pid: str, iid: str, kinds: list[str], name: str | None = None) -> dict:
    return {"person_id": pid, "name": name or pid,
            "inst_id": iid, "auth_kinds": kinds}


def sig(pid: str, kind: str, ts: int) -> dict:
    return {"person_id": pid, "auth_kind": kind, "local_ts": ts}


def evidence(eid: str, payload: bytes, coll_inst: str, coll_ts: int,
             entry_ts: int, accepted: list[str], tenant: str = "TENANT-X",
             custodian: str = "CUSTODIAN-1",
             cp_inst: str | None = None,
             cp_ts: int | None = None) -> dict:
    col_digest = sha256_hex(
        f"collection|{eid}|{sha256_hex(payload)}|{coll_inst}|{coll_ts}"
        .encode("utf-8"))
    checkpoint = {"accepted_terminal_digests": accepted,
                  "entry_global_ts": entry_ts}
    if cp_inst is not None:
        checkpoint["inst_id"] = cp_inst
        checkpoint["local_ts"] = cp_ts
    return {
        "evidence_id": eid,
        "tenant": tenant,
        "custodian": custodian,
        "payload_hex": payload.hex(),
        "evidence_sha256": sha256_hex(payload),
        "collection": {
            "digest": col_digest,
            "inst_id": coll_inst,
            "local_ts": coll_ts,
        },
        "checkpoint": checkpoint,
    }


def handover(hid: str, eid: str, prev: str, voucher: str,
             rel: dict, rcv: dict, forge: bool = False) -> dict:
    rec = {
        "handover_id": hid,
        "evidence_id": eid,
        "prev_digest": prev,
        "voucher_id": voucher,
        "release": rel,
        "receive": rcv,
    }
    digest = canonical_handover_digest(rec)
    if forge:
        # 伪造：登记一个对不上的摘要（“同摘要新分叉”场景里再单独制造碰撞尝试）
        digest = sha256_hex((digest + "FORGED").encode("utf-8"))
    rec["digest"] = digest
    return rec


def digest_of(rec: dict) -> str:
    return canonical_handover_digest(rec)


# --------------------------------------------------------------------------- #
# 用例 1：基础可解（两机构见证，两跳链）
# --------------------------------------------------------------------------- #

def case_basic_sat() -> dict:
    e1 = evidence("E1", b"SYN-E1-PAYLOAD", A, 100, 1000, accepted=[])
    h1 = handover("H1", "E1", e1["collection"]["digest"], "V1",
                  sig("pa1", AUTH_OUTBOUND, 200),
                  sig("pb1", AUTH_TRANSFER, 210))
    h2 = handover("H2", "E1", h1["digest"], "V2",
                  sig("pb1", AUTH_TRANSFER, 300),
                  sig("pa2", AUTH_INBOUND, 320))
    e1["checkpoint"]["accepted_terminal_digests"] = [h2["digest"]]
    return {
        "case_id": "basic_sat",
        "deadline": 2000,
        "min_witness_kinds": 2,
        "institutions": [inst(A, -50, 50), inst(B, -50, 50)],
        "persons": [
            person("pa1", A, [AUTH_OUTBOUND, AUTH_INSPECT]),
            person("pa2", A, [AUTH_INBOUND]),
            person("pb1", B, [AUTH_TRANSFER, AUTH_INSPECT]),
        ],
        "evidences": [e1],
        "handovers": [h1, h2],
    }


# --------------------------------------------------------------------------- #
# 用例 2：分叉并列解（同出库数、同长度，按交接 ID 序列决胜）
# --------------------------------------------------------------------------- #

def case_fork_tie() -> dict:
    e1 = evidence("E1", b"SYN-FORK", A, 100, 1000, accepted=[])
    h1 = handover("H1", "E1", e1["collection"]["digest"], "V1",
                  sig("pa1", AUTH_TRANSFER, 120),
                  sig("pb1", AUTH_TRANSFER, 130))
    h2a = handover("H2A", "E1", h1["digest"], "V2",
                   sig("pb1", AUTH_TRANSFER, 140),
                   sig("pa2", AUTH_INBOUND, 150))
    h2b = handover("H2B", "E1", h1["digest"], "V3",
                   sig("pa1", AUTH_TRANSFER, 145),
                   sig("pb2", AUTH_INBOUND, 155))
    e1["checkpoint"]["accepted_terminal_digests"] = [
        h2a["digest"], h2b["digest"]]
    return {
        "case_id": "fork_tie",
        "deadline": 2000,
        "min_witness_kinds": 2,
        "institutions": [inst(A, -20, 20), inst(B, -20, 20)],
        "persons": [
            person("pa1", A, [AUTH_TRANSFER, AUTH_INSPECT]),
            person("pa2", A, [AUTH_INBOUND]),
            person("pb1", B, [AUTH_TRANSFER, AUTH_INSPECT]),
            person("pb2", B, [AUTH_INBOUND]),
        ],
        "evidences": [e1],
        "handovers": [h2b, h1, h2a],  # 故意乱序
    }


# --------------------------------------------------------------------------- #
# 用例 3：局部最短链占用其他证物唯一交接凭单
# --------------------------------------------------------------------------- #

def case_voucher_coupling() -> dict:
    e1 = evidence("E1", b"SYN-E1", A, 100, 3000, accepted=[])
    e2 = evidence("E2", b"SYN-E2", A, 110, 3000, accepted=[])

    # E1 短链：H10(出库,V_SHARED) -> H11(入库)
    h10 = handover("H10", "E1", e1["collection"]["digest"], "V_SHARED",
                   sig("pa1", AUTH_OUTBOUND, 200),
                   sig("pb1", AUTH_TRANSFER, 220))
    h11 = handover("H11", "E1", h10["digest"], "V_E1_END",
                   sig("pb1", AUTH_TRANSFER, 260),
                   sig("pa2", AUTH_INBOUND, 280))
    # E1 长链：H12 -> H13 -> H14（不碰 V_SHARED，同样含一个出库项）
    h12 = handover("H12", "E1", e1["collection"]["digest"], "V_E1_A",
                   sig("pa1", AUTH_OUTBOUND, 300),
                   sig("pb1", AUTH_TRANSFER, 320))
    h13 = handover("H13", "E1", h12["digest"], "V_E1_B",
                   sig("pb2", AUTH_TRANSFER, 400),
                   sig("pa3", AUTH_TRANSFER, 420))
    h14 = handover("H14", "E1", h13["digest"], "V_E1_C",
                   sig("pa3", AUTH_TRANSFER, 500),
                   sig("pa2", AUTH_INBOUND, 520))
    e1["checkpoint"]["accepted_terminal_digests"] = [
        h11["digest"], h14["digest"]]

    # E2 唯一链必须用 V_SHARED
    h20 = handover("H20", "E2", e2["collection"]["digest"], "V_SHARED",
                   sig("pa1", AUTH_OUTBOUND, 210),
                   sig("pb1", AUTH_TRANSFER, 230))
    h21 = handover("H21", "E2", h20["digest"], "V_E2_END",
                   sig("pb1", AUTH_TRANSFER, 300),
                   sig("pa2", AUTH_INBOUND, 320))
    e2["checkpoint"]["accepted_terminal_digests"] = [h21["digest"]]

    return {
        "case_id": "voucher_coupling",
        "deadline": 5000,
        "min_witness_kinds": 2,
        "institutions": [inst(A, -30, 30), inst(B, -30, 30)],
        "persons": [
            person("pa1", A, [AUTH_OUTBOUND, AUTH_TRANSFER, AUTH_INSPECT]),
            person("pa2", A, [AUTH_INBOUND]),
            person("pa3", A, [AUTH_TRANSFER]),
            person("pb1", B, [AUTH_TRANSFER, AUTH_INSPECT]),
            person("pb2", B, [AUTH_TRANSFER]),
        ],
        "evidences": [e1, e2],
        "handovers": [h10, h11, h12, h13, h14, h20, h21],
    }


# --------------------------------------------------------------------------- #
# 用例 4：表面时间反转但可校准
# --------------------------------------------------------------------------- #

def case_clock_reversal() -> dict:
    e1 = evidence("E1", b"SYN-REV", A, 100, 1000, accepted=[])
    # 机构内本地读数各自单调，唯一跨机构约束来自 H1 接收(B,200) -> H2 交出(A,150)：
    # 朴素看 200 > 150 表面时间反转；非递减要求 oA - oB >= 50，可校准。
    h1 = handover("H1", "E1", e1["collection"]["digest"], "V1",
                  sig("pa1", AUTH_OUTBOUND, 120),
                  sig("pb1", AUTH_TRANSFER, 200))
    h2 = handover("H2", "E1", h1["digest"], "V2",
                  sig("pa2", AUTH_TRANSFER, 150),
                  sig("pb2", AUTH_INBOUND, 240))
    e1["checkpoint"]["accepted_terminal_digests"] = [h2["digest"]]
    return {
        "case_id": "clock_reversal",
        "deadline": 2000,
        "min_witness_kinds": 2,
        # 需要 oA-oB>=50；全取 0（朴素读法）则 200 > 150 表面反转
        "institutions": [inst(A, 0, 200), inst(B, -100, 100)],
        "persons": [
            person("pa1", A, [AUTH_OUTBOUND, AUTH_INSPECT]),
            person("pa2", A, [AUTH_TRANSFER]),
            person("pb1", B, [AUTH_TRANSFER, AUTH_INSPECT]),
            person("pb2", B, [AUTH_INBOUND]),
        ],
        "evidences": [e1],
        "handovers": [h1, h2],
    }


# --------------------------------------------------------------------------- #
# 用例 5：各自校准区间可行，组合冲突
# --------------------------------------------------------------------------- #

def case_joint_clock_conflict() -> dict:
    e1 = evidence("E1", b"SYN-J1", A, 100, 3000, accepted=[])
    e2 = evidence("E2", b"SYN-J2", A, 100, 3000, accepted=[])
    # E1：B(200) 交出 -> A(100) 接收，非递减要求 oA - oB >= 100（单件可解）
    j1 = handover("J1", "E1", e1["collection"]["digest"], "W1",
                  sig("pb1", AUTH_TRANSFER, 200),
                  sig("pa1", AUTH_TRANSFER, 100))
    e1["checkpoint"]["accepted_terminal_digests"] = [j1["digest"]]
    # E2：A(200) 交出 -> B(100) 接收，非递减要求 oB - oA >= 100（单件可解）
    # 联合时 oA-oB>=100 与 oB-oA>=100 同时成立，矛盾
    j2 = handover("J2", "E2", e2["collection"]["digest"], "W2",
                  sig("pa2", AUTH_TRANSFER, 200),
                  sig("pb1", AUTH_TRANSFER, 100))
    e2["checkpoint"]["accepted_terminal_digests"] = [j2["digest"]]
    return {
        "case_id": "joint_clock_conflict",
        "deadline": 5000,
        "min_witness_kinds": 2,
        # 单件各自可解，联合无解
        "institutions": [inst(A, -60, 60), inst(B, -60, 60)],
        "persons": [
            person("pa1", A, [AUTH_TRANSFER, AUTH_INSPECT]),
            person("pa2", A, [AUTH_TRANSFER, AUTH_INBOUND]),
            person("pb1", B, [AUTH_TRANSFER, AUTH_INSPECT]),
        ],
        "evidences": [e1, e2],
        "handovers": [j1, j2],
    }


# --------------------------------------------------------------------------- #
# 用例 6：全局物理凭单占用冲突
# --------------------------------------------------------------------------- #

def case_voucher_conflict() -> dict:
    e1 = evidence("E1", b"SYN-VC1", A, 100, 3000, accepted=[])
    e2 = evidence("E2", b"SYN-VC2", A, 100, 3000, accepted=[])
    k1 = handover("K1", "E1", e1["collection"]["digest"], "V_LOCK",
                  sig("pa1", AUTH_TRANSFER, 200),
                  sig("pb1", AUTH_TRANSFER, 220))
    e1["checkpoint"]["accepted_terminal_digests"] = [k1["digest"]]
    k2 = handover("K2", "E2", e2["collection"]["digest"], "V_LOCK",
                  sig("pa1", AUTH_TRANSFER, 210),
                  sig("pb1", AUTH_TRANSFER, 230))
    e2["checkpoint"]["accepted_terminal_digests"] = [k2["digest"]]
    return {
        "case_id": "voucher_conflict",
        "deadline": 5000,
        "min_witness_kinds": 2,
        "institutions": [inst(A, -20, 20), inst(B, -20, 20)],
        "persons": [
            person("pa1", A, [AUTH_TRANSFER, AUTH_INSPECT]),
            person("pb1", B, [AUTH_TRANSFER, AUTH_INSPECT]),
        ],
        "evidences": [e1, e2],
        "handovers": [k1, k2],
    }


# --------------------------------------------------------------------------- #
# 用例 7：见证不足（全部签名人只属同一机构种类）
# --------------------------------------------------------------------------- #

def case_witness_insufficient() -> dict:
    e1 = evidence("E1", b"SYN-WI", A, 100, 3000, accepted=[])
    w1 = handover("W1", "E1", e1["collection"]["digest"], "V1",
                  sig("pa1", AUTH_TRANSFER, 200),
                  sig("pa2", AUTH_INBOUND, 240))
    e1["checkpoint"]["accepted_terminal_digests"] = [w1["digest"]]
    return {
        "case_id": "witness_insufficient",
        "deadline": 5000,
        "min_witness_kinds": 2,
        "institutions": [inst(A, -20, 20), inst(B, -20, 20)],
        "persons": [
            person("pa1", A, [AUTH_TRANSFER, AUTH_INSPECT]),
            person("pa2", A, [AUTH_INBOUND]),
            person("pb1", B, [AUTH_TRANSFER, AUTH_INSPECT]),  # 未参与签名
        ],
        "evidences": [e1],
        "handovers": [w1],
    }


# --------------------------------------------------------------------------- #
# 用例 8：重复见证人（同一人员跨多跳出现，种类仍不足）
# --------------------------------------------------------------------------- #

def case_repeated_witness() -> dict:
    e1 = evidence("E1", b"SYN-RW", A, 100, 3000, accepted=[])
    r1 = handover("R1", "E1", e1["collection"]["digest"], "V1",
                  sig("pa1", AUTH_TRANSFER, 200),
                  sig("pa2", AUTH_TRANSFER, 220))
    r2 = handover("R2", "E1", r1["digest"], "V2",
                  sig("pa1", AUTH_TRANSFER, 260),
                  sig("pa2", AUTH_INBOUND, 280))
    e1["checkpoint"]["accepted_terminal_digests"] = [r2["digest"]]
    return {
        "case_id": "repeated_witness",
        "deadline": 5000,
        "min_witness_kinds": 2,
        "institutions": [inst(A, -20, 20), inst(B, -20, 20)],
        "persons": [
            person("pa1", A, [AUTH_TRANSFER, AUTH_INSPECT]),
            person("pa2", A, [AUTH_TRANSFER, AUTH_INBOUND]),
            person("pb1", B, [AUTH_TRANSFER, AUTH_INSPECT]),  # 未参与
        ],
        "evidences": [e1],
        "handovers": [r1, r2],
    }


# --------------------------------------------------------------------------- #
# 用例 9：伪造同摘要的新分叉（摘要核验失败被排除）
# --------------------------------------------------------------------------- #

def case_forged_fork() -> dict:
    e1 = evidence("E1", b"SYN-FF", A, 100, 3000, accepted=[])
    f1 = handover("F1", "E1", e1["collection"]["digest"], "V1",
                  sig("pa1", AUTH_TRANSFER, 200),
                  sig("pb1", AUTH_TRANSFER, 220))
    # 合法分叉
    f2_ok = handover("F2OK", "E1", f1["digest"], "V2",
                     sig("pb1", AUTH_TRANSFER, 260),
                     sig("pa2", AUTH_INBOUND, 280))
    # 伪造分叉：内容不同却声称接上 f1；登记错误摘要
    f2_bad = handover("F2BAD", "E1", f1["digest"], "V3",
                      sig("pa1", AUTH_TRANSFER, 700),
                      sig("pb2", AUTH_INBOUND, 720),
                      forge=True)
    e1["checkpoint"]["accepted_terminal_digests"] = [
        f2_ok["digest"], f2_bad["digest"]]
    return {
        "case_id": "forged_fork",
        "deadline": 5000,
        "min_witness_kinds": 2,
        "institutions": [inst(A, -20, 20), inst(B, -20, 20)],
        "persons": [
            person("pa1", A, [AUTH_TRANSFER, AUTH_INSPECT]),
            person("pa2", A, [AUTH_INBOUND]),
            person("pb1", B, [AUTH_TRANSFER, AUTH_INSPECT]),
            person("pb2", B, [AUTH_INBOUND]),
        ],
        "evidences": [e1],
        "handovers": [f1, f2_ok, f2_bad],
    }


# --------------------------------------------------------------------------- #
# 用例 10：单件不可校准（时钟差超界 + 无结构链）
# --------------------------------------------------------------------------- #

def case_uncalibratable() -> dict:
    e1 = evidence("E1", b"SYN-UC1", A, 100, 3000, accepted=[])
    # B(200) 交出 -> A(100) 接收，非递减要求 200+oB <= 100+oA，即 oA-oB>=100；
    # 两机构偏移闭区间只有 ±10（最大差 20），故不可校准
    u1 = handover("U1", "E1", e1["collection"]["digest"], "V1",
                  sig("pb1", AUTH_TRANSFER, 200),
                  sig("pa1", AUTH_TRANSFER, 100))
    e1["checkpoint"]["accepted_terminal_digests"] = [u1["digest"]]

    e2 = evidence("E2", b"SYN-UC2", A, 100, 3000, accepted=[])
    # 悬空记录：prev 不接采集锚点，无结构链
    u2 = handover("U2", "E2", "dead-digest-not-registered", "V2",
                  sig("pa1", AUTH_TRANSFER, 200),
                  sig("pb1", AUTH_TRANSFER, 220))
    e2["checkpoint"]["accepted_terminal_digests"] = [u2["digest"]]
    return {
        "case_id": "uncalibratable",
        "deadline": 5000,
        "min_witness_kinds": 2,
        "institutions": [inst(A, -10, 10), inst(B, -10, 10)],
        "persons": [
            person("pa1", A, [AUTH_TRANSFER, AUTH_INSPECT]),
            person("pb1", B, [AUTH_TRANSFER, AUTH_INSPECT]),
        ],
        "evidences": [e1, e2],
        "handovers": [u1, u2],
    }


# --------------------------------------------------------------------------- #
# 用例 11：乱序 + 重复候选（重复登记被拒/去重后仍可解）
# --------------------------------------------------------------------------- #

def case_out_of_order_dup() -> dict:
    e1 = evidence("E1", b"SYN-OO", A, 100, 3000, accepted=[])
    d1 = handover("D1", "E1", e1["collection"]["digest"], "V1",
                  sig("pa1", AUTH_TRANSFER, 200),
                  sig("pb1", AUTH_TRANSFER, 220))
    d2 = handover("D2", "E1", d1["digest"], "V2",
                  sig("pb1", AUTH_TRANSFER, 260),
                  sig("pa2", AUTH_INBOUND, 280))
    e1["checkpoint"]["accepted_terminal_digests"] = [d2["digest"]]
    # 完全重复的候选（同 handover_id、同内容）
    d1_dup = json.loads(json.dumps(d1))
    return {
        "case_id": "out_of_order_dup",
        "deadline": 5000,
        "min_witness_kinds": 2,
        "institutions": [inst(A, -20, 20), inst(B, -20, 20)],
        "persons": [
            person("pa1", A, [AUTH_TRANSFER, AUTH_INSPECT]),
            person("pa2", A, [AUTH_INBOUND]),
            person("pb1", B, [AUTH_TRANSFER, AUTH_INSPECT]),
        ],
        "evidences": [e1],
        "handovers": [d2, d1_dup, d1],  # 乱序且含重复
    }


# --------------------------------------------------------------------------- #
# 用例 12：小输入穷举对照
# --------------------------------------------------------------------------- #

def case_brute_force_oracle() -> dict:
    e1 = evidence("E1", b"SYN-BF1", A, 100, 3000, accepted=[])
    e2 = evidence("E2", b"SYN-BF2", A, 100, 3000, accepted=[])
    b1 = handover("B1", "E1", e1["collection"]["digest"], "V1",
                  sig("pa1", AUTH_TRANSFER, 200),
                  sig("pb1", AUTH_TRANSFER, 230))
    e1["checkpoint"]["accepted_terminal_digests"] = [b1["digest"]]
    b2 = handover("B2", "E2", e2["collection"]["digest"], "V2",
                  sig("pb1", AUTH_TRANSFER, 210),
                  sig("pa2", AUTH_TRANSFER, 240))
    e2["checkpoint"]["accepted_terminal_digests"] = [b2["digest"]]
    return {
        "case_id": "brute_force_oracle",
        "deadline": 5000,
        "min_witness_kinds": 2,
        "institutions": [inst(A, -30, 30), inst(B, -30, 30)],
        "persons": [
            person("pa1", A, [AUTH_TRANSFER, AUTH_INSPECT]),
            person("pa2", A, [AUTH_TRANSFER, AUTH_INBOUND]),
            person("pb1", B, [AUTH_TRANSFER, AUTH_INSPECT]),
        ],
        "evidences": [e1, e2],
        "handovers": [b2, b1],
    }


def all_cases() -> list[dict]:
    return [
        case_basic_sat(),
        case_fork_tie(),
        case_voucher_coupling(),
        case_clock_reversal(),
        case_joint_clock_conflict(),
        case_voucher_conflict(),
        case_witness_insufficient(),
        case_repeated_witness(),
        case_forged_fork(),
        case_uncalibratable(),
        case_out_of_order_dup(),
        case_brute_force_oracle(),
    ]


def main() -> None:
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "cases.json")
    payload = {"schema": "forensic-packages/1", "cases": all_cases()}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"wrote {len(payload['cases'])} cases -> {os.path.normpath(out_path)}")


if __name__ == "__main__":
    main()

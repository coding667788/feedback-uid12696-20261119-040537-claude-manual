"""数据模型、输入校验与摘要（SHA-256）完整性核验。

所有数据均为合成数据：证物哈希是对一段合成字节串计算的 SHA-256，
交接记录的摘要由记录去掉 ``digest`` 字段后的规范化 JSON 计算 SHA-256 得到。
本模块不接触任何真实取证数据。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

# 授权种类（合成枚举）
AUTH_COLLECT = "collect"   # 采集
AUTH_OUTBOUND = "outbound"  # 出库
AUTH_TRANSFER = "transfer"  # 交接传输
AUTH_INBOUND = "inbound"    # 入库
AUTH_INSPECT = "inspect"    # 见证/检查

VALID_AUTH = {
    AUTH_COLLECT,
    AUTH_OUTBOUND,
    AUTH_TRANSFER,
    AUTH_INBOUND,
    AUTH_INSPECT,
}


class CaseError(ValueError):
    """输入保全包结构非法。"""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_handover_digest(record: dict[str, Any]) -> str:
    """交接记录的规范摘要：去掉 digest 字段后按确定顺序序列化再做 SHA-256。"""
    stripped = {k: v for k, v in record.items() if k != "digest"}
    blob = json.dumps(stripped, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")
    return sha256_hex(blob)


@dataclass(frozen=True)
class Institution:
    inst_id: str
    name: str
    offset_min: int
    offset_max: int


@dataclass(frozen=True)
class Person:
    person_id: str
    name: str
    inst_id: str
    auth_kinds: frozenset[str]


@dataclass(frozen=True)
class Signature:
    person_id: str
    auth_kind: str
    local_ts: int  # 机构本地时钟读数（整数秒）


@dataclass
class Handover:
    handover_id: str
    evidence_id: str
    prev_digest: str
    voucher_id: str
    release: Signature
    receive: Signature
    digest: str
    claimed_digest: str
    digest_ok: bool
    # 校验期填充
    release_person: Person | None = None
    receive_person: Person | None = None
    auth_ok: bool = True
    linkage_ok: bool = True
    invalid_reasons: list[str] = field(default_factory=list)

    def signatures(self) -> tuple[Signature, Signature]:
        return self.release, self.receive


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    tenant: str
    custodian: str
    payload_bytes: bytes
    evidence_sha256: str
    collection_digest: str
    collection_inst: str
    collection_local_ts: int
    checkpoint_inst: str | None  # None 表示入库时刻本身就是全局时刻
    checkpoint_local_ts: int | None
    entry_global_ts: int  # 入保全库全局时刻（最终上界）
    accepted_terminal_digests: frozenset[str]


@dataclass
class Package:
    case_id: str
    deadline: int
    min_witness_kinds: int
    institutions: dict[str, Institution]
    persons: dict[str, Person]
    evidences: dict[str, Evidence]
    handovers: dict[str, Handover]
    notes: list[str]

    def usable_handovers(self) -> list[Handover]:
        """通过完整性、授权与（静态）连接校验的候选记录。"""
        return [h for h in self.handovers.values()
                if h.digest_ok and h.auth_ok and h.linkage_ok]


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise CaseError(msg)


def _parse_sig(raw: Any, role: str, handover_id: str) -> Signature:
    _require(isinstance(raw, dict), f"{handover_id}: {role} 签名必须是对象")
    for key in ("person_id", "auth_kind", "local_ts"):
        _require(key in raw, f"{handover_id}: {role} 签名缺少 {key}")
    _require(isinstance(raw["person_id"], str) and raw["person_id"],
             f"{handover_id}: {role} person_id 非法")
    _require(raw["auth_kind"] in VALID_AUTH,
             f"{handover_id}: {role} 授权种类 {raw['auth_kind']!r} 非法")
    _require(isinstance(raw["local_ts"], int) and not isinstance(raw["local_ts"], bool),
             f"{handover_id}: {role} local_ts 必须是整数秒")
    return Signature(raw["person_id"], raw["auth_kind"], raw["local_ts"])


def load_package(case: dict[str, Any]) -> Package:
    """解析并校验一个合成保全包。"""
    notes: list[str] = []
    _require(isinstance(case, dict), "保全包必须是 JSON 对象")
    case_id = case.get("case_id", "unknown")
    _require(isinstance(case_id, str), "case_id 必须是字符串")
    _require(isinstance(case.get("deadline"), int), "deadline 必须是整数")
    deadline = case["deadline"]
    min_kinds = case.get("min_witness_kinds", 2)
    _require(isinstance(min_kinds, int) and min_kinds >= 1, "min_witness_kinds 非法")

    institutions: dict[str, Institution] = {}
    for raw in case.get("institutions", []):
        _require(isinstance(raw, dict), "institutions 条目必须是对象")
        iid = raw.get("inst_id")
        _require(isinstance(iid, str) and iid, "inst_id 非法")
        _require(iid not in institutions, f"机构 {iid} 重复登记")
        lo, hi = raw.get("offset_min"), raw.get("offset_max")
        _require(isinstance(lo, int) and isinstance(hi, int) and lo <= hi,
                 f"机构 {iid} 偏移闭区间非法")
        institutions[iid] = Institution(iid, raw.get("name", iid), lo, hi)

    persons: dict[str, Person] = {}
    for raw in case.get("persons", []):
        pid = raw.get("person_id")
        _require(isinstance(pid, str) and pid, "person_id 非法")
        _require(pid not in persons, f"人员 {pid} 重复登记")
        iid = raw.get("inst_id")
        _require(iid in institutions, f"人员 {pid} 所属机构 {iid!r} 未登记")
        kinds = raw.get("auth_kinds", [])
        _require(isinstance(kinds, list) and all(k in VALID_AUTH for k in kinds),
                 f"人员 {pid} 授权种类非法")
        persons[pid] = Person(pid, raw.get("name", pid), iid, frozenset(kinds))

    evidences: dict[str, Evidence] = {}
    for raw in case.get("evidences", []):
        eid = raw.get("evidence_id")
        _require(isinstance(eid, str) and eid, "evidence_id 非法")
        _require(eid not in evidences, f"证物 {eid} 重复登记")
        payload_hex = raw.get("payload_hex", "")
        _require(isinstance(payload_hex, str), f"证物 {eid} payload_hex 非法")
        payload = bytes.fromhex(payload_hex) if payload_hex else b""
        actual_hash = sha256_hex(payload)
        claimed_hash = raw.get("evidence_sha256")
        _require(claimed_hash == actual_hash,
                 f"证物 {eid} 合成字节与登记 SHA-256 不一致")
        col = raw["collection"]
        c_inst = col["inst_id"]
        _require(c_inst in institutions, f"证物 {eid} 采集机构未登记")
        _require(isinstance(col.get("local_ts"), int), f"证物 {eid} 采集时刻非法")
        cp = raw["checkpoint"]
        cp_inst = cp.get("inst_id")
        cp_ts = cp.get("local_ts")
        if cp_inst is None:
            _require(cp_ts is None, f"证物 {eid} 检查点字段不一致")
            entry = cp["entry_global_ts"]
        else:
            _require(cp_inst in institutions, f"证物 {eid} 保全检查点机构未登记")
            _require(isinstance(cp_ts, int), f"证物 {eid} 检查点本地时刻非法")
            entry = cp["entry_global_ts"]
        _require(isinstance(entry, int), f"证物 {eid} 入库全局时刻非法")
        accepted = frozenset(cp.get("accepted_terminal_digests", []))
        _require(accepted, f"证物 {eid} 检查点未登记任何承接摘要")
        evidences[eid] = Evidence(
            evidence_id=eid,
            tenant=raw["tenant"],
            custodian=raw["custodian"],
            payload_bytes=payload,
            evidence_sha256=actual_hash,
            collection_digest=col["digest"],
            collection_inst=c_inst,
            collection_local_ts=col["local_ts"],
            checkpoint_inst=cp_inst,
            checkpoint_local_ts=cp_ts,
            entry_global_ts=entry,
            accepted_terminal_digests=accepted,
        )

    handovers: dict[str, Handover] = {}
    for raw in case.get("handovers", []):
        hid = raw.get("handover_id")
        _require(isinstance(hid, str) and hid, "handover_id 非法")
        if hid in handovers:
            # 候选可重复：完全相同的重复登记去重，内容冲突则拒绝
            previous = handovers[hid]
            same = (previous.evidence_id == raw.get("evidence_id")
                    and previous.prev_digest == raw.get("prev_digest")
                    and previous.voucher_id == raw.get("voucher_id")
                    and previous.claimed_digest == raw.get("digest"))
            _require(same, f"交接记录 {hid} 重复登记且内容冲突")
            notes.append(f"handover {hid}: 重复候选已去重")
            continue
        eid = raw.get("evidence_id")
        _require(eid in evidences, f"交接 {hid} 指向未登记证物 {eid!r}")
        rel = _parse_sig(raw.get("release"), "交出方", hid)
        rcv = _parse_sig(raw.get("receive"), "接收方", hid)
        _require(rel.person_id != rcv.person_id,
                 f"交接 {hid} 交出/接收不得为同一模拟签名人")
        claimed = raw.get("digest")
        _require(isinstance(claimed, str), f"交接 {hid} 缺少 digest")
        actual = canonical_handover_digest(raw)
        digest_ok = claimed == actual
        if not digest_ok:
            notes.append(f"handover {hid}: 摘要核验失败（伪造/篡改），已排除")
        h = Handover(
            handover_id=hid,
            evidence_id=eid,
            prev_digest=raw["prev_digest"],
            voucher_id=raw["voucher_id"],
            release=rel,
            receive=rcv,
            digest=actual,
            claimed_digest=claimed,
            digest_ok=digest_ok,
        )
        handovers[hid] = h

    # 人员/授权与静态连接校验
    known_digests = {h.digest for h in handovers.values()}
    collection_digests = {e.collection_digest for e in evidences.values()}
    for h in handovers.values():
        reasons: list[str] = []
        for sig, role in ((h.release, "release"), (h.receive, "receive")):
            person = persons.get(sig.person_id)
            if person is None:
                reasons.append(f"{role}: 签名人 {sig.person_id} 未登记")
            elif sig.auth_kind not in person.auth_kinds:
                reasons.append(
                    f"{role}: {sig.person_id} 无授权种类 {sig.auth_kind}")
            if sig.person_id in persons:
                setattr(h, f"{role}_person", persons[sig.person_id])
        if reasons:
            h.auth_ok = False
            h.invalid_reasons.extend(reasons)
            notes.append(f"handover {h.handover_id}: 授权/人员校验失败，已排除")
        if (h.prev_digest not in known_digests
                and h.prev_digest not in collection_digests):
            h.linkage_ok = False
            h.invalid_reasons.append("prev_digest 对不上任何采集锚点或交接摘要")
            notes.append(f"handover {h.handover_id}: 前序摘要失配，已排除")

    return Package(
        case_id=case_id,
        deadline=deadline,
        min_witness_kinds=min_kinds,
        institutions=institutions,
        persons=persons,
        evidences=evidences,
        handovers=handovers,
        notes=notes,
    )

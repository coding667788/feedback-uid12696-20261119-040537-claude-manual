"""共享时钟校准：差约束系统（Bellman-Ford）与交接链枚举。

差约束建模
----------
对每个机构 ``i`` 设整数秒偏移变量 ``o_i``，区间约束
``offset_min <= o_i <= offset_max``。
签名事件 ``e`` 来自机构 ``i``、本地读数 ``t``，其全局时刻
``g_e = t + o_i``，写成两条差约束：

* ``g_e - o_i <= t``   （边 o_i -> g_e，权 t）
* ``o_i - g_e <= -t``  （边 g_e -> o_i，权 -t）

同一条链上的事件按顺序非递减：``g_{k+1} - g_k >= 0``，
即 ``g_k - g_{k+1} <= 0``（边 g_{k+1} -> g_k，权 0）。
所有签名全局时刻不晚于截止时刻与入保全库时刻：``g_e <= U``。

机构区间用虚拟源 s 表达：

* ``o_i <= hi``  ->  边 s -> o_i，权 hi
* ``o_i >= lo``  ->  边 s - o_i <= -lo，即边 o_i -> s，权 -lo

Bellman-Ford 无负环即可行，出现负环即该组链不可校准。
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import PACKAGE_TOO_LARGE
from .model import AUTH_OUTBOUND, Evidence, Package

# 单件证物候选链数量与全局叶节点搜索的保护性上限。
MAX_CHAINS_PER_EVIDENCE = 100_000
MAX_JOINT_LEAVES = 200_000


class SolverLimitError(RuntimeError):
    def __init__(self, code: str = PACKAGE_TOO_LARGE, message: str = ""):
        super().__init__(message or code)
        self.code = code


@dataclass(frozen=True)
class Event:
    """链上一个带机构时钟的事件。"""
    kind: str            # 'collection' | 'release' | 'receive'
    inst_id: str
    local_ts: int


@dataclass(frozen=True)
class Chain:
    evidence_id: str
    handovers: tuple[Handover, ...]
    events: tuple[Event, ...]
    terminal_digest: str
    outbound_count: int


def _chain_events(evidence: Evidence,
                  handovers: tuple[Handover, ...]) -> tuple[Event, ...]:
    events: list[Event] = [
        Event("collection", evidence.collection_inst, evidence.collection_local_ts)
    ]
    for h in handovers:
        events.append(Event("release", h.release_person.inst_id,
                            h.release.local_ts))
        events.append(Event("receive", h.receive_person.inst_id,
                            h.receive.local_ts))
    return tuple(events)


def enumerate_chains(pkg: Package, evidence: Evidence) -> list[Chain]:
    """枚举单件证物从采集锚点到已登记保全检查点的全部候选链。

    仅使用通过完整性/授权/连接校验的交接记录；每条记录的
    ``prev_digest`` 必须与链上前一条记录的确切摘要一致。
    """
    usable = [h for h in pkg.usable_handovers()
              if h.evidence_id == evidence.evidence_id]
    by_prev: dict[str, list[Handover]] = {}
    for h in usable:
        by_prev.setdefault(h.prev_digest, []).append(h)
    for lst in by_prev.values():
        lst.sort(key=lambda h: h.handover_id)

    accepted = evidence.accepted_terminal_digests
    chains: list[Chain] = []
    truncated = False

    def dfs(prev_digest: str, path: list[Handover], visited: set[str]) -> None:
        nonlocal truncated
        for h in by_prev.get(prev_digest, ()):
            if len(chains) >= MAX_CHAINS_PER_EVIDENCE:
                truncated = True
                return
            if h.handover_id in visited:
                continue  # 防御环
            path.append(h)
            visited.add(h.handover_id)
            if h.digest in accepted:
                tup = tuple(path)
                events = _chain_events(evidence, tup)
                outbound = sum(
                    1 for x in tup
                    if AUTH_OUTBOUND in (x.release.auth_kind, x.receive.auth_kind))
                chains.append(Chain(
                    evidence_id=evidence.evidence_id,
                    handovers=tup,
                    events=events,
                    terminal_digest=h.digest,
                    outbound_count=outbound,
                ))
            dfs(h.digest, path, visited)
            path.pop()
            visited.discard(h.handover_id)

    dfs(evidence.collection_digest, [], set())
    if truncated:
        raise SolverLimitError(
            message=f"证物 {evidence.evidence_id} 候选链超过 "
                    f"{MAX_CHAINS_PER_EVIDENCE} 条")
    chains.sort(key=lambda c: [h.handover_id for h in c.handovers])
    return chains


# --------------------------------------------------------------------------- #
# 差约束系统
# --------------------------------------------------------------------------- #

def _all_edges(pkg: Package,
               chains: list[Chain],
               fixed: dict[str, int] | None,
               extra_upper: dict[str, int] | None
               ) -> tuple[list[str], list[tuple[int, int, int]], int]:
    """生成完整边表（含虚拟源 s 的区间/上界边）。"""
    inst_ids = sorted(pkg.institutions)
    inst_idx = {iid: i for i, iid in enumerate(inst_ids)}
    n_inst = len(inst_ids)
    edges: list[tuple[int, int, int]] = []
    event_vars: list[tuple[int, int]] = []  # (变量, 上界)
    event_count = 0

    def add_event(ev: Event, upper: int) -> int:
        nonlocal event_count
        v = n_inst + event_count
        event_count += 1
        i = inst_idx[ev.inst_id]
        edges.append((i, v, ev.local_ts))
        edges.append((v, i, -ev.local_ts))
        event_vars.append((v, upper))
        return v

    for chain in chains:
        prev_v: int | None = None
        evidence = pkg.evidences[chain.evidence_id]
        upper = min(pkg.deadline, evidence.entry_global_ts)
        for ev in chain.events:
            v = add_event(ev, upper)
            if prev_v is not None:
                edges.append((v, prev_v, 0))  # 非递减
            prev_v = v

    n_vars = n_inst + event_count
    s = n_vars  # 虚拟源

    # 机构偏移区间
    fixed = fixed or {}
    extra_upper = extra_upper or {}
    for iid in inst_ids:
        i = inst_idx[iid]
        inst = pkg.institutions[iid]
        lo, hi = inst.offset_min, inst.offset_max
        if iid in fixed:
            val = fixed[iid]
            if not (lo <= val <= hi):
                return inst_ids, [], s
            lo = hi = val
        if iid in extra_upper:
            hi = min(hi, extra_upper[iid])
        if lo > hi:
            return inst_ids, [], s
        edges.append((s, i, hi))    # o_i <= hi
        edges.append((i, s, -lo))  # o_i >= lo

    # 事件全局时刻上界 g <= U
    for v, upper in event_vars:
        edges.append((s, v, upper))

    return inst_ids, edges, s


def _has_negative_cycle(edges: list[tuple[int, int, int]], s: int) -> bool:
    """以虚拟源 s 为源的 Bellman-Ford 负环检测。"""
    if not edges:
        return True
    n = s + 1
    dist = [0] * n
    for _ in range(n):
        updated = False
        for u, v, w in edges:
            nd = dist[u] + w
            if nd < dist[v]:
                dist[v] = nd
                updated = True
        if not updated:
            return False
    return True


def feasible(pkg: Package,
             chains: list[Chain],
             fixed: dict[str, int] | None = None,
             extra_upper: dict[str, int] | None = None) -> bool:
    """给定一组链（可含部分固定机构偏移）判断差约束是否可行。"""
    _, edges, s = _all_edges(pkg, chains, fixed, extra_upper)
    if not edges:
        return False
    return not _has_negative_cycle(edges, s)


def lex_min_offsets(pkg: Package,
                    chains: list[Chain]) -> dict[str, int] | None:
    """求机构 ID 字典序下偏移向量最小的可行整数偏移。"""
    inst_ids = sorted(pkg.institutions)
    fixed: dict[str, int] = {}
    for iid in inst_ids:
        inst = pkg.institutions[iid]
        lo, hi = inst.offset_min, inst.offset_max
        if not feasible(pkg, chains, fixed=fixed, extra_upper={iid: hi}):
            return None
        best = hi
        while lo <= hi:
            mid = (lo + hi) // 2
            if feasible(pkg, chains, fixed=fixed, extra_upper={iid: mid}):
                best = mid
                hi = mid - 1
            else:
                lo = mid + 1
        fixed[iid] = best
    return fixed


def event_global_times(chain: Chain, offsets: dict[str, int]) -> list[int]:
    return [e.local_ts + offsets[e.inst_id] for e in chain.events]

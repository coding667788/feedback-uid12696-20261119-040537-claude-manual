"""保全包全局求解器。

求解顺序严格按题目要求：

1. 每件证物枚举从采集锚点到已登记保全检查点的候选交接链；
2. 单件差约束可行性过滤（不可校准链剔除）；
3. 全局回溯：物理凭单独占 + 跨证物共享时钟联合可行；
4. 见证覆盖：每件证物链上签名人所属机构种类数 >= ``min_witness_kinds``；
5. 最优性比较：不同出库交接项数 -> 证物 ID/交接 ID 序列 -> 字典序最小全局时刻。
"""

from __future__ import annotations

from dataclasses import dataclass

from .calibration import (
    MAX_JOINT_LEAVES,
    Chain,
    SolverLimitError,
    enumerate_chains,
)
from .errors import (
    DETAIL_CLOCK,
    DETAIL_VOUCHER,
    EVIDENCE_UNCALIBRATABLE,
    GLOBAL_VOUCHER_CONFLICT,
    WITNESS_INSUFFICIENT,
)
from .model import AUTH_OUTBOUND, Handover, Package


# --------------------------------------------------------------------------- #
# 差约束（支持固定事件全局时刻，用于字典序最小全局时刻贪心）
# --------------------------------------------------------------------------- #

class Constraints:
    """一组链对应的差约束模型。"""

    def __init__(self, pkg: Package, chains: list[Chain]):
        self.pkg = pkg
        self.chains = chains
        self.inst_ids = sorted(pkg.institutions)
        self.inst_idx = {iid: i for i, iid in enumerate(self.inst_ids)}
        n_inst = len(self.inst_ids)
        self.edges: list[tuple[int, int, int]] = []
        self.event_vars: list[list[int]] = []   # 每链事件变量下标
        self.event_uppers: list[int] = []
        event_count = 0

        def add_event(inst_id: str, local_ts: int, upper: int) -> int:
            nonlocal event_count
            v = n_inst + event_count
            event_count += 1
            i = self.inst_idx[inst_id]
            self.edges.append((i, v, local_ts))
            self.edges.append((v, i, -local_ts))
            self.event_uppers.append(upper)
            return v

        for chain in chains:
            evidence = pkg.evidences[chain.evidence_id]
            upper = min(pkg.deadline, evidence.entry_global_ts)
            vars_: list[int] = []
            prev_v: int | None = None
            for ev in chain.events:
                v = add_event(ev.inst_id, ev.local_ts, upper)
                if prev_v is not None:
                    # 非递减 g_prev <= g_cur：边 cur -> prev，权 0
                    self.edges.append((v, prev_v, 0))
                prev_v = v
                vars_.append(v)
            self.event_vars.append(vars_)

        self.n_vars = n_inst + event_count
        self.s = self.n_vars

    def feasible(self,
                 fixed_offsets: dict[str, int] | None = None,
                 offset_upper: dict[str, int] | None = None,
                 fixed_event_times: dict[int, int] | None = None) -> bool:
        fixed_offsets = fixed_offsets or {}
        offset_upper = offset_upper or {}
        fixed_event_times = fixed_event_times or {}
        edges = list(self.edges)

        for iid in self.inst_ids:
            i = self.inst_idx[iid]
            inst = self.pkg.institutions[iid]
            lo, hi = inst.offset_min, inst.offset_max
            if iid in fixed_offsets:
                val = fixed_offsets[iid]
                if not (lo <= val <= hi):
                    return False
                lo = hi = val
            if iid in offset_upper:
                hi = min(hi, offset_upper[iid])
            if lo > hi:
                return False
            edges.append((self.s, i, hi))
            edges.append((i, self.s, -lo))

        for v, upper in enumerate(self.event_uppers, start=len(self.inst_ids)):
            if v not in fixed_event_times:
                # 已固定事件由下面的等值边同时给出上/下界，避免更紧的通用上界误伤
                edges.append((self.s, v, upper))

        for v, val in fixed_event_times.items():
            edges.append((self.s, v, val))
            edges.append((v, self.s, -val))

        n = self.s + 1
        dist = [0] * n
        for _ in range(n):
            updated = False
            for u, v, w in edges:
                nd = dist[u] + w
                if nd < dist[v]:
                    dist[v] = nd
                    updated = True
            if not updated:
                return True
        return False

    def lex_min_offsets(self) -> dict[str, int] | None:
        """机构 ID 字典序下偏移向量最小的可行整数偏移。

        对单个机构偏移收紧上界不会放松任何约束，可行性对偏移值单调，
        因此可逐机构二分最小可行值。
        """
        fixed: dict[str, int] = {}
        for iid in self.inst_ids:
            inst = self.pkg.institutions[iid]
            lo, hi = inst.offset_min, inst.offset_max
            if not self.feasible(fixed_offsets=fixed, offset_upper={iid: hi}):
                return None
            best = hi
            while lo <= hi:
                mid = (lo + hi) // 2
                if self.feasible(fixed_offsets=fixed,
                                 offset_upper={iid: mid}):
                    best = mid
                    hi = mid - 1
                else:
                    lo = mid + 1
            fixed[iid] = best
        return fixed

    def lex_min_schedule(self) -> tuple[dict[str, int], list[list[int]]] | None:
        """求字典序最小的可行全局时刻安排。

        分两步：

        1. 求机构 ID 字典序最小的可行偏移向量（偏移决定全部全局时刻，
           是更靠前的优化量，且固定偏移后事件时刻被唯一表达为 local+offset）；
        2. 在固定偏移下，按链顺序让每个事件取满足非递减与上界的最小全局时刻。
        """
        offsets = self.lex_min_offsets()
        if offsets is None:
            return None

        times: list[list[int]] = []
        for chain_idx, chain in enumerate(self.chains):
            evidence = self.pkg.evidences[chain.evidence_id]
            upper = min(self.pkg.deadline, evidence.entry_global_ts)
            seq: list[int] = []
            prev: int | None = None
            for ev in chain.events:
                g = ev.local_ts + offsets[ev.inst_id]
                if prev is not None:
                    g = max(g, prev)  # 非递减
                if g > upper:
                    return None
                seq.append(g)
                prev = g
            times.append(seq)
        return offsets, times


def _is_outbound(h: Handover) -> bool:
    return AUTH_OUTBOUND in (h.release.auth_kind, h.receive.auth_kind)


def witness_coverage(pkg: Package, chains: list[Chain]
                     ) -> dict[str, dict[str, list[str]]]:
    """每件证物：机构 ID -> 在其链上签名的人员（去重排序）。"""
    coverage: dict[str, dict[str, list[str]]] = {}
    for chain in chains:
        per: dict[str, set[str]] = {}
        for h in chain.handovers:
            for sig in (h.release, h.receive):
                person = pkg.persons[sig.person_id]
                per.setdefault(person.inst_id, set()).add(person.person_id)
        coverage[chain.evidence_id] = {
            iid: sorted(pids) for iid, pids in sorted(per.items())}
    return coverage


def witnesses_sufficient(pkg: Package, chains: list[Chain]) -> bool:
    coverage = witness_coverage(pkg, chains)
    return all(len(m) >= pkg.min_witness_kinds for m in coverage.values())


@dataclass
class SolveResult:
    ok: bool
    code: str | None = None
    detail: str | None = None
    chains: list[Chain] | None = None
    offsets: dict[str, int] | None = None
    times: list[list[int]] | None = None
    reason_evidence: dict[str, str] | None = None


def _solo_chains(pkg: Package) -> tuple[dict[str, list[Chain]], dict[str, str]]:
    """每件证物返回可单独校准的候选链；不可行者记录原因。"""
    calibratable: dict[str, list[Chain]] = {}
    reasons: dict[str, str] = {}
    for eid in sorted(pkg.evidences):
        evidence = pkg.evidences[eid]
        chains = enumerate_chains(pkg, evidence)
        if not chains:
            reasons[eid] = "no_structural_chain"
            continue
        good = [c for c in chains if Constraints(pkg, [c]).feasible()]
        if not good:
            reasons[eid] = "clock_not_calibratable"
            continue
        calibratable[eid] = good
    return calibratable, reasons


def _outbound_key(selected: dict[str, Chain]) -> int:
    return len({h.handover_id for c in selected.values() for h in c.handovers
                if _is_outbound(h)})


def _chain_seq_key(selected: dict[str, Chain]) -> tuple[tuple[str, ...], ...]:
    return tuple(tuple(h.handover_id for h in selected[eid].handovers)
                 for eid in sorted(selected))


def solve(pkg: Package) -> SolveResult:
    calibratable, reasons = _solo_chains(pkg)
    if reasons:
        return SolveResult(ok=False, code=EVIDENCE_UNCALIBRATABLE,
                           reason_evidence=reasons)

    order = sorted(calibratable, key=lambda e: (len(calibratable[e]), e))
    leaves = 0
    best: dict[str, Chain] | None = None
    best_outbound: int | None = None
    best_seq = None
    best_time: list[int] | None = None
    best_schedule: tuple[dict[str, int], list[list[int]]] | None = None
    # 进入 consider 的叶节点均已通过凭单独占与联合时钟校验
    clock_feasible_leaf = False
    witness_feasible_leaf = False

    def consider(selected: dict[str, Chain]) -> None:
        nonlocal best, best_outbound, best_seq, best_time, best_schedule
        nonlocal clock_feasible_leaf, witness_feasible_leaf, leaves
        leaves += 1
        if leaves > MAX_JOINT_LEAVES:
            raise SolverLimitError(
                message=f"全局组合叶节点超过 {MAX_JOINT_LEAVES}")
        clock_feasible_leaf = True
        chains = [selected[e] for e in sorted(selected)]
        if not witnesses_sufficient(pkg, chains):
            return
        witness_feasible_leaf = True
        cons = Constraints(pkg, chains)
        schedule = cons.lex_min_schedule()
        if schedule is None:
            return
        offsets, times = schedule
        flat = [t for seq in times for t in seq]
        ob = _outbound_key(selected)
        seq = _chain_seq_key(selected)
        if (best is None or ob < best_outbound
                or (ob == best_outbound and seq < best_seq)
                or (ob == best_outbound and seq == best_seq and flat < best_time)):
            best = dict(selected)
            best_outbound = ob
            best_seq = seq
            best_time = flat
            best_schedule = (offsets, times)

    def dfs(idx: int,
            selected: dict[str, Chain],
            used_vouchers: set[str]) -> None:
        if idx == len(order):
            consider(selected)
            return
        eid = order[idx]
        for chain in calibratable[eid]:
            vset = {h.voucher_id for h in chain.handovers}
            if vset & used_vouchers:
                continue  # 物理凭单独占冲突
            trial = dict(selected)
            trial[eid] = chain
            chains = [trial[e] for e in sorted(trial)]
            if not Constraints(pkg, chains).feasible():
                continue  # 联合时钟不可校准
            dfs(idx + 1, trial, used_vouchers | vset)

    dfs(0, {}, set())

    if best is not None:
        chains = [best[e] for e in sorted(best)]
        offsets, times = best_schedule
        return SolveResult(ok=True, chains=chains, offsets=offsets, times=times)

    # 无解分类（与独立穷举器口径一致）
    if not _voucher_only_assignment(calibratable, order):
        return SolveResult(ok=False, code=GLOBAL_VOUCHER_CONFLICT,
                           detail=DETAIL_VOUCHER)
    if not clock_feasible_leaf:
        return SolveResult(ok=False, code=GLOBAL_VOUCHER_CONFLICT,
                           detail=DETAIL_CLOCK)
    if not witness_feasible_leaf:
        return SolveResult(ok=False, code=WITNESS_INSUFFICIENT)
    return SolveResult(ok=False, code=GLOBAL_VOUCHER_CONFLICT,
                       detail=DETAIL_CLOCK)


def _voucher_only_assignment(calibratable: dict[str, list[Chain]],
                             order: list[str]) -> bool:
    """忽略时钟，仅检查物理凭单能否为每件证物分配互不冲突的链。"""
    def dfs(idx: int, used: set[str]) -> bool:
        if idx == len(order):
            return True
        for chain in calibratable[order[idx]]:
            vset = {h.voucher_id for h in chain.handovers}
            if not (vset & used) and dfs(idx + 1, used | vset):
                return True
        return False

    return dfs(0, set())

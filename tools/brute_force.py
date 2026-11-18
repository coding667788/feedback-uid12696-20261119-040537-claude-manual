"""独立组合穷举校验器（仅用于小输入交叉验证）。

与主求解器完全独立：直接枚举证物链的笛卡尔积、所有机构整数偏移，
逐条手工核验凭单独占、差约束、上界与见证覆盖，再按题目三级目标
（出库项数 -> 交接 ID 序列 -> 扁平化全局时刻）取最优。
"""

from __future__ import annotations

from itertools import product

from solution.model import AUTH_OUTBOUND, Package


def _all_paths(pkg: Package, evidence):
    """从采集摘要出发的全部合法路径（独立实现，不调用主链枚举）。"""
    usable = [h for h in pkg.handovers.values()
              if h.digest_ok and h.auth_ok and h.linkage_ok
              and h.evidence_id == evidence.evidence_id]
    by_prev: dict[str, list] = {}
    for h in usable:
        by_prev.setdefault(h.prev_digest, []).append(h)
    results = []

    def dfs(prev, path, seen):
        extended = False
        for h in sorted(by_prev.get(prev, []), key=lambda x: x.handover_id):
            if h.handover_id in seen:
                continue
            extended = True
            if h.digest in evidence.accepted_terminal_digests:
                results.append(path + [h])
            dfs(h.digest, path + [h], seen | {h.handover_id})
        _ = extended

    dfs(evidence.collection_digest, [], set())
    return results


def _event_seq(pkg, evidence, path):
    seq = [(evidence.collection_inst, evidence.collection_local_ts)]
    for h in path:
        seq.append((h.release_person.inst_id, h.release.local_ts))
        seq.append((h.receive_person.inst_id, h.receive.local_ts))
    return seq


def brute_solve(pkg: Package):
    """返回 (status, best_info)。best_info 为 (出库集合, 序列键, 时刻表, 偏移)。"""
    eids = sorted(pkg.evidences)
    paths_per = {eid: _all_paths(pkg, pkg.evidences[eid]) for eid in eids}
    if any(not paths_per[eid] for eid in eids):
        return "EVIDENCE_UNCALIBRATABLE", None

    inst_ids = sorted(pkg.institutions)
    ranges = {iid: range(pkg.institutions[iid].offset_min,
                         pkg.institutions[iid].offset_max + 1)
              for iid in inst_ids}

    best = None  # (outbound_set, seq_key, flat_times, offsets, assignment)
    # 三类中间可行性标记，用于无解时的原因分类
    voucher_ok = False          # 存在仅凭单不冲突的组合
    clock_ok_any = False        # 存在凭单+时钟均可行的组合
    witness_ok_any = False      # 存在凭单+时钟+见证均可行的组合（即 SAT）

    for combo in product(*[paths_per[eid] for eid in eids]):
        assignment = dict(zip(eids, combo))
        # 凭单独占
        all_vouchers = [h.voucher_id for path in combo for h in path]
        if len(all_vouchers) != len(set(all_vouchers)):
            continue
        voucher_ok = True
        # 见证覆盖
        ok_witness = True
        for path in combo:
            kinds = {pkg.persons[s.person_id].inst_id
                     for h in path for s in (h.release, h.receive)}
            if len(kinds) < pkg.min_witness_kinds:
                ok_witness = False
                break
        # 事件序列与上界
        seqs = {eid: _event_seq(pkg, pkg.evidences[eid], assignment[eid])
                for eid in eids}
        uppers = {eid: min(pkg.deadline,
                           pkg.evidences[eid].entry_global_ts) for eid in eids}
        combo_clock_ok = False
        # 枚举偏移
        for offset_values in product(*[ranges[iid] for iid in inst_ids]):
            offsets = dict(zip(inst_ids, offset_values))
            valid = True
            flat = []
            for eid in eids:
                times = [ts + offsets[iid] for iid, ts in seqs[eid]]
                if any(times[i] > times[i + 1] for i in range(len(times) - 1)):
                    valid = False
                    break
                if any(t > uppers[eid] for t in times):
                    valid = False
                    break
                flat.extend(times)
            if not valid:
                continue
            combo_clock_ok = True
            if not ok_witness:
                continue
            witness_ok_any = True
            outbound = {h.handover_id for path in combo for h in path
                        if AUTH_OUTBOUND in (h.release.auth_kind,
                                             h.receive.auth_kind)}
            seq_key = tuple(tuple(h.handover_id for h in assignment[e])
                            for e in eids)
            cand = (outbound, seq_key, flat, offsets, assignment)
            if best is None or (len(outbound), seq_key, flat) < (
                    len(best[0]), best[1], best[2]):
                best = cand
        if combo_clock_ok:
            clock_ok_any = True

    if best is not None:
        return "SAT", best
    if not voucher_ok:
        return "GLOBAL_VOUCHER_CONFLICT", "voucher_occupancy_conflict"
    if not clock_ok_any:
        return "GLOBAL_VOUCHER_CONFLICT", "joint_clock_calibration_conflict"
    if not witness_ok_any:
        return "WITNESS_INSUFFICIENT", None
    return "GLOBAL_VOUCHER_CONFLICT", "joint_clock_calibration_conflict"

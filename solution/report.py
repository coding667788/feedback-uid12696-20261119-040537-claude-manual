"""把求解结果序列化为 result.json 结构。"""

from __future__ import annotations

from .calibration import Chain
from .model import AUTH_OUTBOUND, Package
from .solver import SolveResult, witness_coverage


def _chain_report(pkg: Package,
                  chain: Chain,
                  times: list[int],
                  coverage: dict[str, list[str]]) -> dict:
    events = chain.events
    idx = 1  # events[0] 是采集事件
    handover_reports = []
    for h in chain.handovers:
        rel_t = times[idx]
        rcv_t = times[idx + 1]
        idx += 2
        handover_reports.append({
            "handover_id": h.handover_id,
            "voucher_id": h.voucher_id,
            "digest": h.digest,
            "prev_digest": h.prev_digest,
            "is_outbound": AUTH_OUTBOUND in (h.release.auth_kind,
                                             h.receive.auth_kind),
            "release": {
                "person_id": h.release.person_id,
                "auth_kind": h.release.auth_kind,
                "inst_id": h.release_person.inst_id,
                "local_ts": h.release.local_ts,
                "global_ts": rel_t,
            },
            "receive": {
                "person_id": h.receive.person_id,
                "auth_kind": h.receive.auth_kind,
                "inst_id": h.receive_person.inst_id,
                "local_ts": h.receive.local_ts,
                "global_ts": rcv_t,
            },
            "effective_global_ts": max(rel_t, rcv_t),
        })

    evidence = pkg.evidences[chain.evidence_id]
    return {
        "evidence_id": chain.evidence_id,
        "collection": {
            "digest": evidence.collection_digest,
            "inst_id": evidence.collection_inst,
            "local_ts": evidence.collection_local_ts,
            "global_ts": times[0],
        },
        "checkpoint_entry_global_ts": evidence.entry_global_ts,
        "terminal_digest": chain.terminal_digest,
        "outbound_count": chain.outbound_count,
        "handovers": handover_reports,
        "witness_by_institution": coverage,
        "witness_kind_count": len(coverage),
    }


def build_report(pkg: Package, result: SolveResult) -> dict:
    base = {
        "case_id": pkg.case_id,
        "deadline": pkg.deadline,
        "min_witness_kinds": pkg.min_witness_kinds,
        "validation_notes": pkg.notes,
    }
    if result.ok:
        coverage_all = witness_coverage(pkg, result.chains)
        evidences_out = []
        for chain, times in zip(result.chains, result.times):
            evidences_out.append(
                _chain_report(pkg, chain, times,
                              coverage_all[chain.evidence_id]))
        distinct_outbound = sorted({
            h["handover_id"] for r in evidences_out
            for h in r["handovers"] if h["is_outbound"]})
        return {
            **base,
            "status": "SAT",
            "solution": {
                "distinct_outbound_count": len(distinct_outbound),
                "distinct_outbound_handover_ids": distinct_outbound,
                "institution_offsets": dict(sorted(result.offsets.items())),
                "evidences": evidences_out,
            },
        }

    report = {
        **base,
        "status": "UNSAT",
        "error": {
            "code": result.code,
            "detail": result.detail,
        },
    }
    if result.reason_evidence:
        report["error"]["evidence_reasons"] = dict(
            sorted(result.reason_evidence.items()))
    return report

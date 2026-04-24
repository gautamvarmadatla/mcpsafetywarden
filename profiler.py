import math
from collections import Counter
from typing import Dict, Any, List, Optional

import database as db


def _percentiles(values: List[float], *pcts: float) -> List[Optional[float]]:
    if not values:
        return [None] * len(pcts)
    s = sorted(values)
    n = len(s)
    result = []
    for p in pcts:
        idx_f = p * (n - 1)
        lo = int(idx_f)
        hi = min(lo + 1, n - 1)
        frac = idx_f - lo
        result.append(s[lo] + frac * (s[hi] - s[lo]))
    return result


def compute_profile_from_runs(tool_id: str, prior: Dict[str, Any]) -> Dict[str, Any]:
    """Merge static prior with observed run telemetry into an updated profile."""
    runs = db.get_runs(tool_id, limit=500)

    profile = dict(prior)
    profile["run_count"] = len(runs)

    if not runs: return profile

    total = len(runs)
    failures = sum(1 for r in runs if not r["success"])
    profile["failure_rate"] = round(failures / total, 4)

    latencies = [r["latency_ms"] for r in runs if r["latency_ms"] is not None]
    p50, p95 = _percentiles(latencies, 0.50, 0.95)
    profile["latency_p50_ms"] = round(p50, 1) if p50 is not None else None
    profile["latency_p95_ms"] = round(p95, 1) if p95 is not None else None

    sizes = [r["output_size"] for r in runs if r["output_size"] is not None]
    p95_size, = _percentiles(sizes, 0.95)
    profile["output_size_p95_bytes"] = int(p95_size) if p95_size is not None else None

    hashes = [r["output_schema_hash"] for r in runs if r["output_schema_hash"]]
    if hashes:
        most_common, freq = Counter(hashes).most_common(1)[0]
        profile["schema_stability"] = round(freq / len(hashes), 3)

    if total >= 5:
        boost = min(0.15, total / 150)
        profile["confidence"] = {
            k: round(min(0.97, v + boost), 2)
            for k, v in prior.get("confidence", {}).items()
        }
        extra_evidence = [
            f"observed_{total}_runs",
            f"failure_rate={profile['failure_rate']}",
        ]
        if profile.get("schema_stability") is not None: extra_evidence.append(f"schema_stability={profile['schema_stability']}")
        profile["evidence"] = list(prior.get("evidence", [])) + extra_evidence

    return profile


_UPDATE_EVERY_N_RUNS = 10


def update_tool_profile(tool_id: str, prior: Dict[str, Any]) -> Dict[str, Any]:
    profile = compute_profile_from_runs(tool_id, prior)
    db.upsert_profile(tool_id, profile)
    return profile


def maybe_update_tool_profile(tool_id: str, prior: Dict[str, Any], run_count: int) -> Optional[Dict[str, Any]]:
    if run_count % _UPDATE_EVERY_N_RUNS != 0:
        return None
    return update_tool_profile(tool_id, prior)


def get_or_build_profile(
    tool_id: str,
    fresh_prior: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    stored = db.get_profile(tool_id)

    if fresh_prior is None and stored is not None: return stored

    if fresh_prior is not None and stored is not None:
        prior = dict(stored)
        for k, v in fresh_prior.items():
            if k not in ("run_count", "failure_rate", "latency_p50_ms",
                         "latency_p95_ms", "output_size_p95_bytes",
                         "schema_stability", "evidence", "confidence"):
                prior[k] = v
    else:
        prior = fresh_prior or stored or {
            "effect_class": "unknown",
            "retry_safety": "unknown",
            "destructiveness": "unknown",
            "open_world": False,
            "output_risk": "unknown",
            "confidence": {"effect_class": 0.25},
            "evidence": [],
            "run_count": 0,
        }

    return update_tool_profile(tool_id, prior)

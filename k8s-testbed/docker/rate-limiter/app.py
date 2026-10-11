#!/usr/bin/env python3
"""
Rate Limiter / TAADA Defense Controller
========================================
Implements the TAADA Defense Selection Algorithm (DSA). Receives metrics
from the payment-gateway, classifies attack type and severity, then
activates the appropriate defense bundle within the available latency budget.

Defense Budget Equation:
  Delta_budget = T_SLA - T_baseline - SUM(delta_i * w_i)

DSA: Greedy selection of highest-priority compatible defenses fitting within budget.

Paper: Section VI.G -- TAADA Defense Orchestration
"""

import os
import time
from collections import deque
from typing import Dict, List, Optional, Tuple

from fastapi import FastAPI
from fastapi.responses import JSONResponse
import uvicorn

app = FastAPI(title="TAADA Rate Limiter / Defense Controller", version="1.0.0")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TAADA_ENABLED = os.getenv("TAADA_ENABLED", "true").lower() == "true"
T_SLA_MS = float(os.getenv("SLA_BUDGET_MS", "50"))
T_BASELINE_MS = float(os.getenv("T_BASELINE_MS", "28"))
TPS_TIER = os.getenv("TPS_TIER", "50k+")

# ---------------------------------------------------------------------------
# Defense Catalog (subset: inline defenses relevant to payment gateway)
# ---------------------------------------------------------------------------
DEFENSE_CATALOG = {
    "bin_watch": {
        "overhead_ms": 0.5, "priority": 2,
        "targets": ["bin_enumeration"], "description": "BIN-WATCH entropy detection"
    },
    "rate_limit_per_bin": {
        "overhead_ms": 1.2, "priority": 3,
        "targets": ["bin_enumeration", "auth_flood"], "description": "Per-BIN token bucket"
    },
    "waf": {
        "overhead_ms": 3.1, "priority": 4,
        "targets": ["bin_enumeration", "auth_flood", "mixed"],
        "description": "WAF signature matching"
    },
    "circuit_breaker": {
        "overhead_ms": 0.3, "priority": 3,
        "targets": ["auth_flood", "mixed"], "description": "Circuit breaker (5xx threshold)"
    },
    "acs_guard": {
        "overhead_ms": 2.1, "priority": 2,
        "targets": ["acs_exhaustion", "mixed"], "description": "ACS-GUARD session protection"
    },
    "connection_timeout": {
        "overhead_ms": 0.1, "priority": 2,
        "targets": ["mixed", "slowloris"], "description": "Aggressive connection timeout"
    },
    "ebpf_xdp": {
        "overhead_ms": 0.10, "priority": 2,
        "targets": ["auth_flood", "mixed", "bin_enumeration"],
        "description": "eBPF/XDP packet filter"
    },
}

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_metrics_history: deque = deque(maxlen=60)   # last 60 reports
_active_bundle: List[str] = []
_bundle_activated_at: Optional[float] = None
_attack_type_detected: Optional[str] = None
_delta_budget_ms: float = T_SLA_MS - T_BASELINE_MS
_sla_compliance_history: deque = deque(maxlen=120)
_total_reports = 0
_activation_count = 0


def _classify_attack(metrics: dict) -> Optional[str]:
    """
    Classify attack type from gateway metrics.
    Uses simple rule-based classification matching paper Section VI.G.2.
    """
    sla_rate = metrics.get("sla_compliance_rate", 1.0)
    p99_lat = metrics.get("p99_latency_ms", 0.0)
    rps = metrics.get("requests_per_second", 0.0)

    # No attack signature
    if sla_rate >= 0.98 and p99_lat < T_SLA_MS * 0.7:
        return None

    # Heuristics based on metrics
    if p99_lat > T_SLA_MS * 2 and rps > 500:
        return "auth_flood"
    elif sla_rate < 0.7 and p99_lat > T_SLA_MS:
        return "bin_enumeration"
    elif sla_rate < 0.5:
        return "mixed"
    elif sla_rate < 0.85:
        return "auth_flood"
    return None


def _dsa(attack_type: str) -> List[str]:
    """
    Defense Selection Algorithm: greedy, priority-ordered, budget-constrained.
    Returns selected defense bundle names.
    """
    initial_budget = T_SLA_MS - T_BASELINE_MS
    candidates = []
    for name, defense in DEFENSE_CATALOG.items():
        targets = defense["targets"]
        if attack_type in targets or "all" in targets:
            candidates.append((name, defense["priority"], defense["overhead_ms"]))

    candidates.sort(key=lambda x: (x[1], x[2]))

    bundle = []
    remaining = initial_budget
    for name, priority, overhead in candidates:
        if overhead <= remaining:
            bundle.append(name)
            remaining -= overhead

    return bundle


def _compute_delta_budget(bundle: List[str]) -> float:
    total_overhead = sum(
        DEFENSE_CATALOG[d]["overhead_ms"] for d in bundle if d in DEFENSE_CATALOG
    )
    return T_SLA_MS - T_BASELINE_MS - total_overhead


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "rate-limiter",
        "taada_enabled": TAADA_ENABLED,
        "defense_bundle_active": _active_bundle,
    }


@app.get("/status")
async def status():
    delta = _compute_delta_budget(_active_bundle) if _active_bundle else T_SLA_MS - T_BASELINE_MS
    activation_latency = None
    if _bundle_activated_at:
        activation_latency = round(time.time() - _bundle_activated_at, 2)
    compliance_list = list(_sla_compliance_history)
    sla_rate = sum(compliance_list) / max(1, len(compliance_list))
    return {
        "taada_enabled": TAADA_ENABLED,
        "defense_bundle_active": _active_bundle,
        "attack_type_detected": _attack_type_detected,
        "delta_budget_ms": round(delta, 2),
        "sla_compliance_rate": round(sla_rate, 4),
        "t_sla_ms": T_SLA_MS,
        "t_baseline_ms": T_BASELINE_MS,
        "total_reports_received": _total_reports,
        "bundle_activations": _activation_count,
        "bundle_active_seconds": activation_latency,
    }


@app.post("/report")
async def report(metrics: dict):
    global _active_bundle, _bundle_activated_at, _attack_type_detected
    global _total_reports, _activation_count

    _total_reports += 1
    _metrics_history.append((time.time(), metrics))
    sla_rate = metrics.get("sla_compliance_rate", 1.0)
    _sla_compliance_history.append(sla_rate >= 0.95)

    if not TAADA_ENABLED:
        return JSONResponse({"taada_enabled": False, "action": "none"})

    # Detect attack
    attack_type = _classify_attack(metrics)

    if attack_type is None:
        # No attack: deactivate bundle if active
        if _active_bundle:
            _active_bundle = []
            _bundle_activated_at = None
            _attack_type_detected = None
        return JSONResponse({"attack_detected": False, "action": "none", "bundle": []})

    # Attack detected: select bundle if not already active or attack type changed
    if attack_type != _attack_type_detected or not _active_bundle:
        new_bundle = _dsa(attack_type)
        _active_bundle = new_bundle
        _bundle_activated_at = time.time()
        _attack_type_detected = attack_type
        _activation_count += 1
        delta = _compute_delta_budget(new_bundle)
        return JSONResponse(
            {
                "attack_detected": True,
                "attack_type": attack_type,
                "action": "bundle_activated",
                "bundle": new_bundle,
                "delta_budget_ms": round(delta, 2),
                "sla_compliance_rate": round(sla_rate, 4),
            }
        )

    # Bundle already active for same attack type
    delta = _compute_delta_budget(_active_bundle)
    return JSONResponse(
        {
            "attack_detected": True,
            "attack_type": attack_type,
            "action": "bundle_maintained",
            "bundle": _active_bundle,
            "delta_budget_ms": round(delta, 2),
            "sla_compliance_rate": round(sla_rate, 4),
        }
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)

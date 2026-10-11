#!/usr/bin/env python3
"""
ACS Service (3-D Secure Access Control Server)
===============================================
Implements EMVCo 3-D Secure 2.x challenge flow simulation with
ACS-GUARD session pool protection mechanisms.

ACS-GUARD mechanisms (toggleable via env):
  1. Session pre-pooling with hard cap (alpha * M_session_pool)
  2. Frictionless rate budgeting per merchant
  3. Adaptive session TTL based on pool utilization

Paper: Section VII.E -- ACS-GUARD Protocol
"""

import asyncio
import math
import os
import random
import time
from collections import defaultdict, deque
from typing import Dict, Set

from fastapi import FastAPI
from fastapi.responses import JSONResponse
import uvicorn

app = FastAPI(title="ACS Service", version="1.0.0")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ACS_GUARD_ENABLED = os.getenv("ACS_GUARD_ENABLED", "true").lower() == "true"
SESSION_POOL_SIZE = int(os.getenv("SESSION_POOL_SIZE", "10000"))
ACS_GUARD_ALPHA = float(os.getenv("ACS_GUARD_ALPHA", "0.85"))
NORMAL_TAU = int(os.getenv("NORMAL_TAU", "300"))        # seconds
TAU_MIN = int(os.getenv("TAU_MIN", "30"))               # seconds minimum TTL
U_THRESHOLD = float(os.getenv("U_THRESHOLD", "0.65"))   # utilization threshold
FRICTIONLESS_BUDGET_PER_MIN = int(os.getenv("FRICTIONLESS_BUDGET_PER_MIN", "5000"))
BASE_CHALLENGE_MS_LOW = float(os.getenv("BASE_CHALLENGE_MS_LOW", "50"))
BASE_CHALLENGE_MS_HIGH = float(os.getenv("BASE_CHALLENGE_MS_HIGH", "80"))

# Derived
M_CAP = int(SESSION_POOL_SIZE * ACS_GUARD_ALPHA) if ACS_GUARD_ENABLED else SESSION_POOL_SIZE

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_active_sessions: Dict[str, float] = {}   # session_id -> expiry_timestamp
_frictionless_counts: deque = deque()     # (timestamp, count) per window slot
_total_challenges = 0
_total_accepted = 0
_total_rejected = 0
_legitimate_accepted = 0
_legitimate_total = 0
_attack_rejected = 0
_attack_total = 0
_rng = random.Random(42)


def _current_pool_used() -> int:
    now = time.time()
    expired = [sid for sid, exp in _active_sessions.items() if exp < now]
    for sid in expired:
        del _active_sessions[sid]
    return len(_active_sessions)


def _pool_utilization() -> float:
    cap = M_CAP if ACS_GUARD_ENABLED else SESSION_POOL_SIZE
    return _current_pool_used() / cap


def _adaptive_ttl() -> int:
    """
    ACS-GUARD Mechanism 3: Adaptive session TTL.
    tau(t) = max(tau_min, tau_normal * (1 - clamp((rho - u_threshold) / (1 - u_threshold), 0, 1)))
    """
    if not ACS_GUARD_ENABLED:
        return NORMAL_TAU
    rho = _pool_utilization()
    if rho <= U_THRESHOLD:
        return NORMAL_TAU
    compression = (rho - U_THRESHOLD) / (1.0 - U_THRESHOLD)
    compression = min(compression, 1.0)
    return max(TAU_MIN, int(NORMAL_TAU * (1.0 - compression)))


def _frictionless_budget_remaining() -> int:
    """ACS-GUARD Mechanism 2: Count frictionless requests in last 60s window."""
    now = time.time()
    cutoff = now - 60.0
    while _frictionless_counts and _frictionless_counts[0][0] < cutoff:
        _frictionless_counts.popleft()
    used = sum(c for _, c in _frictionless_counts)
    return max(0, FRICTIONLESS_BUDGET_PER_MIN - used)


def _record_frictionless(count: int = 1):
    _frictionless_counts.append((time.time(), count))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "acs-service",
        "acs_guard_enabled": ACS_GUARD_ENABLED,
        "pool_used": _current_pool_used(),
        "pool_cap": M_CAP,
    }


@app.get("/metrics")
async def metrics():
    pool_used = _current_pool_used()
    pool_cap = M_CAP if ACS_GUARD_ENABLED else SESSION_POOL_SIZE
    util = pool_used / pool_cap if pool_cap > 0 else 0.0
    leg_rate = _legitimate_accepted / max(1, _legitimate_total)
    atk_rej_rate = _attack_rejected / max(1, _attack_total)
    return {
        "acs_guard_enabled": ACS_GUARD_ENABLED,
        "session_pool_used": pool_used,
        "session_pool_cap": pool_cap,
        "pool_utilization": round(util, 4),
        "adaptive_ttl_seconds": _adaptive_ttl(),
        "frictionless_budget_remaining": _frictionless_budget_remaining(),
        "total_challenges": _total_challenges,
        "total_accepted": _total_accepted,
        "total_rejected": _total_rejected,
        "legitimate_acceptance_rate": round(leg_rate, 4),
        "attack_rejection_rate": round(atk_rej_rate, 4),
    }


@app.post("/challenge")
async def challenge(body: dict = None):
    global _total_challenges, _total_accepted, _total_rejected
    global _legitimate_accepted, _legitimate_total, _attack_rejected, _attack_total

    body = body or {}
    is_frictionless = body.get("frictionless", False)
    is_legitimate = body.get("is_legitimate", True)
    _total_challenges += 1

    if is_legitimate:
        _legitimate_total += 1
    else:
        _attack_total += 1

    pool_used = _current_pool_used()
    pool_cap = M_CAP if ACS_GUARD_ENABLED else SESSION_POOL_SIZE

    # ACS-GUARD Mechanism 1: Hard cap check
    if pool_used >= pool_cap:
        _total_rejected += 1
        if not is_legitimate:
            _attack_rejected += 1
        return JSONResponse(
            {"session_accepted": False, "reason": "pool_exhausted", "pool_utilization": 1.0},
            status_code=429,
        )

    # ACS-GUARD Mechanism 2: Frictionless budget check
    if is_frictionless and ACS_GUARD_ENABLED:
        budget = _frictionless_budget_remaining()
        if budget <= 0:
            _total_rejected += 1
            if not is_legitimate:
                _attack_rejected += 1
            return JSONResponse(
                {"session_accepted": False, "reason": "frictionless_budget_exhausted"},
                status_code=429,
            )
        _record_frictionless(1)

    # Accept session
    ttl = _adaptive_ttl()
    session_id = f"sess_{int(time.time() * 1000)}_{_rng.randint(0, 99999):05d}"
    _active_sessions[session_id] = time.time() + ttl

    # Simulate challenge processing time
    t0 = time.perf_counter()
    delay_ms = _rng.uniform(BASE_CHALLENGE_MS_LOW, BASE_CHALLENGE_MS_HIGH)
    await asyncio.sleep(delay_ms / 1000.0)
    processing_ms = (time.perf_counter() - t0) * 1000

    _total_accepted += 1
    if is_legitimate:
        _legitimate_accepted += 1

    return JSONResponse(
        {
            "session_accepted": True,
            "session_id": session_id,
            "session_ttl_seconds": ttl,
            "challenge_url": f"https://acs.testbed/challenge/{session_id}",
            "processing_time_ms": round(processing_ms, 2),
            "pool_utilization": round((_current_pool_used()) / pool_cap, 4),
        }
    )


@app.delete("/session/{session_id}")
async def close_session(session_id: str):
    """RReq equivalent: close a completed challenge session."""
    if session_id in _active_sessions:
        del _active_sessions[session_id]
        return {"closed": True}
    return JSONResponse({"closed": False, "reason": "not_found"}, status_code=404)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)

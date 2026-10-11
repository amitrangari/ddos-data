#!/usr/bin/env python3
"""
Payment Gateway Service
=======================
Entry point for the payment processing testbed. Routes authorization,
tokenization, and 3DS challenge requests to downstream services while
recording latency and reporting SLA compliance metrics.

Paper: "Adaptive DDoS Defense Strategies for High-TPS Payment Processing Systems"
Section: IX.C.1 -- TAADA Testbed Validation
"""

import asyncio
import os
import time
import statistics
from collections import deque
from typing import Optional

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
import uvicorn

app = FastAPI(title="Payment Gateway", version="1.0.0")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://auth-service:8080")
ACS_SERVICE_URL = os.getenv("ACS_SERVICE_URL", "http://acs-service:8080")
BIN_LOOKUP_URL = os.getenv("BIN_LOOKUP_URL", "http://bin-lookup-service:8080")
RATE_LIMITER_URL = os.getenv("RATE_LIMITER_URL", "http://rate-limiter:8080")
SLA_BUDGET_MS = float(os.getenv("SLA_BUDGET_MS", "50"))

# ---------------------------------------------------------------------------
# In-memory metrics state
# ---------------------------------------------------------------------------
_window_seconds = 60
_request_times: deque = deque()   # (timestamp_s, latency_ms, sla_ok)
_total_requests = 0
_sla_violations = 0
_start_time = time.time()


def _record(latency_ms: float) -> bool:
    global _total_requests, _sla_violations
    now = time.time()
    sla_ok = latency_ms <= SLA_BUDGET_MS
    _request_times.append((now, latency_ms, sla_ok))
    _total_requests += 1
    if not sla_ok:
        _sla_violations += 1
    # Prune old entries outside sliding window
    cutoff = now - _window_seconds
    while _request_times and _request_times[0][0] < cutoff:
        _request_times.popleft()
    return sla_ok


def _current_metrics() -> dict:
    now = time.time()
    cutoff = now - _window_seconds
    window = [(t, lat, ok) for t, lat, ok in _request_times if t >= cutoff]
    if not window:
        return {
            "requests_per_second": 0.0,
            "mean_latency_ms": 0.0,
            "p99_latency_ms": 0.0,
            "sla_compliance_rate": 1.0,
            "window_requests": 0,
        }
    latencies = sorted(lat for _, lat, _ in window)
    sla_ok_count = sum(1 for _, _, ok in window if ok)
    p99_idx = max(0, int(len(latencies) * 0.99) - 1)
    elapsed = now - _start_time
    return {
        "requests_per_second": round(len(window) / _window_seconds, 2),
        "mean_latency_ms": round(statistics.mean(latencies), 2),
        "p99_latency_ms": round(latencies[p99_idx], 2),
        "sla_compliance_rate": round(sla_ok_count / len(window), 4),
        "window_requests": len(window),
        "total_requests": _total_requests,
        "total_sla_violations": _sla_violations,
        "uptime_seconds": round(elapsed, 1),
    }


# ---------------------------------------------------------------------------
# HTTP client (shared, connection-pooled)
# ---------------------------------------------------------------------------
_http_client: Optional[httpx.AsyncClient] = None


@app.on_event("startup")
async def startup():
    global _http_client
    _http_client = httpx.AsyncClient(timeout=5.0)


@app.on_event("shutdown")
async def shutdown():
    if _http_client:
        await _http_client.aclose()


async def _report_metrics_to_rate_limiter(metrics: dict):
    """Fire-and-forget metrics report to TAADA rate-limiter controller."""
    try:
        await _http_client.post(f"{RATE_LIMITER_URL}/report", json=metrics, timeout=1.0)
    except Exception:
        pass  # Non-fatal; rate limiter may not be ready


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok", "service": "payment-gateway"}


@app.get("/metrics")
async def metrics():
    return JSONResponse(_current_metrics())


@app.post("/authorize")
async def authorize(request: Request):
    t0 = time.perf_counter()
    body = await request.json()
    bin_prefix = str(body.get("bin", "400000"))[:6]

    # Step 1: BIN lookup + entropy check
    bin_result = {"action": "allow", "bes_score": 0.0, "is_attack": False}
    try:
        resp = await _http_client.post(
            f"{BIN_LOOKUP_URL}/lookup",
            json={"bin": bin_prefix, "source_ip": body.get("source_ip", "0.0.0.0")},
        )
        if resp.status_code == 200:
            bin_result = resp.json()
    except Exception:
        pass

    if bin_result.get("action") == "block":
        latency_ms = (time.perf_counter() - t0) * 1000
        _record(latency_ms)
        return JSONResponse(
            {"status": "blocked", "reason": "bin_watch_block", "bes_score": bin_result.get("bes_score")},
            status_code=429,
        )

    # Step 2: Forward to auth-service
    auth_result = {"approved": False, "processing_time_ms": 0}
    try:
        resp = await _http_client.post(
            f"{AUTH_SERVICE_URL}/authorize",
            json=body,
        )
        if resp.status_code == 200:
            auth_result = resp.json()
    except Exception as exc:
        latency_ms = (time.perf_counter() - t0) * 1000
        _record(latency_ms)
        return JSONResponse({"status": "error", "detail": str(exc)}, status_code=503)

    latency_ms = (time.perf_counter() - t0) * 1000
    sla_ok = _record(latency_ms)
    m = _current_metrics()
    asyncio.create_task(_report_metrics_to_rate_limiter(m))

    return JSONResponse(
        {
            "status": "approved" if auth_result.get("approved") else "declined",
            "latency_ms": round(latency_ms, 2),
            "sla_ok": sla_ok,
            "bin_action": bin_result.get("action", "allow"),
            "bes_score": bin_result.get("bes_score", 0.0),
            "processing_time_ms": auth_result.get("processing_time_ms", 0),
        }
    )


@app.post("/tokenize")
async def tokenize(request: Request):
    t0 = time.perf_counter()
    body = await request.json()
    # Simulate tokenization (lightweight)
    await asyncio.sleep(0.003)
    latency_ms = (time.perf_counter() - t0) * 1000
    _record(latency_ms)
    pan = str(body.get("pan", "4000000000000000"))
    token = "TOK" + pan[-4:].zfill(12)
    return JSONResponse({"token": token, "latency_ms": round(latency_ms, 2)})


@app.post("/3ds/challenge")
async def threeds_challenge(request: Request):
    t0 = time.perf_counter()
    body = await request.json()
    acs_result = {"session_accepted": False, "challenge_url": None}
    try:
        resp = await _http_client.post(f"{ACS_SERVICE_URL}/challenge", json=body)
        if resp.status_code == 200:
            acs_result = resp.json()
        elif resp.status_code == 429:
            latency_ms = (time.perf_counter() - t0) * 1000
            _record(latency_ms)
            return JSONResponse({"status": "pool_exhausted"}, status_code=429)
    except Exception as exc:
        latency_ms = (time.perf_counter() - t0) * 1000
        _record(latency_ms)
        return JSONResponse({"status": "acs_unavailable"}, status_code=503)

    latency_ms = (time.perf_counter() - t0) * 1000
    _record(latency_ms)
    return JSONResponse(
        {
            "status": "challenge_initiated" if acs_result.get("session_accepted") else "rejected",
            "latency_ms": round(latency_ms, 2),
            "acs_result": acs_result,
        }
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)

#!/usr/bin/env python3
"""
Metrics Collector Service
=========================
Scrapes metrics from all testbed services and provides consolidated
results including SLA compliance, TAADA effectiveness, and BIN-WATCH F1.

Endpoints:
  GET /metrics  -- consolidated JSON metrics from all services
  GET /report   -- formatted markdown results table
  GET /health   -- liveness probe

Paper: Section IX.C.1 -- Metrics Collection and Reporting
"""

import asyncio
import os
import time
from typing import Dict, Any, Optional

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse
import uvicorn

app = FastAPI(title="Metrics Collector", version="1.0.0")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PAYMENT_GATEWAY_URL  = os.getenv("PAYMENT_GATEWAY_URL",  "http://payment-gateway:8080")
AUTH_SERVICE_URL     = os.getenv("AUTH_SERVICE_URL",     "http://auth-service:8080")
ACS_SERVICE_URL      = os.getenv("ACS_SERVICE_URL",      "http://acs-service:8080")
BIN_LOOKUP_URL       = os.getenv("BIN_LOOKUP_URL",       "http://bin-lookup-service:8080")
RATE_LIMITER_URL     = os.getenv("RATE_LIMITER_URL",     "http://rate-limiter:8080")
ATTACK_GENERATOR_URL = os.getenv("ATTACK_GENERATOR_URL", "http://attack-generator:8080")
SCRAPE_TIMEOUT_S     = float(os.getenv("SCRAPE_TIMEOUT_S", "3.0"))

# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------
_http_client: Optional[httpx.AsyncClient] = None

@app.on_event("startup")
async def startup():
    global _http_client
    _http_client = httpx.AsyncClient(timeout=SCRAPE_TIMEOUT_S)

@app.on_event("shutdown")
async def shutdown():
    if _http_client:
        await _http_client.aclose()


async def _scrape(url: str, path: str = "/metrics") -> Dict[str, Any]:
    try:
        resp = await _http_client.get(f"{url}{path}")
        if resp.status_code == 200:
            return resp.json()
    except Exception as exc:
        return {"error": str(exc)}
    return {}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok", "service": "metrics-collector"}


@app.get("/metrics")
async def metrics():
    """Scrape all services concurrently and return consolidated metrics."""
    gw, auth, acs, bin_svc, rl, atk = await asyncio.gather(
        _scrape(PAYMENT_GATEWAY_URL,  "/metrics"),
        _scrape(AUTH_SERVICE_URL,     "/metrics"),
        _scrape(ACS_SERVICE_URL,      "/metrics"),
        _scrape(BIN_LOOKUP_URL,       "/metrics"),
        _scrape(RATE_LIMITER_URL,     "/status"),
        _scrape(ATTACK_GENERATOR_URL, "/status"),
        return_exceptions=False,
    )
    return JSONResponse(
        {
            "timestamp": time.time(),
            "payment_gateway": gw,
            "auth_service": auth,
            "acs_service": acs,
            "bin_lookup": bin_svc,
            "rate_limiter": rl,
            "attack_generator": atk,
        }
    )


@app.get("/report", response_class=PlainTextResponse)
async def report():
    """Return a formatted markdown results table matching the paper's expected output."""
    gw, bin_svc, rl, atk = await asyncio.gather(
        _scrape(PAYMENT_GATEWAY_URL,  "/metrics"),
        _scrape(BIN_LOOKUP_URL,       "/metrics"),
        _scrape(RATE_LIMITER_URL,     "/status"),
        _scrape(ATTACK_GENERATOR_URL, "/status"),
        return_exceptions=False,
    )

    def _fmt_err(d: dict, key: str, default="N/A", fmt=None) -> str:
        v = d.get(key, default) if isinstance(d, dict) and "error" not in d else default
        if fmt and v != default:
            return fmt(v)
        return str(v)

    rps         = _fmt_err(gw, "requests_per_second", "N/A", lambda v: f"{v:,.0f}")
    mean_lat    = _fmt_err(gw, "mean_latency_ms",     "N/A", lambda v: f"{v:.1f}ms")
    p99_lat     = _fmt_err(gw, "p99_latency_ms",      "N/A", lambda v: f"{v:.1f}ms")
    sla_rate    = _fmt_err(gw, "sla_compliance_rate", "N/A", lambda v: f"{v*100:.1f}%")

    f1          = _fmt_err(bin_svc, "f1_score",           "N/A", lambda v: f"{v:.3f}")
    fpr         = _fmt_err(bin_svc, "false_positive_rate","N/A", lambda v: f"{v:.3f}")
    bes         = _fmt_err(bin_svc, "bes_score",          "N/A", lambda v: f"{v:.2f}")
    bin_action  = _fmt_err(bin_svc, "current_action",     "N/A")

    bundle      = _fmt_err(rl, "defense_bundle_active", [], lambda v: ", ".join(v) if v else "none")
    delta_b     = _fmt_err(rl, "delta_budget_ms",  "N/A", lambda v: f"{v:.1f}ms")
    atk_type    = _fmt_err(rl, "attack_type_detected", "none")
    taada_on    = _fmt_err(rl, "taada_enabled", "N/A")

    atk_active  = _fmt_err(atk, "attack_active",  "N/A")
    atk_rps     = _fmt_err(atk, "current_rps",    "N/A", lambda v: f"{v:,.0f}")
    atk_kind    = _fmt_err(atk, "attack_type",     "none")
    atk_intens  = _fmt_err(atk, "attack_intensity","N/A")

    lines = [
        "=== DDoS Defense Testbed Results ===",
        f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        "",
        "--- PAYMENT GATEWAY METRICS ---",
        f"  Requests/sec:        {rps}",
        f"  Mean Latency:        {mean_lat}",
        f"  P99 Latency:         {p99_lat}",
        f"  SLA Compliance:      {sla_rate}",
        "",
        "--- BIN-WATCH (BIN LOOKUP SERVICE) ---",
        f"  BES Score:           {bes}",
        f"  Current Action:      {bin_action}",
        f"  F1 Score:            {f1}",
        f"  False Positive Rate: {fpr}",
        "",
        "--- TAADA RATE LIMITER ---",
        f"  TAADA Enabled:       {taada_on}",
        f"  Attack Detected:     {atk_type}",
        f"  Defense Bundle:      [{bundle}]",
        f"  Delta_budget:        {delta_b} remaining",
        "",
        "--- ATTACK GENERATOR ---",
        f"  Attack Active:       {atk_active}",
        f"  Attack Type:         {atk_kind}",
        f"  Intensity:           {atk_intens}",
        f"  Attack RPS:          {atk_rps}",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)

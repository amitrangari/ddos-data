#!/usr/bin/env python3
"""
Attack Generator Service
========================
Injects controlled DDoS attack traffic into the payment processing testbed.
Supports BIN enumeration, auth flood, and mixed attack types with gradual
escalation (starts at 20% intensity, ramps over 60 seconds).

Attack types:
  bin_enumeration  -- Sequential or random BIN prefix probing
  auth_flood       -- Rapid ISO 8583 0100 authorization requests
  mixed            -- Combined BIN enumeration + auth flood

Paper: Section IX.C.1 -- Testbed Attack Simulation Toolkit
"""

import asyncio
import os
import random
import time
from typing import Optional

import httpx
from fastapi import FastAPI, BackgroundTasks
from fastapi.responses import JSONResponse
import uvicorn

app = FastAPI(title="Attack Generator", version="1.0.0")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PAYMENT_GATEWAY_URL = os.getenv("PAYMENT_GATEWAY_URL", "http://payment-gateway:8080")
BIN_LOOKUP_URL = os.getenv("BIN_LOOKUP_URL", "http://bin-lookup-service:8080")
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://auth-service:8080")
ACS_SERVICE_URL = os.getenv("ACS_SERVICE_URL", "http://acs-service:8080")
RAMP_DURATION_S = int(os.getenv("RAMP_DURATION_S", "60"))
INITIAL_INTENSITY_PCT = float(os.getenv("INITIAL_INTENSITY_PCT", "0.20"))

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_attack_active = False
_attack_type: Optional[str] = None
_attack_intensity: str = "medium"
_attack_start_time: Optional[float] = None
_attack_duration_s: int = 120
_attack_task: Optional[asyncio.Task] = None
_requests_sent = 0
_requests_succeeded = 0
_current_rps = 0.0
_rng = random.Random(int(time.time()))

INTENSITY_RPS = {
    "low":    50,
    "medium": 200,
    "high":   1000,
}

# BIN ranges for enumeration
_SEQUENTIAL_START = 400000
_SEQUENTIAL_END   = 499999
_sequential_cursor = _SEQUENTIAL_START


def _next_attack_bin(mode: str = "random") -> str:
    global _sequential_cursor
    if mode == "sequential":
        bin_val = _sequential_cursor
        _sequential_cursor += 1
        if _sequential_cursor > _SEQUENTIAL_END:
            _sequential_cursor = _SEQUENTIAL_START
        return str(bin_val)
    elif mode == "targeted":
        # Focused on high-value BIN range
        return str(_rng.randint(400000, 405000))
    else:
        # Random
        return str(_rng.randint(100000, 999999))


def _ramp_factor(elapsed_s: float) -> float:
    """Linear ramp from INITIAL_INTENSITY_PCT to 1.0 over RAMP_DURATION_S."""
    if elapsed_s >= RAMP_DURATION_S:
        return 1.0
    progress = elapsed_s / RAMP_DURATION_S
    return INITIAL_INTENSITY_PCT + (1.0 - INITIAL_INTENSITY_PCT) * progress


async def _run_bin_enumeration(client: httpx.AsyncClient, target_rps: int, mode: str = "random"):
    global _requests_sent, _requests_succeeded
    interval = 1.0 / max(1, target_rps)
    try:
        bin_prefix = _next_attack_bin(mode)
        resp = await client.post(
            f"{BIN_LOOKUP_URL}/lookup",
            json={"bin": bin_prefix, "source_ip": f"10.{_rng.randint(0,255)}.{_rng.randint(0,255)}.1",
                  "is_legitimate": False},
            timeout=2.0,
        )
        _requests_sent += 1
        if resp.status_code == 200:
            _requests_succeeded += 1
    except Exception:
        _requests_sent += 1


async def _run_auth_flood(client: httpx.AsyncClient):
    global _requests_sent, _requests_succeeded
    try:
        resp = await client.post(
            f"{AUTH_SERVICE_URL}/authorize",
            json={
                "pan": f"4{''.join([str(_rng.randint(0,9)) for _ in range(15)])}",
                "amount": _rng.randint(100, 50000),
                "merchant_id": f"M{_rng.randint(1000, 9999)}",
                "is_legitimate": False,
            },
            timeout=2.0,
        )
        _requests_sent += 1
        if resp.status_code == 200:
            _requests_succeeded += 1
    except Exception:
        _requests_sent += 1


async def _run_acs_exhaustion(client: httpx.AsyncClient):
    global _requests_sent, _requests_succeeded
    try:
        resp = await client.post(
            f"{ACS_SERVICE_URL}/challenge",
            json={
                "device_channel": "02",
                "message_category": "01",
                "frictionless": False,
                "is_legitimate": False,
            },
            timeout=2.0,
        )
        _requests_sent += 1
        if resp.status_code in (200, 429):
            _requests_succeeded += 1
    except Exception:
        _requests_sent += 1


async def _attack_loop():
    global _attack_active, _current_rps
    attack_type = _attack_type
    intensity = _attack_intensity
    start = time.time()
    target_rps = INTENSITY_RPS.get(intensity, 200)

    async with httpx.AsyncClient(limits=httpx.Limits(max_connections=200)) as client:
        while _attack_active and (time.time() - start) < _attack_duration_s:
            elapsed = time.time() - start
            ramp = _ramp_factor(elapsed)
            effective_rps = max(1, int(target_rps * ramp))
            _current_rps = effective_rps

            # Launch a burst of concurrent requests
            batch_size = min(effective_rps, 50)  # cap concurrency per iteration
            tasks = []
            for _ in range(batch_size):
                if attack_type == "bin_enumeration":
                    tasks.append(_run_bin_enumeration(client, effective_rps, mode="sequential"))
                elif attack_type == "auth_flood":
                    tasks.append(_run_auth_flood(client))
                elif attack_type == "mixed":
                    if _rng.random() < 0.6:
                        tasks.append(_run_bin_enumeration(client, effective_rps, mode="random"))
                    elif _rng.random() < 0.8:
                        tasks.append(_run_auth_flood(client))
                    else:
                        tasks.append(_run_acs_exhaustion(client))

            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.sleep(1.0)

    _attack_active = False


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "attack-generator",
        "attack_active": _attack_active,
        "attack_type": _attack_type,
    }


@app.get("/status")
async def status():
    elapsed = round(time.time() - _attack_start_time, 1) if _attack_start_time else 0
    return {
        "attack_active": _attack_active,
        "attack_type": _attack_type,
        "attack_intensity": _attack_intensity,
        "elapsed_seconds": elapsed,
        "duration_seconds": _attack_duration_s,
        "current_rps": _current_rps,
        "requests_sent": _requests_sent,
        "requests_succeeded": _requests_succeeded,
        "ramp_factor": round(_ramp_factor(elapsed), 3),
    }


@app.post("/start")
async def start_attack(body: dict, background_tasks: BackgroundTasks):
    global _attack_active, _attack_type, _attack_intensity
    global _attack_start_time, _attack_duration_s
    global _requests_sent, _requests_succeeded, _current_rps

    if _attack_active:
        return JSONResponse({"error": "attack already running"}, status_code=409)

    attack_type = body.get("type", "bin_enumeration")
    if attack_type not in ("bin_enumeration", "auth_flood", "mixed"):
        return JSONResponse({"error": f"unknown attack type: {attack_type}"}, status_code=400)

    _attack_type = attack_type
    _attack_intensity = body.get("intensity", "medium")
    _attack_duration_s = int(body.get("duration_seconds", 120))
    _attack_active = True
    _attack_start_time = time.time()
    _requests_sent = 0
    _requests_succeeded = 0
    _current_rps = 0.0

    background_tasks.add_task(_attack_loop)

    return JSONResponse(
        {
            "started": True,
            "attack_type": _attack_type,
            "intensity": _attack_intensity,
            "duration_seconds": _attack_duration_s,
            "target_rps": INTENSITY_RPS.get(_attack_intensity, 200),
            "ramp_duration_seconds": RAMP_DURATION_S,
        }
    )


@app.post("/stop")
async def stop_attack():
    global _attack_active
    was_active = _attack_active
    _attack_active = False
    return JSONResponse(
        {
            "stopped": was_active,
            "total_requests_sent": _requests_sent,
            "total_succeeded": _requests_succeeded,
        }
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)

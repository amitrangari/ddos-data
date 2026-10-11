#!/usr/bin/env python3
"""
Authorization Service
=====================
Simulates ISO 8583 MTI 0100 (Authorization Request) processing.
Processing time increases linearly with queue depth to model congestion.

Paper: "Adaptive DDoS Defense Strategies for High-TPS Payment Processing Systems"
"""

import asyncio
import os
import random
import time
from collections import deque

from fastapi import FastAPI
from fastapi.responses import JSONResponse
import uvicorn

app = FastAPI(title="Authorization Service", version="1.0.0")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_PROC_MS_LOW = float(os.getenv("BASE_PROC_MS_LOW", "12"))
BASE_PROC_MS_HIGH = float(os.getenv("BASE_PROC_MS_HIGH", "28"))
CONGESTION_FACTOR = float(os.getenv("CONGESTION_FACTOR", "0.05"))  # ms per queued request

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
_queue_depth = 0
_total_processed = 0
_processing_times: deque = deque(maxlen=500)
_rng = random.Random(42)


def _base_proc_ms() -> float:
    return _rng.uniform(BASE_PROC_MS_LOW, BASE_PROC_MS_HIGH)


def _congestion_delay_ms(depth: int) -> float:
    """Linear congestion model: each queued request adds CONGESTION_FACTOR ms."""
    return min(depth * CONGESTION_FACTOR, 25.0)  # cap at 25 ms extra


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok", "service": "auth-service", "queue_depth": _queue_depth}


@app.get("/metrics")
async def metrics():
    if _processing_times:
        times = list(_processing_times)
        mean_t = sum(times) / len(times)
        sorted_t = sorted(times)
        p99_idx = max(0, int(len(sorted_t) * 0.99) - 1)
        p99_t = sorted_t[p99_idx]
    else:
        mean_t = 0.0
        p99_t = 0.0
    return {
        "total_processed": _total_processed,
        "queue_depth": _queue_depth,
        "mean_processing_time_ms": round(mean_t, 2),
        "p99_processing_time_ms": round(p99_t, 2),
    }


@app.post("/authorize")
async def authorize(request_body: dict = None):
    global _queue_depth, _total_processed

    _queue_depth += 1
    t0 = time.perf_counter()

    # Simulate ISO 8583 0100 processing with congestion model
    base_ms = _base_proc_ms()
    congestion_ms = _congestion_delay_ms(_queue_depth)
    total_delay_s = (base_ms + congestion_ms) / 1000.0

    await asyncio.sleep(total_delay_s)

    processing_ms = (time.perf_counter() - t0) * 1000
    _processing_times.append(processing_ms)
    _total_processed += 1
    _queue_depth = max(0, _queue_depth - 1)

    # Approval logic: reject if congestion is severe (simulates back-pressure)
    approved = congestion_ms < 20.0

    return JSONResponse(
        {
            "approved": approved,
            "mti": "0110",  # Authorization Response
            "processing_time_ms": round(processing_ms, 2),
            "queue_depth": _queue_depth,
            "congestion_ms": round(congestion_ms, 2),
            "response_code": "00" if approved else "51",  # 51 = Insufficient funds / congestion
        }
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)

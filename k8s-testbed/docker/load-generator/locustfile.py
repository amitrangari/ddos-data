"""
Locust Load Generator -- Legitimate Payment Traffic
===================================================
Simulates realistic payment authorization traffic against the payment-gateway.
Transaction mix: authorize (85%), tokenize (10%), 3ds_challenge (5%).

BIN distribution follows Zipf's law (alpha=1.5) over 10,000 legitimate BINs.
Time-of-day variation can be configured via LOCUST_TIME_VARIATION env var.

Usage:
  locust -f locustfile.py --host http://payment-gateway:8080 \
    --users 50 --spawn-rate 5 --headless --run-time 3m

Paper: Section IX.C.1 -- Legitimate Traffic Generation
"""

import math
import os
import random
import time

from locust import HttpUser, between, task

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
NUM_LEGIT_BINS = int(os.getenv("NUM_LEGIT_BINS", "10000"))
ZIPF_ALPHA = 1.5
TIME_VARIATION = os.getenv("LOCUST_TIME_VARIATION", "false").lower() == "true"

# ---------------------------------------------------------------------------
# BIN table: Zipf weights over NUM_LEGIT_BINS prefixes
# ---------------------------------------------------------------------------
_rng = random.Random(42)
_LEGIT_BINS = []
for _ in range(NUM_LEGIT_BINS):
    prefix = _rng.choice(["4", "5", "6"])
    suffix = "".join([str(_rng.randint(0, 9)) for _ in range(5)])
    _LEGIT_BINS.append(prefix + suffix)

# Zipf weights
_ZIPF_WEIGHTS = [1.0 / (i ** ZIPF_ALPHA) for i in range(1, NUM_LEGIT_BINS + 1)]
_WEIGHT_SUM = sum(_ZIPF_WEIGHTS)
_ZIPF_CDF = []
cumulative = 0.0
for w in _ZIPF_WEIGHTS:
    cumulative += w / _WEIGHT_SUM
    _ZIPF_CDF.append(cumulative)


def _zipf_bin() -> str:
    """Sample a BIN prefix using Zipf distribution."""
    r = random.random()
    lo, hi = 0, len(_ZIPF_CDF) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        if _ZIPF_CDF[mid] < r:
            lo = mid + 1
        else:
            hi = mid
    return _LEGIT_BINS[lo]


def _time_of_day_multiplier() -> float:
    if not TIME_VARIATION:
        return 1.0
    hour = time.localtime().tm_hour
    multipliers = {
        0: 0.25, 1: 0.20, 2: 0.15, 3: 0.15, 4: 0.15, 5: 0.20,
        6: 0.35, 7: 0.55, 8: 0.70, 9: 0.80, 10: 0.90, 11: 1.00,
        12: 1.00, 13: 0.90, 14: 0.80, 15: 0.75, 16: 0.85, 17: 0.95,
        18: 0.95, 19: 0.85, 20: 0.70, 21: 0.55, 22: 0.40, 23: 0.30,
    }
    return multipliers.get(hour, 1.0)


# ---------------------------------------------------------------------------
# Locust User
# ---------------------------------------------------------------------------
class PaymentUser(HttpUser):
    # Wait between 100ms-500ms between tasks (simulates human-paced payment flow)
    wait_time = between(0.1, 0.5)

    @task(85)
    def authorize(self):
        bin_prefix = _zipf_bin()
        pan = bin_prefix + "".join([str(random.randint(0, 9)) for _ in range(10)])
        payload = {
            "pan": pan,
            "bin": bin_prefix,
            "amount": random.randint(100, 500_000),  # cents
            "currency": "USD",
            "merchant_id": f"M{random.randint(1000, 9999)}",
            "merchant_category_code": random.choice(["5411", "5912", "7011", "4511"]),
            "source_ip": f"203.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
            "is_legitimate": True,
        }
        with self.client.post("/authorize", json=payload, catch_response=True) as resp:
            if resp.status_code == 200:
                data = resp.json()
                if data.get("sla_ok") is False:
                    resp.failure(f"SLA violated: {data.get('latency_ms', 'N/A')}ms")
                else:
                    resp.success()
            elif resp.status_code == 429:
                resp.failure("Rate limited (false positive?)")
            else:
                resp.failure(f"HTTP {resp.status_code}")

    @task(10)
    def tokenize(self):
        bin_prefix = _zipf_bin()
        pan = bin_prefix + "".join([str(random.randint(0, 9)) for _ in range(10)])
        payload = {"pan": pan, "is_legitimate": True}
        with self.client.post("/tokenize", json=payload, catch_response=True) as resp:
            if resp.status_code == 200:
                resp.success()
            else:
                resp.failure(f"HTTP {resp.status_code}")

    @task(5)
    def threeds_challenge(self):
        payload = {
            "transaction_id": f"TXN{random.randint(100000, 999999)}",
            "device_channel": "02",
            "frictionless": random.random() < 0.7,
            "is_legitimate": True,
        }
        with self.client.post("/3ds/challenge", json=payload, catch_response=True) as resp:
            if resp.status_code in (200, 429):
                resp.success()
            else:
                resp.failure(f"HTTP {resp.status_code}")

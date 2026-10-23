"""Shared helpers for the v1.3.0 experiment drivers (round-3 review, Phase 2).
Every driver writes one JSON file to $RESULTS_DIR (default results/v1.3.0/)."""
import json
import logging
import os
import statistics as st
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
logging.disable(logging.WARNING)
RESULTS_DIR = os.environ.get("RESULTS_DIR", os.path.join(ROOT, "results", "v1.3.0"))
N_PROC = int(os.environ.get("N_PROC", str(max(1, (os.cpu_count() or 2) - 1))))


def write(name: str, obj) -> str:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    path = os.path.join(RESULTS_DIR, name)
    with open(path, "w") as f:
        json.dump(obj, f, indent=1, default=float)
    print("wrote", path)
    return path


def q(xs, p):
    xs = sorted(xs)
    if not xs:
        return None
    k = (len(xs) - 1) * p
    lo = int(k)
    hi = min(lo + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def summ(xs, nd=3):
    xs = [x for x in xs if x is not None]
    if not xs:
        return {"n": 0}
    return {"n": len(xs), "median": round(q(xs, 0.5), nd), "q25": round(q(xs, 0.25), nd),
            "q75": round(q(xs, 0.75), nd), "min": round(min(xs), nd), "max": round(max(xs), nd),
            "mean": round(st.mean(xs), nd)}


def clopper_pearson(k: int, n: int, conf: float = 0.95):
    if n <= 0:
        return None
    from scipy.stats import beta
    a = (1 - conf) / 2
    lo = 0.0 if k == 0 else float(beta.ppf(a, k, n - k + 1))
    hi = 1.0 if k == n else float(beta.ppf(1 - a, k + 1, n - k))
    return [round(lo, 5), round(hi, 5)]


def mean_ci(xs, conf: float = 0.95):
    from scipy.stats import t
    n = len(xs)
    if n < 2:
        return None
    m = st.mean(xs)
    se = st.stdev(xs) / n ** 0.5
    h = float(t.ppf(0.5 + conf / 2, n - 1)) * se
    return [round(m - h, 3), round(m + h, 3)]

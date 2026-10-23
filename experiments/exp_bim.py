#!/usr/bin/env python3
"""
BIM experiments for the round-3 review.

2.4 (R3-017) slow-drift rows: drift 0.25, 0.5, 0.75, 1.0%/day (and 1.5, 2.8, 4.0 for
    continuity), 20 seeds each, archived chart parameters (mu0 = 0.00334,
    k = 0.00036, h = 0.00583; N = 2,000 lookups per day, K = 50 categories): share of
    runs alarming within the 14-day window and mean days from onset at a 120-day
    horizon. Drift is also expressed in organic sigma per day (entropy units: the
    organic daily noise of 0.02 bits; JS units: the organic JS standard deviation).
2.5 (R3-020) 200 organic 90-day runs: false-alarm count with an exact 95% interval;
    the 6.15-day mean with a t interval; 200 detection runs at 2.8%/day.
2.7 (R3-018) re-derivation of mu0, k and h at N = 20,000 and 200,000 lookups per day
    (K = 50), by the calibration procedure of calibrate_bim_js_cusum.py, then the
    detection rows at the new parameters.
2.13 (R3-023) Page-Hinkley baseline on the same daily JS series, calibrated by the
    same rule (organic false-alarm-day rate below 5% with at least 90% detection
    at 2.8%/day), then the same drift rows and organic runs.
All data are SYNTHETIC (Zipf BIN-lookup distributions with weekly seasonality).
"""
import math
import os
import random
import sys
from multiprocessing import Pool

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiments._common import write, summ, clopper_pearson, mean_ci, N_PROC  # noqa: E402
from bim.bim import (BaselineIntegrityMonitor, BaselineStat, js_divergence, zipf_distribution,  # noqa: E402
                     zipf_s_for_entropy, sample_categorical_counts, SECONDS_PER_DAY)
from baselines.page_hinkley import PageHinkley  # noqa: E402

K = 50
MU0_ENTROPY = 1.80
AMP = 0.06
ARCH = dict(mu0=0.00334, k=0.00036, h=0.00583)
RATES = [0.25, 0.5, 0.75, 1.0, 1.5, 2.8, 4.0]
SEED_DIST = zipf_distribution(K, zipf_s_for_entropy(K, MU0_ENTROPY))
_S_CACHE = {}


def dist_for_entropy(h):
    return zipf_distribution(K, zipf_s_for_entropy(K, h))


def organic_entropy(day, rng):
    dow = day % 7
    wk = AMP if dow >= 5 else -AMP * 0.4
    return MU0_ENTROPY + wk + rng.gauss(0, 0.02)


def sample(dist, n, rng, nprng):
    if nprng is None:
        return sample_categorical_counts(dist, n, rng)
    c = nprng.multinomial(n, dist)
    a = 0.5
    tot = n + a * len(dist)
    return [(x + a) / tot for x in c]


def run(drift_pct, n_days, seed, mu0, k, h, N=2000, warmup=28, ph=None, use_np=False):
    """Returns (cusum_day_from_onset, ph_day_from_onset). drift_pct=None: organic only
    (day counted from the start, no warm-up)."""
    rng = random.Random(seed)
    nprng = np.random.default_rng(seed) if use_np else None
    bim = BaselineIntegrityMonitor(seed=seed)
    bim.initialize_stat(BaselineStat.BIN_WATCH_ENTROPY, mu0, k, h, 0.0, SEED_DIST)
    ref = bim.week_ref[BaselineStat.BIN_WATCH_ENTROPY]
    phd = PageHinkley(*ph) if ph else None
    if drift_pct is None:
        warmup = 0
    for day in range(warmup):
        obs = sample(dist_for_entropy(organic_entropy(day, rng)), N, rng, nprng)
        x = js_divergence(obs, ref.get(day % 7, SEED_DIST))
        if phd:
            phd.update(x)
        bim.observe_distribution(BaselineStat.BIN_WATCH_ENTROPY, obs, float(day * SECONDS_PER_DAY))
    det = ph_det = None
    dabs = 0.0 if drift_pct is None else (drift_pct / 100.0) * MU0_ENTROPY
    for d in range(n_days):
        day = warmup + d
        seas = organic_entropy(day, rng) - MU0_ENTROPY
        obs = sample(dist_for_entropy(MU0_ENTROPY + seas + (d + 1) * dabs), N, rng, nprng)
        x = js_divergence(obs, ref.get(day % 7, SEED_DIST))
        if phd and ph_det is None and phd.update(x):
            ph_det = d + 1 if drift_pct is not None else d
        a = bim.observe_distribution(BaselineStat.BIN_WATCH_ENTROPY, obs, float(day * SECONDS_PER_DAY))
        if a is not None and det is None:
            det = d + 1 if drift_pct is not None else d
        if det is not None and (phd is None or ph_det is not None):
            break
    return det, ph_det


def organic_js_stats(N, use_np, seeds=10, days=120):
    allj = []
    for s in range(seeds):
        rng = random.Random(s)
        nprng = np.random.default_rng(s) if use_np else None
        bim = BaselineIntegrityMonitor(seed=s)
        bim.initialize_stat(BaselineStat.BIN_WATCH_ENTROPY, 0.0, 0.0, float("inf"), 0.0, SEED_DIST)
        ref = bim.week_ref[BaselineStat.BIN_WATCH_ENTROPY]
        for day in range(days):
            obs = sample(dist_for_entropy(organic_entropy(day, rng)), N, rng, nprng)
            j = js_divergence(obs, ref.get(day % 7, SEED_DIST))
            if day >= 7:
                allj.append(j)
            bim.observe_distribution(BaselineStat.BIN_WATCH_ENTROPY, obs, float(day * SECONDS_PER_DAY))
    m = float(np.mean(allj))
    sd = float(np.std(allj))
    return m, sd


def calibrate(N, use_np):
    """calibrate_bim_js_cusum.py procedure at a given N."""
    mu0, sd = organic_js_stats(N, use_np)
    k = 0.5 * sd
    chosen = None
    grid = []
    for mult in [3, 4, 5, 6, 8, 10, 12, 16, 20]:
        h = mult * sd
        fp_days = 0
        for s in range(20):
            d, _ = run(None, 90, s + 1000, mu0, k, h, N, use_np=use_np)
            if d is not None:
                fp_days += 90 - d
        fp = fp_days / (20 * 90)
        dets = [run(2.8, 14, s + 2000, mu0, k, h, N, use_np=use_np)[0] for s in range(20)]
        dr = sum(1 for x in dets if x is not None) / 20
        grid.append({"h_mult": mult, "fa_day_rate": round(fp, 4), "detect_rate_2.8": dr})
        if chosen is None and fp < 0.05 and dr >= 0.9:
            chosen = (mult, h)
    if chosen is None:
        chosen = (12, 12 * sd)
    return {"N": N, "mu0": mu0, "sd": sd, "k": k, "h": chosen[1], "h_mult": chosen[0], "grid": grid}


def calibrate_ph(mu0, k, h, N=2000):
    """Page-Hinkley: delta = k (same allowance), lambda from the same grid rule."""
    _, sd = organic_js_stats(N, False)
    delta = 0.5 * sd
    chosen = None
    grid = []
    for mult in [3, 4, 5, 6, 8, 10, 12, 16, 20]:
        lam = mult * sd
        fp_days = 0
        for s in range(20):
            _, d = run(None, 90, s + 1000, mu0, k, float("inf"), N, ph=(delta, lam))
            if d is not None:
                fp_days += 90 - d
        fp = fp_days / (20 * 90)
        dets = [run(2.8, 14, s + 2000, mu0, k, float("inf"), N, ph=(delta, lam))[1] for s in range(20)]
        dr = sum(1 for x in dets if x is not None) / 20
        grid.append({"lambda_mult": mult, "fa_day_rate": round(fp, 4), "detect_rate_2.8": dr})
        if chosen is None and fp < 0.05 and dr >= 0.9:
            chosen = (mult, lam)
    if chosen is None:
        chosen = (12, 12 * sd)
    return {"delta": delta, "lambda": chosen[1], "lambda_mult": chosen[0], "grid": grid}


def _rows_job(a):
    rate, seed, mu0, k, h, N, ph, use_np = a
    d14, p14 = run(rate, 14, seed, mu0, k, h, N, ph=ph, use_np=use_np)
    d120, p120 = run(rate, 120, seed, mu0, k, h, N, ph=ph, use_np=use_np)
    return rate, d14, d120, p14, p120


def rows(params, N, use_np, seeds=20, ph=None):
    jobs = [(r, s + 3000, params["mu0"], params["k"], params["h"], N, ph, use_np)
            for r in RATES for s in range(seeds)]
    with Pool(N_PROC) as p:
        res = p.map(_rows_job, jobs)
    out = {}
    for r in RATES:
        rr = [x for x in res if x[0] == r]
        d14 = [x[1] for x in rr]
        d120 = [x[2] for x in rr if x[2] is not None]
        row = {"detected_within_14d": sum(1 for x in d14 if x is not None), "runs": len(rr),
               "detected_within_14d_ci95": clopper_pearson(sum(1 for x in d14 if x is not None), len(rr)),
               "mean_days_120d_horizon": round(float(np.mean(d120)), 2) if d120 else None,
               "detected_120d": len(d120), "days_120d": summ(d120, 2)}
        if ph:
            p14 = [x[3] for x in rr]
            p120 = [x[4] for x in rr if x[4] is not None]
            row["ph_detected_within_14d"] = sum(1 for x in p14 if x is not None)
            row["ph_mean_days_120d_horizon"] = round(float(np.mean(p120)), 2) if p120 else None
            row["ph_detected_120d"] = len(p120)
        out[str(r)] = row
    return out


def _org_job(a):
    s, mu0, k, h, N, ph, use_np = a
    return run(None, 90, s + 5000, mu0, k, h, N, ph=ph, use_np=use_np)


def organic_fa(params, N, use_np, n=200, ph=None):
    with Pool(N_PROC) as p:
        res = p.map(_org_job, [(s, params["mu0"], params["k"], params["h"], N, ph, use_np) for s in range(n)])
    c = sum(1 for d, _ in res if d is not None)
    out = {"runs": n, "runs_with_alarm": c, "rate": round(c / n, 4), "ci95": clopper_pearson(c, n),
           "first_alarm_days": sorted(d for d, _ in res if d is not None)}
    if ph:
        cp = sum(1 for _, d in res if d is not None)
        out["ph_runs_with_alarm"] = cp
        out["ph_ci95"] = clopper_pearson(cp, n)
    return out


def _det_job(a):
    s, mu0, k, h = a
    return run(2.8, 21, s + 3000, mu0, k, h)[0]


def drift_in_sigma(js_sd, N=2000):
    """Drift per day in organic sigma: entropy units (sigma = 0.02 bits) and JS units
    (noise-free JS of the drifted distribution against the organic reference after 7
    days, divided by 7, over the organic JS standard deviation at this N)."""
    out = {}
    for r in RATES:
        dbits = (r / 100.0) * MU0_ENTROPY
        js7 = js_divergence(dist_for_entropy(MU0_ENTROPY + 7 * dbits), SEED_DIST)
        out[str(r)] = {"bits_per_day": round(dbits, 4), "entropy_sigma_per_day": round(dbits / 0.02, 3),
                       "js_week7_noise_free": round(js7, 6), "js_sigma_per_day_avg_first_week": round(js7 / 7 / js_sd, 3)}
    return out


def main():
    out = {"data": "SYNTHETIC: Zipf BIN-lookup distributions, K = 50, weekly step seasonality + Gaussian noise",
           "archived_parameters": ARCH}
    mu0_2k, sd_2k = organic_js_stats(2000, False)
    out["organic_js_N2000"] = {"mean": mu0_2k, "sd": sd_2k}
    out["drift_units"] = drift_in_sigma(sd_2k)
    # 2.4 rows at archived parameters, with Page-Hinkley baseline
    ph = calibrate_ph(ARCH["mu0"], ARCH["k"], ARCH["h"])
    out["page_hinkley_calibration"] = ph
    out["rows_N2000_archived"] = rows(dict(mu0=ARCH["mu0"], k=ARCH["k"], h=ARCH["h"]), 2000, False,
                                      ph=(ph["delta"], ph["lambda"]))
    print("rows N=2000", {r: (v["detected_within_14d"], v["mean_days_120d_horizon"]) for r, v in out["rows_N2000_archived"].items()}, flush=True)
    # 2.5 organic false alarms (200 runs) and detection-day intervals
    out["organic_fa_200_runs_N2000"] = organic_fa(dict(mu0=ARCH["mu0"], k=ARCH["k"], h=ARCH["h"]), 2000, False,
                                                  ph=(ph["delta"], ph["lambda"]))
    with Pool(N_PROC) as p:
        d20 = p.map(_det_job, [(s, ARCH["mu0"], ARCH["k"], ARCH["h"]) for s in range(20)])
        d200 = p.map(_det_job, [(s + 10000, ARCH["mu0"], ARCH["k"], ARCH["h"]) for s in range(200)])
    d20v = [x for x in d20 if x is not None]
    d200v = [x for x in d200 if x is not None]
    out["detection_2.8_20_seeds_archived"] = {"days": d20v, "mean": round(float(np.mean(d20v)), 3),
                                               "ci95_t": mean_ci(d20v)}
    out["detection_2.8_200_seeds"] = {"detected": len(d200v), "mean": round(float(np.mean(d200v)), 3),
                                      "ci95_t": mean_ci(d200v), "summary": summ(d200v, 2)}
    print("FA", out["organic_fa_200_runs_N2000"]["runs_with_alarm"], "det20", out["detection_2.8_20_seeds_archived"], flush=True)
    # 2.7 N re-derivation (numpy multinomial sampler)
    out["rederived"] = {}
    for N in (2000, 20000, 200000):
        cal = calibrate(N, True)
        cal["rows"] = rows(cal, N, True)
        cal["organic_fa_200_runs"] = organic_fa(cal, N, True)
        out["rederived"][str(N)] = cal
        print("N", N, "mu0", cal["mu0"], "k", cal["k"], "h", cal["h"],
              {r: (v["detected_within_14d"], v["mean_days_120d_horizon"]) for r, v in cal["rows"].items()}, flush=True)
    write("bim_rows.json", out)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
2.15 R-12 organic false fires per merchant-day under each message flow (review
R3-004, author fact F2), and the R-11 organic false fires on the same traffic
(feeds 2.14).

Organic only (no attack): zipf profile, 400 merchant identities and 200 BIN
families at 100 authorizations per second, 30% of merchants starting at a
random time in the first hour (new merchants, start of day), 2 hours per run,
10 seeds. Flows: single (approved 0210 is capture), dual_0220 (0220 advice,
lognormal delay with median 120 s), clearing (capture 6 to 30 hours later).
Estimators: censoring_bound (v1.3.0 default), lagged_cohort, same_window (v1.2).
False fires per merchant-day are counted over merchants whose offered rate is
above the 100-per-minute gate; R-11 fires per BIN-day over all families.
"""
import itertools
import os
import sys
from multiprocessing import Pool

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiments._common import write, clopper_pearson, N_PROC  # noqa: E402
from fdce.scenario import OrganicProfile, simulate  # noqa: E402

FLOWS = ["single", "dual_0220", "clearing"]
ESTS = ["censoring_bound", "lagged_cohort", "same_window"]
SEEDS = 10
DUR = 7200.0
PROF = dict(kind="zipf", n_bins=200, n_merchants=400, total_tps=100.0, new_merchant_share=0.3)


def job(a):
    flow, est, seed = a
    r = simulate(None, OrganicProfile(**PROF), seed, DUR, flow,
                 detector_kwargs={"r12_estimator": est}, with_cusum=(est == "censoring_bound"))
    return dict(flow=flow, est=est, seed=seed, r12_fires=r.organic_r12_false_fires,
                r12_merchants=r.n_organic_r12_false_positives, over_gate=r.organic_merchants_over_gate,
                r11_fires=r.organic_r11_false_fires, r11_bins=r.organic_r11_false_bins,
                org=r.n_organic_txn, blocked=r.n_organic_blocked,
                cusum_fa=r.extra.get("cusum_organic_false_alarms"), cusum_bins=r.extra.get("cusum_organic_false_bins"))


def main():
    jobs = [(f, e, 400000 + 7919 * s) for f, e in itertools.product(FLOWS, ESTS) for s in range(SEEDS)]
    with Pool(N_PROC) as p:
        rows = p.map(job, jobs, chunksize=1)
    out = {"design": dict(PROF, duration_s=DUR, seeds=SEEDS, flows=FLOWS, estimators=ESTS,
                          r12_gate_per_min=100.0), "cells": {}}
    for f, e in itertools.product(FLOWS, ESTS):
        v = [r for r in rows if r["flow"] == f and r["est"] == e]
        md = sum(r["over_gate"] for r in v) * DUR / 86400.0
        bd = 200 * len(v) * DUR / 86400.0
        fires = sum(r["r12_fires"] for r in v)
        mer = sum(r["r12_merchants"] for r in v)
        cell = {"runs": len(v), "merchants_over_gate_per_run": v[0]["over_gate"],
                "merchant_days_over_gate": round(md, 3),
                "r12_false_fires": fires, "r12_false_fires_per_merchant_day": round(fires / md, 4) if md else None,
                "r12_merchants_fired": mer,
                "merchant_runs": PROF["n_merchants"] * len(v),
                "r12_merchant_fire_share_all_merchants": round(mer / (PROF["n_merchants"] * len(v)), 5),
                "r12_merchant_fire_ci95_all_merchants": clopper_pearson(mer, PROF["n_merchants"] * len(v)),
                "r11_false_fires": sum(r["r11_fires"] for r in v),
                "r11_false_fires_per_bin_day": round(sum(r["r11_fires"] for r in v) / bd, 5),
                "organic_blocked_share": round(sum(r["blocked"] for r in v) / max(1, sum(r["org"] for r in v)), 6)}
        if e == "censoring_bound":
            cell["cusum_false_alarms"] = sum(r["cusum_fa"] or 0 for r in v)
            cell["cusum_false_alarms_per_bin_day"] = round(cell["cusum_false_alarms"] / bd, 5)
        out["cells"][f"{f}|{e}"] = cell
        print(f, e, {k: cell[k] for k in ("r12_false_fires", "r12_merchants_fired", "r12_false_fires_per_merchant_day",
                                         "r11_false_fires")}, flush=True)
    write("r12_flows_organic.json", out)


if __name__ == "__main__":
    main()

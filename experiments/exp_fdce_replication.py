#!/usr/bin/env python3
"""
2.1 FDCE replication (review R3-002) and 2.13 approval-rate CUSUM baseline (R3-023).

Grid as published: 3 cluster sizes (50, 200, 500 bot merchant identities) x 2
decline mixes (expired_only, mixed) x 5 intensities (per-merchant rate
5 + 10 x intensity = 7 to 15 authorizations per second), 120 s per run,
single-message flow, v1.3.0 detectors. Adversarial grid: decline-spreading mix,
3 cluster sizes x 3 intensities.

Variants, each with independent seeds per cell:
  disjoint      : bots in their own BIN families, legacy organic profile (v1.2 layout)
  shared        : bots in 20 BIN families that also carry organic traffic
                  (zipf organic profile, 100 TPS over 200 families)
  r12_only      : disjoint layout with R-11 disabled, to measure R-12 on its own
  adversarial   : decline-spreading mix, disjoint layout, both rules all run
Reported per variant: cells detected, time to first fire by rule (median, IQR),
bot authorizations admitted before the first block, block rate over the 120 s
run, organic false fires, and the CUSUM baseline's first alarm.
Seeds: 30 per main-grid cell, 20 per adversarial cell.
"""
import itertools
import os
import sys
from multiprocessing import Pool

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiments._common import write, summ, clopper_pearson, N_PROC  # noqa: E402
from fdce.scenario import simulate_fdce_scenario, OrganicProfile  # noqa: E402

CLUSTERS = [50, 200, 500]
MIXES = ["expired_only", "mixed"]
INTENS = [0.2, 0.4, 0.6, 0.8, 1.0]
ADV_INTENS = [0.2, 0.6, 1.0]
SEEDS_MAIN = 30
SEEDS_ADV = 20
R11_OFF = {"r11c_delta": 9.0}


def job(args):
    variant, cluster, mix, intensity, seed = args
    kw = dict(duration_s=120.0, flow="single", with_cusum=True)
    if variant == "shared":
        r = simulate_fdce_scenario(cluster, mix, intensity, seed, bins="shared",
                                   organic=OrganicProfile(kind="zipf", n_bins=200, total_tps=100.0),
                                   **kw)
    elif variant == "r12_only":
        r = simulate_fdce_scenario(cluster, mix, intensity, seed, detector_kwargs=R11_OFF, **kw)
    else:
        r = simulate_fdce_scenario(cluster, mix, intensity, seed, **kw)
    rc = r
    return dict(variant=variant, cluster=cluster, mix=mix, intensity=intensity, seed=seed,
                det=r.detection_latency_s, rule=r.triggered_rule, r11=r.first_r11_s, r12=r.first_r12_s,
                adm_pre=r.n_bot_admitted_before_first_block, adm=r.n_bot_admitted,
                block=r.block_rate, bot=r.n_bot_txn, org_r11=r.organic_r11_false_fires,
                org_r12=r.organic_r12_false_fires, org_blk=r.n_organic_blocked, org=r.n_organic_txn,
                cusum=rc.extra.get("cusum_first_alarm_s"), cusum_org=rc.extra.get("cusum_organic_false_alarms"))


def aggregate(rows):
    n = len(rows)
    det = [r for r in rows if r["det"] is not None]
    rules = {}
    for r in det:
        rules[r["rule"]] = rules.get(r["rule"], 0) + 1
    return {
        "runs": n, "detected": len(det), "detected_ci95": clopper_pearson(len(det), n),
        "first_rule_counts": rules,
        "latency_any_s": summ([r["det"] for r in det]),
        "latency_r11_s": summ([r["r11"] for r in rows]),
        "latency_r12_s": summ([r["r12"] for r in rows]),
        "bot_admitted_before_first_block": summ([r["adm_pre"] for r in rows], 1),
        "bot_admitted_total": summ([r["adm"] for r in rows], 1),
        "block_rate_120s": summ([r["block"] for r in rows], 4),
        "organic_r11_false_fires_total": sum(r["org_r11"] for r in rows),
        "organic_r12_false_fires_total": sum(r["org_r12"] for r in rows),
        "organic_blocked_share": round(sum(r["org_blk"] for r in rows) / max(1, sum(r["org"] for r in rows)), 6),
        "cusum_detected": sum(1 for r in rows if r["cusum"] is not None),
        "cusum_latency_s": summ([r["cusum"] for r in rows]),
        "cusum_organic_false_alarms_total": sum(r["cusum_org"] or 0 for r in rows),
    }


def main():
    jobs = []
    for variant in ("disjoint", "shared", "r12_only"):
        for c, m, i in itertools.product(CLUSTERS, MIXES, INTENS):
            for k in range(SEEDS_MAIN):
                jobs.append((variant, c, m, i, 100000 + 1000 * CLUSTERS.index(c) + 100 * MIXES.index(m)
                             + 10 * INTENS.index(i) + k * 7919))
    for c, i in itertools.product(CLUSTERS, ADV_INTENS):
        for k in range(SEEDS_ADV):
            jobs.append(("adversarial", c, "spread", i, 200000 + 1000 * CLUSTERS.index(c)
                         + 10 * ADV_INTENS.index(i) + k * 7919))
    with Pool(N_PROC) as p:
        rows = p.map(job, jobs, chunksize=4)
    out = {"design": {"clusters": CLUSTERS, "mixes": MIXES, "intensities": INTENS,
                      "per_merchant_rate_tps": {str(i): 5.0 + 10.0 * i for i in INTENS},
                      "duration_s": 120.0, "flow": "single", "seeds_main": SEEDS_MAIN,
                      "seeds_adversarial": SEEDS_ADV, "r12_gate_per_min": 100.0},
           "variants": {}, "cells": {}}
    for variant in ("disjoint", "shared", "r12_only", "adversarial"):
        vr = [r for r in rows if r["variant"] == variant]
        out["variants"][variant] = aggregate(vr)
        cells = {}
        for r in vr:
            cells.setdefault(f'{r["cluster"]}|{r["mix"]}|{r["intensity"]}', []).append(r)
        out["cells"][variant] = {k: aggregate(v) for k, v in cells.items()}
        print(variant, {k: out["variants"][variant][k] for k in ("runs", "detected", "first_rule_counts")},
              "lat", out["variants"][variant]["latency_any_s"], flush=True)
    write("fdce_replication.json", out)


if __name__ == "__main__":
    main()

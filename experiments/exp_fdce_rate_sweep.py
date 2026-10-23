#!/usr/bin/env python3
"""
2.2 FDCE per-merchant rate sweep across the R-12 gate (review R3-001).

Fixed total attack load L (authorizations per second) split over L / r bot
merchant identities, each at r per second, for r from 0.5 to 15 (the R-12 gate
is 100 per minute, 1.67 per second). Bots use 20 BIN families that also carry
organic traffic (zipf organic profile, 100 TPS over 200 families). Crossed with
Poisson or regular spacing, three decline mixes (expired_only, mixed, spread)
and two loads (L = 600/s, heavy; L = 30/s, diluted below the organic volume of
the attacked families), 20 seeds per cell, 300 s per run, single-message flow.
Reported per cell: detection probability with an exact 95% interval, time to
first fire by rule, bot authorizations admitted before the first block and in
total, and the CUSUM baseline's detection.
"""
import itertools
import os
import sys
from multiprocessing import Pool

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiments._common import write, summ, clopper_pearson, N_PROC  # noqa: E402
from fdce.scenario import AttackProfile, OrganicProfile, simulate  # noqa: E402

RATES = [0.5, 1.0, 1.5, 2.0, 3.0, 5.0, 10.0, 15.0]
SPACINGS = ["poisson", "regular"]
MIXES = ["expired_only", "mixed", "spread"]
LOADS = [600.0, 30.0]
SEEDS = 20
DURATION = 300.0


def job(a):
    load, rate, spacing, mix, seed = a
    n_m = max(1, int(round(load / rate)))
    ap = AttackProfile(n_merchants=n_m, rate_per_merchant=rate, card_mix=mix, spacing=spacing,
                       bins="shared", n_bins=20)
    org = OrganicProfile(kind="zipf", n_bins=200, total_tps=100.0)
    r = simulate(ap, org, seed, DURATION, "single", with_cusum=True)
    return dict(load=load, rate=rate, spacing=spacing, mix=mix, seed=seed, n_merchants=n_m,
                det=r.detection_latency_s, rule=r.triggered_rule, r11=r.first_r11_s, r12=r.first_r12_s,
                adm_pre=r.n_bot_admitted_before_first_block, adm=r.n_bot_admitted, bot=r.n_bot_txn,
                block=r.block_rate, org_r11=r.organic_r11_false_fires, org_r12=r.organic_r12_false_fires,
                cusum=r.extra.get("cusum_first_alarm_s"))


def main():
    jobs = [(L, r, sp, m, 300000 + 7919 * k + 101 * RATES.index(r) + 13 * MIXES.index(m)
             + 3 * SPACINGS.index(sp) + 1000003 * LOADS.index(L))
            for L, r, sp, m in itertools.product(LOADS, RATES, SPACINGS, MIXES) for k in range(SEEDS)]
    with Pool(N_PROC) as p:
        rows = p.map(job, jobs, chunksize=2)
    cells = {}
    for r in rows:
        cells.setdefault((r["load"], r["rate"], r["spacing"], r["mix"]), []).append(r)
    out = {"design": {"rates_per_s": RATES, "spacings": SPACINGS, "mixes": MIXES, "loads_per_s": LOADS,
                      "seeds": SEEDS, "duration_s": DURATION, "attacked_families": 20,
                      "organic": "zipf, 100 TPS over 200 families", "r12_gate_per_min": 100.0},
           "cells": []}
    for (L, rate, sp, mix), v in sorted(cells.items()):
        det = [x for x in v if x["det"] is not None]
        r12 = [x for x in v if x["r12"] is not None]
        r11 = [x for x in v if x["r11"] is not None]
        cus = [x for x in v if x["cusum"] is not None]
        out["cells"].append({
            "load": L, "rate_per_s": rate, "rate_per_min": rate * 60, "spacing": sp, "mix": mix,
            "n_merchants": v[0]["n_merchants"], "runs": len(v),
            "detected": len(det), "detected_ci95": clopper_pearson(len(det), len(v)),
            "r11_fired": len(r11), "r12_fired": len(r12),
            "latency_any_s": summ([x["det"] for x in det]),
            "latency_r11_s": summ([x["r11"] for x in r11]),
            "latency_r12_s": summ([x["r12"] for x in r12]),
            "admitted_before_first_block": summ([x["adm_pre"] for x in v], 1),
            "admitted_total": summ([x["adm"] for x in v], 1),
            "bot_total": summ([x["bot"] for x in v], 1),
            "organic_r11_false_fires": sum(x["org_r11"] for x in v),
            "organic_r12_false_fires": sum(x["org_r12"] for x in v),
            "cusum_detected": len(cus), "cusum_latency_s": summ([x["cusum"] for x in cus]),
        })
        c = out["cells"][-1]
        print(L, rate, sp, mix, "det", c["detected"], "r11", c["r11_fired"], "r12", c["r12_fired"],
              "cusum", c["cusum_detected"], flush=True)
    write("fdce_rate_sweep.json", out)


if __name__ == "__main__":
    main()

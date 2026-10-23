#!/usr/bin/env python3
"""
2.2 / 2.11 supplement: the dilution boundary of R-11 (review R3-001, R3-022).

The rate sweep showed that per-merchant pacing does not evade the family-level
R-11 statistic when the attack is concentrated in 20 families. This driver
spreads the attack over ALL 200 organic families in proportion to their organic
volume, so every family carries the same attack share x of its responses, and
paces each bot merchant identity at 1.5 per second (under the R-12 gate).
x in {0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6}; organic zipf profile at 100 TPS;
expired-only declines; 300 s; 10 seeds; single-message flow. Reported: R-11,
R-12 and approval-rate CUSUM detection, and bot authorizations admitted.
"""
import os
import sys
from multiprocessing import Pool

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiments._common import write, summ, clopper_pearson, N_PROC  # noqa: E402
from fdce.scenario import AttackProfile, OrganicProfile, simulate  # noqa: E402

SHARES = [0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6]
SEEDS = 10
ORG_TPS = 100.0
DUR = 300.0
RATE = 1.5


def job(a):
    x, seed = a
    load = ORG_TPS * x / (1.0 - x)
    ap = AttackProfile(n_merchants=max(1, int(round(load / RATE))), rate_per_merchant=RATE,
                       card_mix="expired_only", spacing="regular", bins="proportional")
    r = simulate(ap, OrganicProfile(kind="zipf", n_bins=200, total_tps=ORG_TPS), seed, DUR, "single",
                 with_cusum=True)
    return dict(x=x, seed=seed, load=load, det=r.detection_latency_s, r11=r.first_r11_s, r12=r.first_r12_s,
                cusum=r.extra.get("cusum_first_alarm_s"), adm=r.n_bot_admitted, bot=r.n_bot_txn,
                org_blk=r.n_organic_blocked, org=r.n_organic_txn,
                org_r11=r.organic_r11_false_fires, cus_org=r.extra.get("cusum_organic_false_alarms"))


def main():
    jobs = [(x, 700000 + 7919 * k + int(1000 * x)) for x in SHARES for k in range(SEEDS)]
    with Pool(N_PROC) as p:
        rows = p.map(job, jobs, chunksize=1)
    out = {"design": {"attack_share_per_family": SHARES, "seeds": SEEDS, "organic_tps": ORG_TPS,
                      "duration_s": DUR, "per_merchant_rate_per_s": RATE, "spacing": "regular",
                      "allocation": "proportional to organic family volume, all 200 families"},
           "cells": []}
    for x in SHARES:
        v = [r for r in rows if r["x"] == x]
        c = {"attack_share": x, "attack_load_per_s": round(v[0]["load"], 2), "runs": len(v),
             "r11_detected": sum(1 for r in v if r["r11"] is not None),
             "r11_ci95": clopper_pearson(sum(1 for r in v if r["r11"] is not None), len(v)),
             "r12_detected": sum(1 for r in v if r["r12"] is not None),
             "cusum_detected": sum(1 for r in v if r["cusum"] is not None),
             "cusum_ci95": clopper_pearson(sum(1 for r in v if r["cusum"] is not None), len(v)),
             "r11_latency_s": summ([r["r11"] for r in v if r["r11"] is not None]),
             "cusum_latency_s": summ([r["cusum"] for r in v if r["cusum"] is not None]),
             "bot_admitted_share": round(sum(r["adm"] for r in v) / max(1, sum(r["bot"] for r in v)), 4),
             "organic_blocked_share": round(sum(r["org_blk"] for r in v) / max(1, sum(r["org"] for r in v)), 4)}
        out["cells"].append(c)
        print(c, flush=True)
    write("fdce_dilution.json", out)


if __name__ == "__main__":
    main()

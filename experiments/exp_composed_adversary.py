#!/usr/bin/env python3
"""
2.11 Composed adaptive adversary (review R3-022). One adversary combining the
evasions the paper states separately, run through the v1.3.0 detectors:

  FDCE part: bot merchant identities regularly paced at 1.5 authorizations per
    second (90 per minute, under the R-12 gate of 100), in 20 BIN families that
    also carry organic traffic, at a total load diluted to 30 per second (organic
    100 per second over 200 families). Three decline variants: spread watched
    codes, 05/51 substitution, and authorize-then-reverse (approved, reversed
    10 s later). 600 s per run, 10 seeds. Single-message and dual_0220 flows.
  STC view: the attacked families' TCS (str, dst) at the end of the run, from the
    reference STC fed the same stream.
  CLCS: layer signals held at 0.12 each (W = 0.12 < 0.136) with the attacked
    families' measured TCS: does CLCS activate (multiplicative, beta = 4.5)?
  BIM: poisoning at 0.25%/day, from bim_rows.json (rows at archived parameters).
Reported: which mechanism fires, and when.
"""
import itertools
import os
import sys
from multiprocessing import Pool

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiments._common import write, summ, N_PROC  # noqa: E402
from fdce.scenario import AttackProfile, OrganicProfile, organic_events, attack_events, run_stream, make_detector  # noqa: E402
from baselines.approval_cusum import BinDeclineCUSUM  # noqa: E402
from stc.stc import SemanticTransactionCorrelator, PaymentEvent, EventType  # noqa: E402

DUR = 600.0
SEEDS = 10
VARIANTS = {
    "spread": dict(card_mix="spread"),
    "substitution_05_51": dict(card_mix="substitution"),
    "authorize_then_reverse": dict(card_mix="expired_only", p_approve=1.0, reverse_after_s=10.0),
}
FLOWS = ["single", "dual_0220"]


def job(a):
    variant, flow, seed = a
    rng = np.random.default_rng(seed)
    org = OrganicProfile(kind="zipf", n_bins=200, total_tps=100.0)
    oev, obins, omer, info = organic_events(org, flow, DUR, rng)
    ap = AttackProfile(n_merchants=20, rate_per_merchant=1.5, spacing="regular", bins="shared", n_bins=20,
                       **VARIANTS[variant])
    aev, bb, bm = attack_events(ap, DUR, rng, obins, omer, info["bin_weights"])
    events = list(oev) + list(aev)
    det = make_detector(flow, baseline_init=info["baseline"])
    cus = BinDeclineCUSUM(baseline=info["baseline"])
    r = run_stream(list(events), det, 0.0, bb, bm, info["merchant_rate_tps"], cus)
    # STC over the same stream (no blocking)
    stc = SemanticTransactionCorrelator(window_s=3600.0, flow=flow, rho_star=0.50,
                                        decline_baseline=info["baseline"])
    events.sort(key=lambda e: e[0])
    for ts, kind, m, b, tid, code, bot in events:
        kw = dict(bin_prefix=b, terminal_id=m, source_ip="ip-" + tid, stan=tid, amount=25.0)
        if kind == "auth":
            req = EventType.ISO_0200 if flow == "single" else EventType.ISO_0100
            rsp = EventType.ISO_0210 if flow == "single" else EventType.ISO_0110
            stc.ingest_event(PaymentEvent(tid + "a", req, timestamp=ts, **kw))
            stc.ingest_event(PaymentEvent(tid + "b", rsp, timestamp=ts + 0.3, response_code=code, **kw))
        elif kind == "comp":
            stc.ingest_event(PaymentEvent(tid + "c", EventType.ISO_0220, timestamp=ts, **kw))
        elif kind == "rev":
            stc.ingest_event(PaymentEvent(tid + "r", EventType.ISO_0400, timestamp=ts, **kw))
    tcs = [stc.compute_tcs(b, DUR) for b in bb]
    tmin = min(x.tcs for x in tcs)
    W = 0.12
    clcs_max = min(1.0, W * (1 + 4.5 * (1 - tmin)))
    return dict(variant=variant, flow=flow, seed=seed, det=r.detection_latency_s, rule=r.triggered_rule,
                r11=r.first_r11_s, r12=r.first_r12_s, adm=r.n_bot_admitted, bot=r.n_bot_txn,
                cusum=r.extra.get("cusum_first_alarm_s"), tcs_min=tmin,
                tcs_str_min=min(x.tcs_str for x in tcs), tcs_dst_min=min(x.tcs_dst for x in tcs),
                stc_alarm=tmin < 0.50, clcs=clcs_max, clcs_activates=clcs_max > 0.75,
                attack_share=None)


def main():
    jobs = [(v, f, 600000 + 7919 * s) for v, f in itertools.product(VARIANTS, FLOWS) for s in range(SEEDS)]
    with Pool(N_PROC) as p:
        rows = p.map(job, jobs, chunksize=1)
    import json
    bim = None
    bp = os.path.join(os.environ.get("RESULTS_DIR", ""), "bim_rows.json")
    if os.path.exists(bp):
        bim = json.load(open(bp))["rows_N2000_archived"].get("0.25")
    out = {"design": {"duration_s": DUR, "seeds": SEEDS, "per_merchant_rate_per_s": 1.5, "spacing": "regular",
                      "bot_merchants": 20, "attack_load_per_s": 30.0, "attacked_families": 20,
                      "organic": "zipf, 100 TPS over 200 families", "layer_signals_held": 0.12},
           "bim_0.25pct_per_day_row": bim, "cells": {}}
    for v, f in itertools.product(VARIANTS, FLOWS):
        rr = [r for r in rows if r["variant"] == v and r["flow"] == f]
        out["cells"][f"{v}|{f}"] = {
            "runs": len(rr), "fdce_detected": sum(1 for r in rr if r["det"] is not None),
            "r11_fired": sum(1 for r in rr if r["r11"] is not None),
            "r12_fired": sum(1 for r in rr if r["r12"] is not None),
            "latency_s": summ([r["det"] for r in rr if r["det"] is not None]),
            "cusum_fired": sum(1 for r in rr if r["cusum"] is not None),
            "cusum_latency_s": summ([r["cusum"] for r in rr if r["cusum"] is not None]),
            "bot_admitted": summ([r["adm"] for r in rr], 0), "bot_offered": summ([r["bot"] for r in rr], 0),
            "stc_alarm_runs": sum(1 for r in rr if r["stc_alarm"]),
            "tcs_min": summ([r["tcs_min"] for r in rr], 4), "tcs_str_min": summ([r["tcs_str_min"] for r in rr], 4),
            "tcs_dst_min": summ([r["tcs_dst_min"] for r in rr], 4),
            "clcs_activates_runs": sum(1 for r in rr if r["clcs_activates"]),
            "clcs_max": summ([r["clcs"] for r in rr], 4)}
        print(v, f, out["cells"][f"{v}|{f}"], flush=True)
    write("composed_adversary.json", out)


if __name__ == "__main__":
    main()

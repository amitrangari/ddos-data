#!/usr/bin/env python3
"""
2.14 Organic false-alarm population (review R3-021): TCS and CLCS on organic
traffic over a Zipf population of BIN families.

Organic only, zipf profile (200 BIN families, 400 merchants, 50 authorizations
per second, dual_0220 flow), 6 hours per run, 5 seeds. Every authorization is
fed to the reference STC as 0100 / 0110 (and 0220 or 0400 when captured or
reversed). At the end of each hour, TCS(b, W = 3600 s) is computed for every
family; CLCS is then evaluated for each family-hour with organic layer signals
drawn from the D0-b organic distributions (s1, s2, s3, s5 ~ Beta(2, 30),
s4 ~ Beta(6, 34)), beta = 4.5, theta = 0.75. Reported: the distribution of
organic TCS by family size, the number of family-hours below the STC alarm
threshold 0.50, and CLCS false activations per family-day. R-11 and R-12
organic false fires per day come from exp_r12_flows.py.
"""
import os
import sys
from multiprocessing import Pool

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiments._common import write, summ, clopper_pearson, N_PROC  # noqa: E402
from fdce.scenario import OrganicProfile, organic_events  # noqa: E402
from stc.stc import SemanticTransactionCorrelator, PaymentEvent, EventType  # noqa: E402

HOURS = 6
SEEDS = 5
W8 = np.array([0.20, 0.25, 0.20, 0.20, 0.15])


def job(seed):
    rng = np.random.default_rng(seed)
    prof = OrganicProfile(kind="zipf", n_bins=200, n_merchants=400, total_tps=50.0)
    ev, bins, merchants, info = organic_events(prof, "dual_0220", HOURS * 3600.0, rng)
    ev.sort(key=lambda e: e[0])
    stc = SemanticTransactionCorrelator(window_s=3600.0, flow="dual_0220", rho_star=0.50,
                                        decline_baseline=info["baseline"])
    rows = []
    next_eval = 3600.0
    for ts, kind, m, b, tid, code, bot in ev:
        while ts >= next_eval:
            for fam, r in stc.compute_tcs_all(next_eval).items():
                rows.append((next_eval, fam, r.tcs, r.tcs_str, r.tcs_dst, r.total_sequences))
            next_eval += 3600.0
        kw = dict(bin_prefix=b, terminal_id=m, source_ip="ip-" + tid, stan=tid, amount=25.0)
        if kind == "auth":
            stc.ingest_event(PaymentEvent(tid + "a", EventType.ISO_0100, timestamp=ts, **kw))
            stc.ingest_event(PaymentEvent(tid + "b", EventType.ISO_0110, timestamp=ts + 0.3,
                                          response_code=code, **kw))
        elif kind == "comp":
            stc.ingest_event(PaymentEvent(tid + "c", EventType.ISO_0220, timestamp=ts, **kw))
        elif kind == "rev":
            stc.ingest_event(PaymentEvent(tid + "r", EventType.ISO_0400, timestamp=ts, **kw))
    for fam, r in stc.compute_tcs_all(HOURS * 3600.0).items():
        rows.append((HOURS * 3600.0, fam, r.tcs, r.tcs_str, r.tcs_dst, r.total_sequences))
    wb = dict(zip(bins, info["bin_weights"]))
    return [(seed, t, f, tcs, ts_, td, n, wb.get(f, 0.0)) for t, f, tcs, ts_, td, n in rows]


def main():
    with Pool(min(N_PROC, SEEDS)) as p:
        res = p.map(job, [500000 + 7919 * s for s in range(SEEDS)])
    rows = [r for rr in res for r in rr if r[1] >= 3600.0 * 2]   # skip the first hour (warm-up)
    rng = np.random.default_rng(42)
    n = len(rows)
    S = np.column_stack([rng.beta(2, 30, n), rng.beta(2, 30, n), rng.beta(2, 30, n),
                         rng.beta(6, 34, n), rng.beta(2, 30, n)])
    T = np.array([r[3] for r in rows])
    Wv = S @ W8
    cl = np.minimum(1.0, Wv * (1 + 4.5 * (1 - T)))
    act = int((cl > 0.75).sum())
    fam_days = n / 24.0
    sizes = np.array([r[6] for r in rows])
    out = {"design": {"hours": HOURS, "seeds": SEEDS, "families": 200, "tps": 50.0, "flow": "dual_0220",
                      "first_hour_excluded": True},
           "family_hours": n,
           "tcs": summ(list(T), 4), "tcs_str": summ([r[4] for r in rows], 4), "tcs_dst": summ([r[5] for r in rows], 4),
           "tcs_small_families_lt100_seq": summ([r[3] for r in rows if r[6] < 100], 4),
           "family_hours_tcs_below_0.50": int((T < 0.50).sum()),
           "family_hours_tcs_below_0.50_ci95": clopper_pearson(int((T < 0.50).sum()), n),
           "clcs_false_activations": act, "clcs_false_activations_per_family_day": round(act / fam_days, 5),
           "clcs_false_activation_ci95_per_family_hour": clopper_pearson(act, n),
           "resolved_sequences_per_family_hour": summ(list(sizes), 1)}
    print({k: v for k, v in out.items() if k != "design"})
    write("organic_population.json", out)


if __name__ == "__main__":
    main()

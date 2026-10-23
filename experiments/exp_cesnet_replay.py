#!/usr/bin/env python3
"""
2.6 BIM on real data (review R3-016): replay the shipped JS-CUSUM with its
week-aligned reference on the 357 daily service-mix distributions of
CESNET-TLS-Year22 (Zenodo doi:10.5281/zenodo.10608607, CC-BY-4.0), the data the
package already uses in calibrate_drift_from_real_data.py. Needs the external
data under $DDOS_RAW_DATA_ROOT/15-drift-cesnet/tls_stats.

The real data carry no poisoning, so every alarm is a false alarm. Each day is
one observation: the day's flow-count distribution over the union of services
(K = 180 after the union), Laplace-smoothed like the simulator. After an alarm
the monitor's placeholder peer rule decides (rollback resets the chart; it
always returned POISONING in the review), so alarms can recur.

Parameter sets:
  P1 archived simulator parameters (mu0 = 0.00334, k = 0.00036, h = 0.00583; N = 2,000, K = 50)
  P2 re-derived for the CESNET N and K by the simulator calibration procedure
     (Zipf at CESNET's mean entropy, K = 180, N = median daily flow count)
  P3 calibrated on the first 8 weeks of CESNET itself (mu0 = mean JS, k = 0.5 sd,
     h = smallest multiple of sd in {3,...,20} with no alarm in those weeks),
     then applied to the remaining weeks (out-of-sample)
Also reported: the organic JS series against the week-aligned reference (mean,
sd, quantiles) and, in the same unit, the week-over-week variation, plus the
Page-Hinkley baseline with P3-style calibration.
"""
import glob
import json
import math
import os
import random
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiments._common import write, summ  # noqa: E402
from experiments.exp_bim import calibrate as sim_calibrate  # noqa: E402
import experiments.exp_bim as XB  # noqa: E402
from bim.bim import (BaselineIntegrityMonitor, BaselineStat, js_divergence, shannon_entropy_bits,  # noqa: E402
                     zipf_distribution, zipf_s_for_entropy, SECONDS_PER_DAY)
from baselines.page_hinkley import PageHinkley  # noqa: E402

ROOT = os.environ.get("DDOS_RAW_DATA_ROOT", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "raw-data"))
STATS = os.path.join(ROOT, "15-drift-cesnet", "tls_stats")


def load():
    files = sorted(glob.glob(os.path.join(STATS, "stats-*.json")))
    days, maps = [], []
    for f in files:
        j = json.load(open(f))
        a = j.get("apps", {})
        if a:
            days.append(os.path.basename(f)[6:14])
            maps.append(a)
    apps = sorted({k for m in maps for k in m})
    idx = {a: i for i, a in enumerate(apps)}
    C = np.zeros((len(maps), len(apps)))
    for r, m in enumerate(maps):
        for a, c in m.items():
            C[r, idx[a]] = c
    return days, apps, C


def smooth(c):
    a = 0.5
    return list((c + a) / (c.sum() + a * len(c)))


def replay(P, mu0, k, h, start=0, ph=None):
    seed = P[start:start + 7].mean(axis=0)
    seed = list(seed / seed.sum())
    bim = BaselineIntegrityMonitor()
    bim.initialize_stat(BaselineStat.BIN_WATCH_ENTROPY, mu0, k, h, 0.0, seed)
    ref = bim.week_ref[BaselineStat.BIN_WATCH_ENTROPY]
    alarms, js = [], []
    phd = PageHinkley(*ph) if ph else None
    ph_alarms = []
    for t in range(start, len(P)):
        d = t - start
        x = js_divergence(P[t], ref.get(d % 7, seed))
        js.append(x)
        if phd and phd.update(x):
            ph_alarms.append(t)
            phd = PageHinkley(*ph)          # restart after an alarm
        a = bim.observe_distribution(BaselineStat.BIN_WATCH_ENTROPY, P[t], float(d * SECONDS_PER_DAY))
        if a is not None:
            alarms.append(t)
    return alarms, js, ph_alarms


def main():
    days, apps, C = load()
    n, K = C.shape
    N_daily = C.sum(axis=1)
    P = [smooth(C[i]) for i in range(n)]
    P = np.array(P)
    ent = [shannon_entropy_bits(list(p)) for p in P]
    out = {"dataset": "CESNET-TLS-Year22 (doi:10.5281/zenodo.10608607), daily service mix",
           "n_days": n, "K_services": K, "daily_flows": summ(list(N_daily), 0),
           "entropy_bits": summ(ent, 4), "date_span": [days[0], days[-1]]}
    # P1
    a1, js1, _ = replay(P, 0.00334, 0.00036, 0.00583)
    out["P1_archived"] = {"alarms": len(a1), "alarm_days": [days[i] for i in a1][:40],
                          "js_vs_week_ref": summ(js1[7:], 5)}
    # week-over-week variation in JS units, and organic sigma
    wow = [js_divergence(list(P[t]), list(P[t - 7])) for t in range(7, n)]
    out["week_over_week_js"] = summ(wow, 5)
    # P2: simulator re-derivation at CESNET N and K
    XB.K = K
    XB.MU0_ENTROPY = float(np.mean(ent))
    XB.SEED_DIST = zipf_distribution(K, zipf_s_for_entropy(K, XB.MU0_ENTROPY))
    Nmed = int(np.median(N_daily))
    cal = sim_calibrate(Nmed, True)
    a2, _, _ = replay(P, cal["mu0"], cal["k"], cal["h"])
    out["P2_simulator_rederived"] = {"N": Nmed, "K": K, "mu0": cal["mu0"], "sd": cal["sd"], "k": cal["k"],
                                     "h": cal["h"], "alarms": len(a2), "alarm_days": [days[i] for i in a2][:40]}
    # P3: calibrate on first 8 weeks, test on the rest
    train = 56
    _, jtr, _ = replay(P[:train], 0.0, 0.0, float("inf"))
    jtr = jtr[7:]
    mu0, sd = float(np.mean(jtr)), float(np.std(jtr))
    k = 0.5 * sd
    chosen = None
    for mult in [3, 4, 5, 6, 8, 10, 12, 16, 20, 30, 50]:
        al, _, _ = replay(P[:train], mu0, k, mult * sd)
        if not al:
            chosen = mult
            break
    h = (chosen or 50) * sd
    a3, js3, _ = replay(P, mu0, k, h)
    test_alarms = [i for i in a3 if i >= train]
    ph = (0.5 * sd, h)
    _, _, pha = replay(P, mu0, k, float("inf"), ph=ph)
    out["P3_cesnet_calibrated"] = {"train_days": train, "mu0": mu0, "sd": sd, "k": k, "h": h,
                                   "h_mult": chosen, "alarms_total": len(a3),
                                   "alarms_test_period": len(test_alarms),
                                   "test_days": n - train,
                                   "alarm_days": [days[i] for i in a3][:60],
                                   "page_hinkley_alarms": len(pha),
                                   "page_hinkley_alarms_test": len([i for i in pha if i >= train])}
    out["units_note"] = ("drift in JS against the week-aligned reference; organic sigma = sd of that "
                         "series in the training weeks (P3)")
    print(json.dumps({k: v for k, v in out.items() if k.startswith("P") or k in ("n_days", "K_services")}, default=float)[:2000])
    write("bim_cesnet_replay.json", out)


if __name__ == "__main__":
    main()

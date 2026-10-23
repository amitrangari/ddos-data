#!/usr/bin/env python3
"""
calibrate_r11_multilook.py (v1.3.0, review R3-003, editorial call E3)

Calibrates R-11 for repeated looks. R-11 is evaluated after every authorization
response, so the relevant error rate is the share of BIN-days on which the
statistic EVER exceeds the threshold, not a per-window rate.

Population: SYNTHETIC organic traffic from fdce.scenario's "zipf" profile (Zipf
BIN volumes, per-BIN decline-rate heterogeneity, an assumed decline-code mix in
which 05 and 51 dominate), 1,000 BIN families at 300 authorizations per second,
24-hour days, several seeds. For every BIN-day and response floor the script
records the maximum of each statistic over all looks; the false-alarm rate at a
threshold is the share of eligible BIN-days (at least one look with the floor
met) whose maximum exceeds it.

Statistics:
  (a) watched_share:   share of all responses in 60 s carrying 14, 54, 57 or 82
  (c) baseline_excess: decline share in 60 s (code 91 excluded) minus the BIN's
                       long-run decline share (EWMA, warmed up for 2 h)

Baseline (R3-023): the per-BIN approval-rate CUSUM of baselines/approval_cusum.py
(k = 0.25) is scanned on the same days; its decision interval h is the smallest
grid value with the same per-BIN-day false-alarm target.

Selection: for the floor of 20 responses, the smallest threshold on a 0.05 grid
whose per-BIN-day false-alarm rate is at most TARGET_PER_BIN_DAY.

Stress streams (validation, not used for selection), each one hour, 5 seeds:
  S1 organic BIN family dominated by 05/51 declines (decline rate 40%)
  S2 recurring-billing run with code-54 retries (30% and 60% expired renewals)
  S3 issuer outage: every response code 91 for 10 minutes
  S4 substitution adversary: bots whose declines are 05/51, in shared families
Output: R11_MULTILOOK_CALIBRATION.json (override with R11_CAL_OUT).
"""
import json
import os
import sys
from collections import deque

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fdce.scenario import OrganicProfile, ORGANIC_DECLINE_MIX, _zipf_weights  # noqa: E402
from fdce.fdce import DECLINE_CODES_WATCHED, R11C_EXCLUDED  # noqa: E402

SEEDS = [11, 12, 13, 14]
N_BINS = 1000
TOTAL_TPS = 300.0
DAY = 86400.0
WINDOW = 60.0
FLOORS = [10, 20, 30, 50]
GRID = [round(x, 2) for x in np.arange(0.05, 0.96, 0.05)]
H_GRID = [2.0, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0, 12.0, 15.0, 20.0]
CUSUM_K = 0.25
TARGET_PER_BIN_DAY = 1e-3
WARMUP = 7200.0
ALPHA = 1.0 / 5000.0
PRIOR = 0.12


def organic_day(seed):
    rng = np.random.default_rng(seed)
    prof = OrganicProfile(kind="zipf", n_bins=N_BINS, total_tps=TOTAL_TPS)
    wb = _zipf_weights(N_BINS, prof.zipf_bins)
    base = np.array(list(ORGANIC_DECLINE_MIX.values()))
    codes = list(ORGANIC_DECLINE_MIX.keys())
    dec_rate = rng.beta(*prof.decline_rate_beta, size=N_BINS)
    mixes = rng.dirichlet(prof.mix_concentration * base, size=N_BINS)
    n = int(rng.poisson(TOTAL_TPS * DAY))
    ts = np.sort(rng.uniform(0, DAY, n))
    bi = rng.choice(N_BINS, size=n, p=wb)
    declined = rng.random(n) < dec_rate[bi]
    cum = np.cumsum(mixes, axis=1)
    ci = np.minimum((rng.random(n)[:, None] > cum[bi]).sum(axis=1), len(codes) - 1)
    watched_codes = np.array([c in DECLINE_CODES_WATCHED for c in codes])
    excl = np.array([c in R11C_EXCLUDED for c in codes])
    w = declined & watched_codes[ci]
    d = declined & ~excl[ci]
    return ts, bi, w.astype(np.int8), d.astype(np.int8), dec_rate


def scan(ts, bi, w, d, n_bins, warm=WARMUP, base_init=None):
    """Max of each statistic per BIN over all looks after `warm`, per floor."""
    dq = [deque() for _ in range(n_bins)]
    cn = np.zeros(n_bins, dtype=np.int64)
    cw = np.zeros(n_bins, dtype=np.int64)
    cd = np.zeros(n_bins, dtype=np.int64)
    base = np.full(n_bins, PRIOR) if base_init is None else base_init.copy()
    mx_a = {f: np.full(n_bins, -1.0) for f in FLOORS}
    mx_c = {f: np.full(n_bins, -9.0) for f in FLOORS}
    S = np.zeros(n_bins)
    mx_s = np.full(n_bins, -1.0)
    tl, bl, wl, dl = ts.tolist(), bi.tolist(), w.tolist(), d.tolist()
    for t, b, wi, di in zip(tl, bl, wl, dl):
        q = dq[b]
        q.append((t, wi, di))
        cn[b] += 1
        cw[b] += wi
        cd[b] += di
        cut = t - WINDOW
        while q[0][0] < cut:
            _, a1, a2 = q.popleft()
            cn[b] -= 1
            cw[b] -= a1
            cd[b] -= a2
        base[b] += ALPHA * (di - base[b])
        if t < warm:
            continue
        sv = S[b] + di - base[b] - CUSUM_K
        S[b] = sv if sv > 0.0 else 0.0
        if S[b] > mx_s[b]:
            mx_s[b] = S[b]
        n = cn[b]
        sa = cw[b] / n
        sc = cd[b] / n - base[b]
        for f in FLOORS:
            if n >= f:
                if sa > mx_a[f][b]:
                    mx_a[f][b] = sa
                if sc > mx_c[f][b]:
                    mx_c[f][b] = sc
            else:
                break
    scan.last_cusum_max = mx_s
    return mx_a, mx_c


def stress_stream(kind, seed, threshold_a, delta_c, floor=20):
    """One-hour stress stream on one BIN family (or a set for S2/S4) inside an
    organic background; returns whether (a) and (c) fire and how often."""
    rng = np.random.default_rng(seed)
    H = 3600.0
    nb = 50
    wb = _zipf_weights(nb, 1.0)
    n = int(rng.poisson(20.0 * H))       # background 20 TPS over 50 families
    ts = rng.uniform(0, H, n)
    bi = rng.choice(nb, size=n, p=wb)
    codes_all = list(ORGANIC_DECLINE_MIX.keys())
    pmix = np.array(list(ORGANIC_DECLINE_MIX.values()))
    dec = rng.random(n) < 0.12
    code = np.array(codes_all, dtype=object)[rng.choice(len(codes_all), size=n, p=pmix)]
    code[~dec] = "00"
    extra_t, extra_b, extra_c = [], [], []
    target = 5   # a mid-volume family
    if kind == "S1_05_51_heavy":
        m = int(rng.poisson(3.0 * H))
        extra_t = list(rng.uniform(0, H, m)); extra_b = [target] * m
        dd = rng.random(m) < 0.40
        extra_c = [("05" if rng.random() < 0.55 else "51") if x else "00" for x in dd]
    elif kind.startswith("S2_billing"):
        frac = 0.30 if kind.endswith("30") else 0.60
        m = 3000
        t0 = rng.uniform(600, 1500, m)
        bsel = rng.choice(nb, size=m, p=wb)
        for t, b in zip(t0, bsel):
            exp = rng.random() < frac
            extra_t.append(t); extra_b.append(int(b)); extra_c.append("54" if exp else "00")
            if exp:
                for r in (1, 2):                      # two retries, 5 minutes apart
                    extra_t.append(t + 300.0 * r); extra_b.append(int(b)); extra_c.append("54")
    elif kind == "S3_outage_91":
        sel = (bi == target) & (ts > 1200) & (ts < 1800)
        code[sel] = "91"
    elif kind == "S4_substitution":
        m = int(rng.poisson(60.0 * 1800))           # 60 TPS of bots for 30 min over 10 families
        extra_t = list(rng.uniform(1800, H, m))
        fams = rng.choice(nb, size=10, replace=False, p=wb)
        extra_b = [int(x) for x in rng.choice(fams, size=m)]
        extra_c = ["05" if rng.random() < 0.6 else "51" for _ in range(m)]
    T = np.concatenate([ts, np.array(extra_t, dtype=float)])
    B = np.concatenate([bi, np.array(extra_b, dtype=int)])
    C = np.concatenate([code, np.array(extra_c, dtype=object)])
    o = np.argsort(T, kind="stable")
    T, B, C = T[o], B[o], C[o]
    W = np.array([c in DECLINE_CODES_WATCHED for c in C], dtype=np.int8)
    D = np.array([(c != "00") and (c not in R11C_EXCLUDED) for c in C], dtype=np.int8)
    Dall = np.array([c != "00" for c in C], dtype=np.int8)
    # baseline initialised at each family's organic decline share (operator history)
    base0 = np.full(nb, 0.12 * (1 - 0.03))
    base0[target] = 0.40 if kind == "S1_05_51_heavy" else base0[target]
    mx_a, mx_c = scan(T, B, W, D, nb, warm=0.0, base_init=base0)
    mx_s = scan.last_cusum_max.copy()
    _, mx_c91 = scan(T, B, W, Dall, nb, warm=0.0, base_init=base0)
    fa = lambda arr, th: int((arr > th).sum())
    return {"a_fires_families": fa(mx_a[floor], threshold_a),
            "c_fires_families": fa(mx_c[floor], delta_c),
            "c_fires_families_if_91_counted": fa(mx_c91[floor], delta_c),
            "cusum_max": round(float(mx_s.max()), 3),
            "max_a": round(float(mx_a[floor].max()), 4),
            "max_c": round(float(mx_c[floor].max()), 4)}


def main():
    mxa_all, mxc_all, mxs_all = [], [], []
    for s in SEEDS:
        ts, bi, w, d, _ = organic_day(s)
        mx_a, mx_c = scan(ts, bi, w, d, N_BINS)
        mxa_all.append(mx_a)
        mxc_all.append(mx_c)
        mxs_all.append(scan.last_cusum_max.copy())
        print(f"seed {s}: {len(ts)} responses scanned", flush=True)

    def curve(mxs, lo):
        out = {}
        for f in FLOORS:
            allmx = np.concatenate([m[f] for m in mxs])
            elig = allmx > lo
            ne = int(elig.sum())
            out[str(f)] = {"eligible_bin_days": ne,
                           "fa_rate": {str(th): (float((allmx[elig] > th).sum()) / ne if ne else None)
                                       for th in GRID}}
        return out
    ca = curve(mxa_all, -1.0)
    cc = curve(mxc_all, -9.0)

    def select(c):
        for th in GRID:
            r = c["20"]["fa_rate"][str(th)]
            if r is not None and r <= TARGET_PER_BIN_DAY:
                return th
        return None
    th_a, th_c = select(ca), select(cc)
    smx = np.concatenate(mxs_all)
    s_elig = smx >= 0.0
    cusum_curve = {str(h): float((smx[s_elig] > h).sum()) / int(s_elig.sum()) for h in H_GRID}
    h_sel = next((h for h in H_GRID if cusum_curve[str(h)] <= TARGET_PER_BIN_DAY), None)
    print(f"approval-rate CUSUM (k={CUSUM_K}): h = {h_sel}; curve {cusum_curve}")
    print(f"selected (floor 20): watched_share > {th_a}; baseline_excess > {th_c}")
    stress = {}
    for kind in ["S1_05_51_heavy", "S2_billing_54_30", "S2_billing_54_60", "S3_outage_91", "S4_substitution"]:
        runs = [stress_stream(kind, 100 + k, th_a, th_c) for k in range(5)]
        stress[kind] = {"runs": runs,
                        "a_fired_runs": sum(1 for r in runs if r["a_fires_families"] > 0),
                        "c_fired_runs": sum(1 for r in runs if r["c_fires_families"] > 0),
                        "c_fired_runs_if_91_counted": sum(1 for r in runs if r["c_fires_families_if_91_counted"] > 0),
                        "cusum_fired_runs": (sum(1 for r in runs if r["cusum_max"] > h_sel)
                                             if h_sel is not None else None)}
        print(kind, {k: v for k, v in stress[kind].items() if k != "runs"}, flush=True)
    out = {
        "data": "SYNTHETIC organic traffic, fdce.scenario zipf profile; assumed decline-code mix",
        "population": {"seeds": SEEDS, "bin_families": N_BINS, "total_tps": TOTAL_TPS,
                       "hours_per_bin_day": 24, "warmup_s": WARMUP, "window_s": WINDOW},
        "target_fa_per_bin_day": TARGET_PER_BIN_DAY,
        "watched_share": {"curve": ca, "selected_threshold_floor20": th_a},
        "baseline_excess": {"curve": cc, "selected_delta_floor20": th_c, "excluded_codes": sorted(R11C_EXCLUDED)},
        "stress_streams": stress,
        "approval_cusum": {"k": CUSUM_K, "eligible_bin_days": int(s_elig.sum()),
                           "fa_rate": cusum_curve, "selected_h": h_sel},
    }
    path = os.environ.get("R11_CAL_OUT", os.path.join(HERE, "R11_MULTILOOK_CALIBRATION.json"))
    with open(path, "w") as f:
        json.dump(out, f, indent=1)
    print("wrote", path)


if __name__ == "__main__":
    main()

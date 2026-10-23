#!/usr/bin/env python3
"""
2.9 D0-b (review R3-011, Amit's decision D0-b): formula-level comparison of fusion
rules. This is NOT a system ablation: signal vectors are drawn from stated
distributions, not produced by the components.

Part 1, closed-form activation map over (W, TCS) on a 201 x 201 grid, for
  multiplicative (TIG-CDO): W * (1 + beta (1 - TCS)) > 0.75, beta = 4.5
  additive:  W + gamma (1 - TCS) > theta_add, gamma = 0.5, theta_add = 0.75
  or_path:   W > 0.75 or (1 - TCS) > theta_c, theta_c = 0.60 (TCS < 0.40)
reporting the share of the sub-threshold region (W <= 0.50, i.e. a fusion that
needs no single layer above 0.50) that each rule activates on, the organic point
(W 0.070, TCS 0.92), the Phase-3 point (W 0.196, TCS 0.23) and the W < 0.136 strip.

Part 2, population comparison: 10,000 organic and 10,000 attack vectors per
attack class. Each rule's threshold is set on the organic population for a
target false-positive rate (1% and 0.1%), and the true-positive rate on each
attack class is reported. Rules: weighted (beta = 0), multiplicative at
beta in {0, 2, 4.5}, additive, or_path and the coherence-only comparator
max(max_i s_i, 1 - TCS). Also clcs.compare_detection_modes at the configured
theta 0.75 on the same populations, and a processor-only variant without s4.

Distributions (assumptions, stated in the paper):
  organic: s1, s2, s3, s5 ~ Beta(2, 30); s4 ~ Beta(6, 34);
           TCS ~ 0.9 Beta(46, 4) + 0.1 Beta(8, 3) (a minority of small families)
  attack A "composite": s_i ~ U(0.05, 0.45), TCS ~ U(0.0, 0.6)
  attack B "evasive":   s_i ~ U(0.02, 0.15), TCS ~ U(0.0, 0.6)   (W held low)
  attack C "coherent":  s_i ~ U(0.05, 0.45), TCS ~ U(0.8, 1.0)   (coherence kept)
"""
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiments._common import write  # noqa: E402
from clcs.clcs import CLCSEngine, CLCSConfig, LayerScores, compare_detection_modes  # noqa: E402

W8 = np.array([0.20, 0.25, 0.20, 0.20, 0.15])
SEED = 42
N = 10000


def populations(rng):
    org = np.column_stack([rng.beta(2, 30, N), rng.beta(2, 30, N), rng.beta(2, 30, N),
                           rng.beta(6, 34, N), rng.beta(2, 30, N)])
    mix = rng.random(N) < 0.9
    tcs_org = np.where(mix, rng.beta(46, 4, N), rng.beta(8, 3, N))
    att = {
        "A_composite": (rng.uniform(0.05, 0.45, (N, 5)), rng.uniform(0.0, 0.6, N)),
        "B_evasive_low_W": (rng.uniform(0.02, 0.15, (N, 5)), rng.uniform(0.0, 0.6, N)),
        "C_coherent": (rng.uniform(0.05, 0.45, (N, 5)), rng.uniform(0.8, 1.0, N)),
    }
    return (org, tcs_org), att


def scores(mode, S, T, w=W8, beta=4.5, gamma=0.5):
    Wv = S @ w
    if mode == "weighted":
        return Wv
    if mode == "multiplicative":
        return np.minimum(1.0, Wv * (1.0 + beta * (1.0 - T)))
    if mode == "additive":
        return Wv + gamma * (1.0 - T)
    if mode == "or_path":
        return np.maximum(Wv, 1.0 - T)
    if mode == "coherence_only":
        return np.maximum(S.max(axis=1), 1.0 - T)
    raise ValueError(mode)


def activation_map():
    Wg = np.linspace(0, 1, 201)
    Tg = np.linspace(0, 1, 201)
    WW, TT = np.meshgrid(Wg, Tg)
    rules = {
        "multiplicative_beta4.5": WW * (1 + 4.5 * (1 - TT)) > 0.75,
        "multiplicative_beta2": WW * (1 + 2.0 * (1 - TT)) > 0.75,
        "additive_gamma0.5": WW + 0.5 * (1 - TT) > 0.75,
        "or_path_tcs0.40": (WW > 0.75) | ((1 - TT) > 0.60),
    }
    sub = WW <= 0.50
    strip = WW < 0.136
    out = {}
    for k, m in rules.items():
        out[k] = {"share_of_subthreshold_region_activated": round(float((m & sub).sum() / sub.sum()), 4),
                  "share_of_W_below_0.136_strip_activated": round(float((m & strip).sum() / strip.sum()), 4),
                  "organic_point_activates": bool(_pt(k, 0.070, 0.92)),
                  "phase3_point_activates": bool(_pt(k, 0.196, 0.23)),
                  "processor_only_point_activates": bool(_pt(k, 0.1675, 0.23))}
    out["min_W_activating_at_TCS0"] = {"multiplicative_beta4.5": round(0.75 / 5.5, 4),
                                       "additive_gamma0.5": 0.25, "or_path_tcs0.40": 0.0}
    return out


def _pt(rule, W, T):
    if rule.startswith("multiplicative"):
        b = float(rule.split("beta")[1])
        return W * (1 + b * (1 - T)) > 0.75
    if rule.startswith("additive"):
        return W + 0.5 * (1 - T) > 0.75
    return (W > 0.75) or ((1 - T) > 0.60)


def tpr_at_fpr(org_s, att_s, fpr):
    thr = float(np.quantile(org_s, 1 - fpr))
    return {"threshold": round(thr, 4), "fpr_realized": round(float((org_s > thr).mean()), 5),
            "tpr": round(float((att_s > thr).mean()), 4)}


def main():
    rng = np.random.default_rng(SEED)
    (org, tcs_org), att = populations(rng)
    out = {"status": "formula-level comparison on sampled signal vectors; not a system ablation",
           "n_per_population": N, "seed": SEED, "activation_map": activation_map(), "populations": {}}
    modes = [("weighted", {}), ("multiplicative", {"beta": 0.0}), ("multiplicative", {"beta": 2.0}),
             ("multiplicative", {"beta": 4.5}), ("additive", {"gamma": 0.5}), ("or_path", {}),
             ("coherence_only", {})]
    for variant, (w, cols) in {"s4_shared": (W8, [0, 1, 2, 3, 4]),
                               "processor_only_no_s4": (np.array([0.20, 0.25, 0.20, 0.15]) / 0.80, [0, 1, 2, 4])}.items():
        So = org[:, cols]
        res = {}
        for mode, kw in modes:
            name = mode + ("_beta%s" % kw["beta"] if "beta" in kw else "")
            so = scores(mode, So, tcs_org, w=w, **kw)
            row = {"organic_activation_at_0.75": round(float((so > 0.75).mean()), 5)}
            for an, (S, T) in att.items():
                sa = scores(mode, S[:, cols], T, w=w, **kw)
                row[an] = {"fpr_1pct": tpr_at_fpr(so, sa, 0.01), "fpr_0.1pct": tpr_at_fpr(so, sa, 0.001),
                           "tpr_at_configured_0.75": round(float((sa > 0.75).mean()), 4),
                           "composite_only_share_at_0.75": round(float(((sa > 0.75) & (S[:, cols].max(axis=1) <= 0.5)).mean()), 4)}
            res[name] = row
        out["populations"][variant] = res
    # compare_detection_modes on the populations (configured theta 0.75)
    def to_scores(S, T, tag):
        return [LayerScores(timestamp=float(i), s1_waf=s[0], s2_lbmd=s[1], s3_bin_watch=s[2],
                            s4_acs_guard=s[3], s5_hpa_delta=s[4], bin_prefix=f"{tag}{i}") for i, s in enumerate(S[:2000])], \
               {f"{tag}{i}": float(t) for i, t in enumerate(T[:2000])}
    cdm = {}
    for an, (S, T) in [("organic", (org, tcs_org))] + list(att.items()):
        ls, tb = to_scores(S, T, an[:3])
        r = compare_detection_modes(ls, tb)
        cdm[an] = {m: {"activations": v.get("activations"), "evaluations": v.get("evaluations"),
                       "composite_only": v.get("composite_only_detections")} for m, v in r.items()}
    out["compare_detection_modes_first_2000"] = cdm
    for v in out["populations"].values():
        for m, r in v.items():
            print(m, {a: (r[a]["fpr_1pct"]["tpr"], r[a]["fpr_0.1pct"]["tpr"]) for a in att})
        print("--")
    write("d0b_fusion.json", out)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
2.10 Vantage (review R3-012, author fact F3: each signal is owned by the party that
produces it; s4, the ACS session-pool ratio, is issuer-side telemetry).

Recomputes Table 11 (CLCS at the Phase-3 and organic points across beta) for
  s4_shared:      all five signals (requires the issuer to share s4)
  processor_only: s1, s2, s3, s5 with weights renormalized to sum to 1
                  (and, for reference, the unrenormalized sum)
and the beta at which each point starts to activate. The organic point uses the
configured organic vector of clcs._demo's midpoints (s = 0.05, 0.065, 0.045,
0.15, 0.03; W = 0.070 with s4).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiments._common import write  # noqa: E402

W = [0.20, 0.25, 0.20, 0.20, 0.15]
ATT = [0.12, 0.18, 0.22, 0.31, 0.14]
ORG = [0.05, 0.065, 0.045, 0.15, 0.03]
TCS_ATT, TCS_ORG, THETA = 0.23, 0.92, 0.75
BETAS = [0.0, 2.0, 3.0, 3.5, 4.0, 4.5, 5.0, 6.0, 7.0]


def wsum(s, drop4=False, renorm=True):
    idx = [0, 1, 2, 4] if drop4 else [0, 1, 2, 3, 4]
    v = sum(W[i] * s[i] for i in idx)
    if drop4 and renorm:
        v /= sum(W[i] for i in idx)
    return v


def clcs(Wv, tcs, beta):
    return min(1.0, Wv * (1.0 + beta * (1.0 - tcs)))


def main():
    out = {"points": {}, "table11": {}}
    for name, drop4, ren in [("s4_shared", False, True), ("processor_only", True, True),
                             ("processor_only_unrenormalized", True, False)]:
        wa, wo = wsum(ATT, drop4, ren), wsum(ORG, drop4, ren)
        out["points"][name] = {"W_attack": round(wa, 4), "W_organic": round(wo, 4),
                               "beta_boundary_attack": round((THETA / wa - 1) / (1 - TCS_ATT), 3),
                               "beta_clamp_attack": round((1 / wa - 1) / (1 - TCS_ATT), 3),
                               "clcs_attack_beta4.5": round(clcs(wa, TCS_ATT, 4.5), 4),
                               "clcs_organic_beta4.5": round(clcs(wo, TCS_ORG, 4.5), 4)}
        out["table11"][name] = [{"beta": b, "clcs_attack": round(clcs(wa, TCS_ATT, b), 4),
                                 "activates": clcs(wa, TCS_ATT, b) > THETA,
                                 "clcs_organic": round(clcs(wo, TCS_ORG, b), 4),
                                 "false_activation": clcs(wo, TCS_ORG, b) > THETA} for b in BETAS]
        print(name, out["points"][name])
    write("vantage_table11.json", out)


if __name__ == "__main__":
    main()

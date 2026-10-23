#!/usr/bin/env python3
"""
2.8 Table 13 like-for-like (review R3-010). Both columns over the same scenario
set (the three attack intensities, attack share 10%, 25%, 45%), all four
configurations at their configured block rates (0, 0.45, 0.55, 0.95):
  gaussian: closed-form SLA of run_followup_analyses.sla_gauss with each
            configuration's own Gaussian latency parameters
  real:     run_followup_analyses.sla_real, legitimate per-RPC response times
            bootstrap-sampled from the Alibaba cluster-trace-v2021 and scaled by
            the RCAEval RE2-TT degradation ratio when residual load exceeds 5%
Neither column subtracts false positives. The real column is the share of
single-RPC response times within 50 ms, compared with a 50 ms end-to-end budget;
no k-hop composition is applied. Needs the external RCAEval and Alibaba data
under $DDOS_RAW_DATA_ROOT.
"""
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiments._common import write  # noqa: E402
import run_followup_analyses as FU  # noqa: E402
import run_tigcdo_eval as EV  # noqa: E402


def main():
    s1 = FU.CAL.section1_rcaeval()
    degr = s1["degraded_over_legit_ratio"]
    s3 = FU.CAL.section3_alibaba()
    rt = np.asarray(s3["_rt_sample"], float)
    rt = rt[(rt > 0) & (rt < 100000)]
    out = {"scenario_set": "attack intensities only (10%, 25%, 45% attack share)", "budget_ms": 50.0,
           "degradation_ratio": degr, "real_rt_mean_ms": round(float(rt.mean()), 2),
           "share_single_rpc_le_50ms_no_attack": round(100.0 * float((rt <= 50.0).mean()), 2),
           "rows": {}}
    for cfg in ["no_defense", "taada", "ensemble", "tig_cdo"]:
        b = EV._ATTACK_BLOCK[cfg]
        out["rows"][cfg] = {"block_rate": b, "gaussian_sla_pct": FU.sla_gauss(b, config=cfg),
                            "real_sla_pct": FU.sla_real(rt, degr, b)}
        print(cfg, out["rows"][cfg], flush=True)
    t, n = out["rows"]["tig_cdo"], out["rows"]["no_defense"]
    out["gap_tig_minus_no_defense_pp"] = {"gaussian": round(t["gaussian_sla_pct"] - n["gaussian_sla_pct"], 1),
                                          "real": round(t["real_sla_pct"] - n["real_sla_pct"], 1)}
    write("table13_like_for_like.json", out)


if __name__ == "__main__":
    main()

"""
Write FDCE_RULE_ENGINE_RESULTS.json from the implemented R-11/R-12 detectors.

Added in v1.2.0 (fix 7): in v1.1.0 this file was checked in without a writer.
This script regenerates both grids with the seeds that reproduce the archived
v1.1.0 file exactly:
  main grid (30 scenarios)       seed = 42 + cluster + int(intensity * 100),
                                 the seed run_tigcdo_eval.run_fdce_evaluation() uses;
  adversarial grid (9 scenarios) seed = 42.

Known limitation, unchanged in v1.2.0 (review R1-006): in the adversarial grid,
simulate_fdce_adversarial_spread() evaluates R-12 only until the first detection,
so at most one merchant is ever blocked and the adversarial block rate is a
harness artifact. The paper does not use that block rate.

Run:    python3 write_fdce_results.py
Output: FDCE_RULE_ENGINE_RESULTS.json (override with FDCE_RESULTS_OUT=<path>)
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from fdce.scenario import simulate_fdce_scenario, simulate_fdce_adversarial_spread  # noqa: E402

SEED = 42
CLUSTERS = [50, 200, 500]
CARD_TYPES = ["expired_only", "mixed"]
INTENSITIES = [0.2, 0.4, 0.6, 0.8, 1.0]
ADV_INTENSITIES = [0.2, 0.6, 1.0]


def main():
    main_grid = []
    for cluster in CLUSTERS:
        for card_type in CARD_TYPES:
            for intensity in INTENSITIES:
                r = simulate_fdce_scenario(cluster, card_type, intensity,
                                           seed=SEED + cluster + int(intensity * 100))
                main_grid.append({
                    "cluster": cluster, "card_type": card_type, "intensity": intensity,
                    "detection_latency_s": r.detection_latency_s,
                    "rule": r.triggered_rule,
                    "block_rate": round(r.block_rate, 4),
                    "bot_txn": r.n_bot_txn,
                    "organic_fp": r.n_organic_r12_false_positives,
                })
    adversarial = []
    for cluster in CLUSTERS:
        for intensity in ADV_INTENSITIES:
            r, r11_ever = simulate_fdce_adversarial_spread(cluster, intensity, seed=SEED)
            adversarial.append({
                "cluster": cluster, "intensity": intensity,
                "detection_latency_s": r.detection_latency_s,
                "rule": r.triggered_rule,
                "block_rate": round(r.block_rate, 4),
                "r11_ever_triggered": bool(r11_ever),
            })
    out = {"main_grid_30_scenarios": main_grid,
           "adversarial_decline_spreading_9_scenarios": adversarial}
    path = os.environ.get("FDCE_RESULTS_OUT", "FDCE_RULE_ENGINE_RESULTS.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    lat = [r["detection_latency_s"] for r in main_grid if r["detection_latency_s"] is not None]
    print(f"main grid: {len(lat)}/{len(main_grid)} detected, mean latency {sum(lat)/len(lat):.2f} s, "
          f"mean block rate {100*sum(r['block_rate'] for r in main_grid)/len(main_grid):.1f}%")
    print("wrote", path)


if __name__ == "__main__":
    main()

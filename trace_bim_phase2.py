"""
Record the per-day JS divergence and CUSUM statistic C+ of the CSDA Phase-2
BIM run in run_tigcdo_eval.run_phase_detection_test() (seed 42).

Added in v1.2.0 (fix 3): Figure 2 and the Phase-2 trajectory table used to be
hard-coded in generate_paper_figures.py, with two wrong C+ cells (days 8 and
10). This script produces the trajectory from the implemented detector, and
generate_paper_figures.py plots Figure 2 from its output.

Run:    python3 trace_bim_phase2.py
Output: BIM_PHASE2_TRACE.json (override with TRACE_OUT=<path>)
"""
import contextlib
import io
import json
import logging
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
logging.disable(logging.CRITICAL)

import bim.bim as B  # noqa: E402

_records = []
_orig_update = B.JSCUSUMState.update


def _recording_update(self, js_t, timestamp):
    r = _orig_update(self, js_t, timestamp)
    _records.append((timestamp / 86400.0, js_t, self.c_plus, self.alarm_triggered))
    return r


B.JSCUSUMState.update = _recording_update

import run_tigcdo_eval as E  # noqa: E402


def main():
    with contextlib.redirect_stdout(io.StringIO()):
        E.run_phase_detection_test()
    rows = [{"day": round(d), "js": round(js, 5), "c_plus": round(c, 5), "alarm": bool(a)}
            for d, js, c, a in _records if 7.5 <= d <= 14.5]
    out = {
        "source": "run_tigcdo_eval.run_phase_detection_test(), CSDA Phase 2, seed 42",
        "status": "simulated traffic; detector output",
        "mu0_js": E.BIM_MU0_JS,
        "k": E.BIM_K,
        "h": E.BIM_H,
        "phase2_onset_day": 8,
        "rows": rows,
    }
    path = os.environ.get("TRACE_OUT", "BIM_PHASE2_TRACE.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=1)
    for r in rows:
        print(f"day {r['day']:>2}  JS={r['js']:.5f}  C+={r['c_plus']:.5f}  alarm={r['alarm']}")
    print("wrote", path)


if __name__ == "__main__":
    main()

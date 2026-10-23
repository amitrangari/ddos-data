"""
Per-BIN approval-rate CUSUM (v1.3.0, review R3-023): a standard Bernoulli CUSUM
on the decline indicator of every authorization response, per BIN family,
against that family's baseline decline share p_b (code 91 excluded, as for R-11):

    S_b <- max(0, S_b + x - p_b - k),   alarm when S_b > h

x is 1 for a decline and 0 for an approval. k = 0.25 targets a rise of the
decline share by about 0.5; h is calibrated for a per-BIN-day false-alarm target
by calibrate_r11_multilook.py on the same organic population as R-11. After an
alarm the statistic restarts at 0. This baseline only alarms; it does not block.
"""
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

CUSUM_K = 0.25
CUSUM_H = 10.0         # calibrated (R11_MULTILOOK_CALIBRATION.json, ledger run R-0034)
EXCLUDED = {"91"}
PRIOR = 0.12


class BinDeclineCUSUM:
    def __init__(self, k: float = CUSUM_K, h: float = CUSUM_H,
                 baseline: Optional[Dict[str, float]] = None, prior: float = PRIOR):
        self.k, self.h = k, h
        self.baseline = dict(baseline or {})
        self.prior = prior
        self.S: Dict[str, float] = defaultdict(float)
        self.alarms: List[Tuple[str, float]] = []

    def observe(self, bin_prefix: str, ts: float, response_code: Optional[str]):
        if response_code in EXCLUDED:
            return
        x = 0.0 if response_code in (None, "00") else 1.0
        p = self.baseline.get(bin_prefix, self.prior)
        s = max(0.0, self.S[bin_prefix] + x - p - self.k)
        if s > self.h:
            self.alarms.append((bin_prefix, ts))
            s = 0.0
        self.S[bin_prefix] = s

"""
Federated Declined-Card Exhaustion (FDCE) rule engine — TIG-CDO, Section II.A

Implements R-11 (decline-code concentration within a BIN window) and R-12
(completion-rate floor per merchant cluster, volume-gated) as live, wired
detectors, rather than the hardcoded per-config block-rate/detection-latency
constants v1 used (see paper2-solution/review/2026-08-15/00_CONSOLIDATED_REVIEW.md,
finding C7).

R-11: >80% of 0110 responses within a BIN window carry decline codes in the
      watched set {14, 54, 57, 82} -> BIN-level signal, independent of merchant.
R-12: 0100->0200 completion rate <5% at >100 txn/min, evaluated PER MERCHANT
      CLUSTER (not per BIN) -> requires a merchant_id on the event, which v1's
      STC session key did not carry. Added here as a separate lightweight
      tracker rather than folded into STC's session key, to avoid touching the
      CSDA Phase 1-4 / TCS session-key architecture that has no merchant_id in
      its design and whose behavior is independently validated.
"""

from collections import deque, defaultdict
from dataclasses import dataclass
from typing import Deque, Dict, Optional, Set, Tuple

DECLINE_CODES_WATCHED: Set[str] = {"14", "54", "57", "82"}


@dataclass
class R11Result:
    triggered: bool
    max_code_share: float
    dominant_code: Optional[str]
    n_declines: int


@dataclass
class R12Result:
    triggered: bool
    completion_rate: float
    txn_per_min: float
    n_auths: int


class FDCEDetector:
    """Sliding-window R-11 / R-12 detector. Feed it every ISO 0100 (auth
    request) and 0110 (auth response, carrying response_code) and 0200
    (completion) event; call check() periodically (or after every event) to
    get the current trigger state for a given bin_prefix / merchant_id."""

    def __init__(self, window_s: float = 60.0,
                 r11_threshold: float = 0.80, r11_min_declines: int = 20,
                 r12_min_txn_per_min: float = 100.0, r12_completion_threshold: float = 0.05,
                 r12_min_auths: int = 10):
        self.window_s = window_s
        self.r11_threshold = r11_threshold
        self.r11_min_declines = r11_min_declines
        self.r12_min_txn_per_min = r12_min_txn_per_min
        self.r12_completion_threshold = r12_completion_threshold
        self.r12_min_auths = r12_min_auths

        # R-11 state: bin_prefix -> deque[(ts, code_or_None)], plus a running
        # decline-code Counter kept in sync incrementally (O(1) amortized per
        # event, rather than rescanning the whole window on every check --
        # matters at FDCE-scale volumes: up to ~900k events/scenario).
        self._bin_responses: Dict[str, Deque[Tuple[float, Optional[str]]]] = defaultdict(deque)
        self._bin_decline_counts: Dict[str, Dict[str, int]] = defaultdict(dict)
        # R-12 state: merchant_id -> deque[ts] for auths and completions
        self._merchant_auths: Dict[str, Deque[float]] = defaultdict(deque)
        self._merchant_completions: Dict[str, Deque[float]] = defaultdict(deque)

        self.r11_triggered_bins: Set[str] = set()
        self.r11_trigger_time: Dict[str, float] = {}
        self.r12_triggered_merchants: Set[str] = set()
        self.r12_trigger_time: Dict[str, float] = {}

    def observe_auth_response(self, bin_prefix: str, ts: float, response_code: Optional[str]):
        """response_code=None or '00' = approved; any other code = decline."""
        code = None if response_code in (None, "00") else response_code
        dq = self._bin_responses[bin_prefix]
        dq.append((ts, code))
        if code is not None:
            counts = self._bin_decline_counts[bin_prefix]
            counts[code] = counts.get(code, 0) + 1
        self._evict_r11(bin_prefix, ts)

    def observe_auth_request(self, merchant_id: str, ts: float):
        dq = self._merchant_auths[merchant_id]
        dq.append(ts)
        self._evict(dq, ts)

    def observe_completion(self, merchant_id: str, ts: float):
        dq = self._merchant_completions[merchant_id]
        dq.append(ts)
        self._evict(dq, ts)

    def _evict(self, dq: Deque, now: float):
        cutoff = now - self.window_s
        while dq and (dq[0][0] if isinstance(dq[0], tuple) else dq[0]) < cutoff:
            dq.popleft()

    def _evict_r11(self, bin_prefix: str, now: float):
        dq = self._bin_responses[bin_prefix]
        counts = self._bin_decline_counts[bin_prefix]
        cutoff = now - self.window_s
        while dq and dq[0][0] < cutoff:
            _, code = dq.popleft()
            if code is not None:
                counts[code] -= 1
                if counts[code] <= 0:
                    del counts[code]

    def check_r11(self, bin_prefix: str, now: float) -> R11Result:
        if bin_prefix not in self._bin_responses:
            return R11Result(False, 0.0, None, 0)
        self._evict_r11(bin_prefix, now)
        counts = self._bin_decline_counts[bin_prefix]
        n = sum(counts.values())
        if n < self.r11_min_declines or not counts:
            return R11Result(False, 0.0, None, n)
        dominant, dom_count = max(counts.items(), key=lambda kv: kv[1])
        share = dom_count / n
        triggered = share > self.r11_threshold
        if triggered and bin_prefix not in self.r11_triggered_bins:
            self.r11_triggered_bins.add(bin_prefix)
            self.r11_trigger_time[bin_prefix] = now
        return R11Result(triggered, share, dominant, n)

    def check_r12(self, merchant_id: str, now: float) -> R12Result:
        auths_dq = self._merchant_auths.get(merchant_id)
        comp_dq = self._merchant_completions.get(merchant_id)
        if not auths_dq:
            return R12Result(False, 1.0, 0.0, 0)
        self._evict(auths_dq, now)
        if comp_dq:
            self._evict(comp_dq, now)
        n_auths = len(auths_dq)
        n_comp = len(comp_dq) if comp_dq else 0
        txn_per_min = n_auths / (self.window_s / 60.0)
        completion_rate = n_comp / n_auths if n_auths > 0 else 1.0
        triggered = (n_auths >= self.r12_min_auths and
                    txn_per_min > self.r12_min_txn_per_min and
                    completion_rate < self.r12_completion_threshold)
        if triggered and merchant_id not in self.r12_triggered_merchants:
            self.r12_triggered_merchants.add(merchant_id)
            self.r12_trigger_time[merchant_id] = now
        return R12Result(triggered, completion_rate, txn_per_min, n_auths)

    def is_blocked(self, bin_prefix: str, merchant_id: str) -> bool:
        """PSRG blocking policy: once R-11 fires for a BIN or R-12 fires for a
        merchant cluster, subsequent traffic from that BIN/merchant is blocked
        (this is the mechanism that produces a genuine block rate, rather than
        a hardcoded one)."""
        return bin_prefix in self.r11_triggered_bins or merchant_id in self.r12_triggered_merchants

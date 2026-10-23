"""
Federated Declined-Card Exhaustion (FDCE) rule engine, TIG-CDO. Version 1.3.0.

R-11 (decline concentration, per BIN family, 60 s window)
    v1.3.0 (review R3-003, editorial call E3). E3 adopted (a), the share of all
    authorization responses carrying a watched code {14, 54, 57, 82}, with (c) as
    the fallback if a 05/51 substitution adversary or code-54 recurring-billing
    retries defeated (a). calibrate_r11_multilook.py found that both do (the
    substitution adversary evades (a); a 60%-expired renewal run with retries fires
    it), while (c) passed all five stress streams, so the default is (c):
      r11_mode="baseline_excess" (default): decline share of the responses in the
          window (code 91, issuer unavailable, excluded) minus the BIN family's
          long-run decline share (EWMA); fires when the excess exceeds R11C_DELTA.
      r11_mode="watched_share": statistic (a), threshold R11_THRESHOLD.
    R-11 is evaluated after every response (repeated looks) and needs at least
    R11_MIN_RESPONSES responses in the window. Thresholds come from the multi-look
    calibration (per-BIN-day false-alarm target). v1.2 used the largest single-code
    share among declines, which fired on organic families dominated by 05, 51 or 91.

R-12 (completion-rate floor, per merchant identity, 60 s window, volume-gated)
    v1.3.0 (review R3-004): censoring-aware. v1.2 compared completions with
    authorizations in the same trailing window, which counts every authorization
    whose capture has not yet arrived as a failure (and the v1.2 simulator fed
    completions to the detector before they happened). Three estimators:
      "censoring_bound" (default): c_ub = 1 - n_failed / n_auth over the window,
          where an authorization counts as failed only once its outcome is known
          (declined, reversed, no response, or approved and not captured by the
          completion deadline). Authorizations still awaiting capture count as
          potential completions, so delayed capture never lowers c_ub.
      "lagged_cohort": completion rate of the authorizations whose completion
          deadline has passed (cohort initiated in (t - D - W, t - D]).
      "same_window": the v1.2 estimator, kept to measure what the fix changes.

Blocks expire after block_ttl_s (default 600 s) and are re-earned if the condition
persists (v1.2 blocks never lifted).
"""

from collections import deque, defaultdict
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional, Set, Tuple

DECLINE_CODES_WATCHED: Set[str] = {"14", "54", "57", "82"}

# Calibrated by calibrate_r11_multilook.py (results/v1.3.0/R11_MULTILOOK_CALIBRATION.json,
# ledger run R-0034): smallest threshold on a 0.05 grid with no false alarm in 1,375
# eligible synthetic organic BIN-days (target 1e-3 per BIN-day; exact 95% upper bound
# of the observed rate 0.27%), floor 20 responses in 60 s.
R11_THRESHOLD = 0.40      # statistic (a), watched-code share
R11_MIN_RESPONSES = 20
R11C_DELTA = 0.45         # statistic (c), decline-share excess over the family baseline (default)
R11C_EXCLUDED = {"91"}
R11C_BASELINE_ALPHA = 1.0 / 5000.0
R11C_PRIOR_DECLINE_SHARE = 0.12

# Completion windows per message flow (author fact F2); parameters, not measurements.
COMPLETION_WINDOW_S = {"single": 5.0, "dual_0220": 1800.0, "clearing": 129600.0}

PENDING_RESPONSE, APPROVED_PENDING, COMPLETED, FAILED = 0, 1, 2, 3


@dataclass
class R11Result:
    triggered: bool
    statistic: float
    n_responses: int
    max_code_share: float = 0.0       # kept for v1.2 callers (equals statistic)
    dominant_code: Optional[str] = None
    n_declines: int = 0


@dataclass
class R12Result:
    triggered: bool
    completion_rate: float
    txn_per_min: float
    n_auths: int


class _Rec:
    __slots__ = ("ts", "status", "in_window")

    def __init__(self, ts):
        self.ts = ts
        self.status = PENDING_RESPONSE
        self.in_window = True


class FDCEDetector:
    def __init__(self, window_s: float = 60.0,
                 r11_mode: str = "baseline_excess",
                 r11_threshold: float = R11_THRESHOLD, r11_min_responses: int = R11_MIN_RESPONSES,
                 r11c_delta: float = R11C_DELTA,
                 r12_min_txn_per_min: float = 100.0, r12_completion_threshold: float = 0.05,
                 r12_min_auths: int = 10, r12_estimator: str = "censoring_bound",
                 flow: str = "single", completion_window_s: Optional[float] = None,
                 block_ttl_s: Optional[float] = 600.0,
                 r11_min_declines: Optional[int] = None,
                 baseline_init: Optional[Dict[str, float]] = None):
        if r11_min_declines is not None:          # v1.2 keyword
            r11_min_responses = r11_min_declines
        assert r11_mode in ("watched_share", "baseline_excess")
        assert r12_estimator in ("censoring_bound", "lagged_cohort", "same_window")
        self.window_s = window_s
        self.r11_mode = r11_mode
        self.r11_threshold = r11_threshold
        self.r11_min_responses = r11_min_responses
        self.r11c_delta = r11c_delta
        self.r12_min_txn_per_min = r12_min_txn_per_min
        self.r12_completion_threshold = r12_completion_threshold
        self.r12_min_auths = r12_min_auths
        self.r12_estimator = r12_estimator
        self.flow = flow
        self.D = completion_window_s if completion_window_s is not None else COMPLETION_WINDOW_S[flow]
        self.block_ttl_s = block_ttl_s

        # R-11 state per BIN: deque[(ts, watched, declined_c)] and counters
        self._bin_resp: Dict[str, Deque[Tuple[float, int, int]]] = defaultdict(deque)
        self._bin_n: Dict[str, int] = defaultdict(int)
        self._bin_w: Dict[str, int] = defaultdict(int)
        self._bin_d: Dict[str, int] = defaultdict(int)
        self._bin_baseline: Dict[str, float] = dict(baseline_init or {})
        # R-12 state per merchant
        self._m_recs: Dict[str, Deque[_Rec]] = defaultdict(deque)
        self._m_failed: Dict[str, int] = defaultdict(int)
        self._m_pending_appr: Dict[str, Deque[_Rec]] = defaultdict(deque)
        self._txn: Dict[str, Tuple[str, _Rec]] = {}
        # lagged cohort: matured records in (t - D - W, t - D]
        self._m_cohort: Dict[str, Deque[Tuple[float, bool]]] = defaultdict(deque)
        self._m_cohort_n: Dict[str, int] = defaultdict(int)
        self._m_cohort_c: Dict[str, int] = defaultdict(int)
        self._m_unmatured: Dict[str, Deque[_Rec]] = defaultdict(deque)
        # legacy same-window state
        self._m_auth_ts: Dict[str, Deque[float]] = defaultdict(deque)
        self._m_comp_ts: Dict[str, Deque[float]] = defaultdict(deque)

        # blocks and fire log
        self._r11_block_until: Dict[str, float] = {}
        self._r12_block_until: Dict[str, float] = {}
        self.r11_triggered_bins: Set[str] = set()
        self.r11_trigger_time: Dict[str, float] = {}
        self.r12_triggered_merchants: Set[str] = set()
        self.r12_trigger_time: Dict[str, float] = {}
        self.r11_fires: List[Tuple[str, float]] = []
        self.r12_fires: List[Tuple[str, float]] = []

    # ------------------------------------------------------------------ R-11
    def observe_auth_response(self, bin_prefix: str, ts: float, response_code: Optional[str],
                              merchant_id: Optional[str] = None, txn_id: Optional[str] = None):
        """response_code None or '00' = approved; anything else is a decline."""
        approved = response_code in (None, "00")
        watched = 0 if approved else int(response_code in DECLINE_CODES_WATCHED)
        declined_c = 0 if approved else int(response_code not in R11C_EXCLUDED)
        dq = self._bin_resp[bin_prefix]
        dq.append((ts, watched, declined_c))
        self._bin_n[bin_prefix] += 1
        self._bin_w[bin_prefix] += watched
        self._bin_d[bin_prefix] += declined_c
        self._evict_r11(bin_prefix, ts)
        if self.r11_mode == "baseline_excess" and not self._is_bin_blocked(bin_prefix, ts):
            b = self._bin_baseline.get(bin_prefix, R11C_PRIOR_DECLINE_SHARE)
            self._bin_baseline[bin_prefix] = b + R11C_BASELINE_ALPHA * (declined_c - b)
        if self.r12_estimator == "same_window" and approved and self.flow == "single" \
                and merchant_id is not None:
            self.observe_completion(merchant_id, ts)   # single-message: approval is capture
        if txn_id is not None and txn_id in self._txn:
            m, rec = self._txn[txn_id]
            if rec.status == PENDING_RESPONSE:
                if approved:
                    if self.flow == "single":
                        self._set_status(m, rec, COMPLETED)   # kept in _txn: a reversal voids it
                    else:
                        rec.status = APPROVED_PENDING
                        self._m_pending_appr[m].append(rec)
                else:
                    self._set_status(m, rec, FAILED)
                    self._txn.pop(txn_id, None)

    def _evict_r11(self, b: str, now: float):
        dq = self._bin_resp[b]
        cutoff = now - self.window_s
        while dq and dq[0][0] < cutoff:
            _, w, d = dq.popleft()
            self._bin_n[b] -= 1
            self._bin_w[b] -= w
            self._bin_d[b] -= d

    def r11_statistic(self, b: str) -> Tuple[float, int]:
        n = self._bin_n.get(b, 0)
        if n == 0:
            return 0.0, 0
        if self.r11_mode == "watched_share":
            return self._bin_w[b] / n, n
        base = self._bin_baseline.get(b, R11C_PRIOR_DECLINE_SHARE)
        return self._bin_d[b] / n - base, n

    def check_r11(self, bin_prefix: str, now: float) -> R11Result:
        if bin_prefix not in self._bin_resp:
            return R11Result(False, 0.0, 0)
        self._evict_r11(bin_prefix, now)
        stat, n = self.r11_statistic(bin_prefix)
        thr = self.r11_threshold if self.r11_mode == "watched_share" else self.r11c_delta
        triggered = n >= self.r11_min_responses and stat > thr
        if triggered and not self._is_bin_blocked(bin_prefix, now):
            self._block_bin(bin_prefix, now)
        return R11Result(triggered, stat, n, max_code_share=stat, n_declines=self._bin_d.get(bin_prefix, 0))

    # ------------------------------------------------------------------ R-12
    def observe_auth_request(self, merchant_id: str, ts: float, txn_id: Optional[str] = None):
        if self.r12_estimator == "same_window":
            dq = self._m_auth_ts[merchant_id]
            dq.append(ts)
            self._evict_ts(dq, ts)
            return
        rec = _Rec(ts)
        self._m_recs[merchant_id].append(rec)
        if self.r12_estimator == "lagged_cohort":
            self._m_unmatured[merchant_id].append(rec)
        if txn_id is not None:
            self._txn[txn_id] = (merchant_id, rec)
        self._advance_r12(merchant_id, ts)

    def observe_completion(self, merchant_id: str, ts: float, txn_id: Optional[str] = None):
        if self.r12_estimator == "same_window":
            dq = self._m_comp_ts[merchant_id]
            dq.append(ts)
            self._evict_ts(dq, ts)
            return
        if txn_id is None or txn_id not in self._txn:
            return
        m, rec = self._txn.pop(txn_id)
        if rec.status in (PENDING_RESPONSE, APPROVED_PENDING) and ts <= rec.ts + self.D:
            self._set_status(m, rec, COMPLETED)

    def observe_reversal(self, merchant_id: str, ts: float, txn_id: Optional[str] = None):
        if self.r12_estimator == "same_window" or txn_id is None or txn_id not in self._txn:
            return
        m, rec = self._txn.pop(txn_id)
        self._set_status(m, rec, FAILED)          # a reversal is a non-completion in every flow

    def _set_status(self, m: str, rec: _Rec, status: int):
        if rec.status == status:
            return
        if self.r12_estimator == "censoring_bound" and rec.in_window:
            if status == FAILED:
                self._m_failed[m] += 1
            elif rec.status == FAILED:
                self._m_failed[m] -= 1
        rec.status = status

    def _advance_r12(self, m: str, now: float):
        # approved authorizations past their capture deadline become failures
        pa = self._m_pending_appr[m]
        while pa and pa[0].ts + self.D < now:
            rec = pa.popleft()
            if rec.status == APPROVED_PENDING:
                self._set_status(m, rec, FAILED)
        if self.r12_estimator == "censoring_bound":
            dq = self._m_recs[m]
            cutoff = now - self.window_s
            while dq and dq[0].ts < cutoff:
                rec = dq.popleft()
                if rec.status == FAILED:
                    self._m_failed[m] -= 1
                rec.in_window = False
        else:  # lagged cohort
            um = self._m_unmatured[m]
            while um and um[0].ts + self.D <= now:
                rec = um.popleft()
                done = rec.status == COMPLETED
                self._m_cohort[m].append((rec.ts, done))
                self._m_cohort_n[m] += 1
                self._m_cohort_c[m] += int(done)
            co = self._m_cohort[m]
            cutoff = now - self.D - self.window_s
            while co and co[0][0] <= cutoff:
                _, done = co.popleft()
                self._m_cohort_n[m] -= 1
                self._m_cohort_c[m] -= int(done)
            dq = self._m_recs[m]
            while dq and dq[0].ts <= cutoff:
                dq.popleft()

    def _evict_ts(self, dq: Deque[float], now: float):
        cutoff = now - self.window_s
        while dq and dq[0] < cutoff:
            dq.popleft()

    def r12_state(self, m: str, now: float) -> Tuple[float, int, float]:
        """(completion estimate, n evaluated, authorizations per minute)."""
        if self.r12_estimator == "same_window":
            a = self._m_auth_ts.get(m)
            if not a:
                return 1.0, 0, 0.0
            self._evict_ts(a, now)
            c = self._m_comp_ts.get(m)
            if c:
                self._evict_ts(c, now)
            n = len(a)
            nc = len(c) if c else 0
            return (nc / n if n else 1.0), n, n / (self.window_s / 60.0)
        self._advance_r12(m, now)
        if self.r12_estimator == "censoring_bound":
            n = len(self._m_recs[m])
            if n == 0:
                return 1.0, 0, 0.0
            return 1.0 - self._m_failed[m] / n, n, n / (self.window_s / 60.0)
        n = self._m_cohort_n[m]
        if n == 0:
            return 1.0, 0, 0.0
        return self._m_cohort_c[m] / n, n, n / (self.window_s / 60.0)

    def check_r12(self, merchant_id: str, now: float) -> R12Result:
        if (merchant_id not in self._m_recs and merchant_id not in self._m_auth_ts):
            return R12Result(False, 1.0, 0.0, 0)
        c, n, rate = self.r12_state(merchant_id, now)
        triggered = (n >= self.r12_min_auths and rate > self.r12_min_txn_per_min
                     and c < self.r12_completion_threshold)
        if triggered and not self._is_merchant_blocked(merchant_id, now):
            self._block_merchant(merchant_id, now)
        return R12Result(triggered, c, rate, n)

    # ---------------------------------------------------------------- blocks
    def _block_bin(self, b: str, now: float):
        self._r11_block_until[b] = now + (self.block_ttl_s if self.block_ttl_s else float("inf"))
        self.r11_fires.append((b, now))
        if b not in self.r11_triggered_bins:
            self.r11_triggered_bins.add(b)
            self.r11_trigger_time[b] = now

    def _block_merchant(self, m: str, now: float):
        self._r12_block_until[m] = now + (self.block_ttl_s if self.block_ttl_s else float("inf"))
        self.r12_fires.append((m, now))
        if m not in self.r12_triggered_merchants:
            self.r12_triggered_merchants.add(m)
            self.r12_trigger_time[m] = now

    def _is_bin_blocked(self, b: str, now: Optional[float]) -> bool:
        u = self._r11_block_until.get(b)
        return u is not None and (now is None or now < u)

    def _is_merchant_blocked(self, m: str, now: Optional[float]) -> bool:
        u = self._r12_block_until.get(m)
        return u is not None and (now is None or now < u)

    def is_blocked(self, bin_prefix: str, merchant_id: str, now: Optional[float] = None) -> bool:
        """Blocking policy: traffic of a BIN family with an active R-11 block, or of
        a merchant identity with an active R-12 block, is refused. Blocks expire
        after block_ttl_s."""
        return self._is_bin_blocked(bin_prefix, now) or self._is_merchant_blocked(merchant_id, now)

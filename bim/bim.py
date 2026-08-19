"""
Baseline Integrity Monitor (BIM) — TIG-CDO Component 3

Monitors the BIN-lookup frequency distribution for CSDA Phase 2 (baseline
poisoning) using a one-sided CUSUM control chart on Jensen-Shannon divergence
between the current window's distribution and a week-aligned (same-day-of-week)
reference distribution.

v2 (2026-08-17): replaces the v1 scalar-mean CUSUM (which never computed a JS
divergence and never deseasonalized -- see paper2-solution/review/2026-08-15/
00_CONSOLIDATED_REVIEW.md, finding C6) with what Section IV-E always described:
distributional drift, measured with JS divergence, against a baseline that is
aligned to the matching phase of the weekly cycle rather than "whatever came
immediately before." The week-alignment is not optional decoration: real-data
grounding (Section VII.D-2, calibrate_drift_from_real_data.py against
CESNET-TLS-Year22) found raw day-over-day drift has median 5.39%/day, almost
entirely weekly seasonality, while the deseasonalized (7-day-lag) secular drift
is 0.985%/day. A monitor comparing against yesterday, not against the same
weekday last week, would false-alarm on organic traffic on the large majority
of days -- which is exactly the failure mode this version is built to avoid.

JS-divergence CUSUM formulation:
  C+_t = max(0, C+_{t-1} + (JS_t - mu0 - k))
Only a one-sided (C+) chart is used: JS divergence is non-negative by
construction, so there is no "drift downward" direction to monitor -- a JS
divergence *below* the organic mean is not evidence of anything.

Calibration: k and h are set empirically (Monte Carlo over the organic
scenario, see BIM_CALIBRATION_REPORT.md) rather than solved in closed form,
because JS divergence of a finite-sample categorical distribution does not
have the analytic Gaussian form the old scalar CUSUM's calibrate() assumed.
"""

import logging
import math
import random
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

SECONDS_PER_DAY = 86400.0

# ---------------------------------------------------------------------------
# Monitored statistics
# ---------------------------------------------------------------------------

class BaselineStat(Enum):
    LBMD_FEATURE_CENTROID = "lbmd_feature_centroid"
    BIN_WATCH_ENTROPY = "bin_watch_entropy_baseline"
    ACS_SESSION_UTIL = "acs_session_utilization"
    HPA_POD_COUNT = "hpa_baseline_pod_count"

# ---------------------------------------------------------------------------
# Distribution utilities
# ---------------------------------------------------------------------------

def js_divergence(p: List[float], q: List[float]) -> float:
    """Jensen-Shannon divergence in bits, JS(P,Q) = 0.5*KL(P||M) + 0.5*KL(Q||M),
    M = 0.5*(P+Q). Same formula validated in calibrate_drift_from_real_data.py
    against real CESNET data. Returns a value in [0, 1]."""
    m = [0.5 * (pi + qi) for pi, qi in zip(p, q)]

    def kl(a, b):
        return sum(ai * math.log2(ai / bi) for ai, bi in zip(a, b) if ai > 0)

    return 0.5 * kl(p, m) + 0.5 * kl(q, m)


def zipf_distribution(k: int, s: float) -> List[float]:
    """Zipf(s) distribution over k categories, unnormalized rank 1..k.
    s=0 -> uniform (max entropy); larger s -> more concentrated (lower entropy)."""
    weights = [1.0 / ((i + 1) ** s) for i in range(k)]
    total = sum(weights)
    return [w / total for w in weights]


def shannon_entropy_bits(p: List[float]) -> float:
    return -sum(pi * math.log2(pi) for pi in p if pi > 0)


def zipf_s_for_entropy(k: int, target_entropy_bits: float, tol: float = 1e-4) -> float:
    """Binary search for the Zipf(s) parameter that gives a target entropy
    (bits) over k categories. Monotonic in s, so bisection is exact enough."""
    lo, hi = 0.0, 4.0
    for _ in range(60):
        mid = (lo + hi) / 2.0
        h = shannon_entropy_bits(zipf_distribution(k, mid))
        if h > target_entropy_bits:
            lo = mid
        else:
            hi = mid
        if abs(h - target_entropy_bits) < tol:
            break
    return (lo + hi) / 2.0


def sample_categorical_counts(p: List[float], n: int, rng: random.Random) -> List[float]:
    """Draw n observations from categorical distribution p and return the
    empirical distribution (with Laplace smoothing so JS divergence stays
    finite when a category is unobserved in a finite window)."""
    k = len(p)
    counts = [0] * k
    cum = []
    acc = 0.0
    for pi in p:
        acc += pi
        cum.append(acc)
    for _ in range(n):
        r = rng.random()
        lo, hi = 0, k - 1
        while lo < hi:
            mid = (lo + hi) // 2
            if cum[mid] < r:
                lo = mid + 1
            else:
                hi = mid
        counts[lo] += 1
    alpha = 0.5  # Laplace smoothing
    total = n + alpha * k
    return [(c + alpha) / total for c in counts]

# ---------------------------------------------------------------------------
# Checkpoint storage (unchanged from v1 -- rollback/audit mechanism, not the
# drift-detection mechanism itself)
# ---------------------------------------------------------------------------

@dataclass
class BaselineCheckpoint:
    checkpoint_id: str
    stat: BaselineStat
    timestamp: float
    distribution: List[float]
    sha256: str
    is_validated: bool = True

    @classmethod
    def create(cls, stat: BaselineStat, ts: float, distribution: List[float]) -> "BaselineCheckpoint":
        payload = f"{stat.value}:{ts}:" + ",".join(f"{x:.6f}" for x in distribution)
        sha = hashlib.sha256(payload.encode()).hexdigest()
        return cls(checkpoint_id=sha[:12], stat=stat, timestamp=ts,
                   distribution=distribution, sha256=sha)

# ---------------------------------------------------------------------------
# Week-aligned reference: one distribution per day-of-week, EWMA-updated
# ---------------------------------------------------------------------------

@dataclass
class WeekAlignedReference:
    """Maintains a reference distribution per day-of-week (0=day the monitor
    was initialized, mod 7), so the current window is always compared against
    the matching phase of the weekly cycle rather than the immediately
    preceding window. New weeks blend in via EWMA once a bucket has been
    observed at least once (cold-start: first occurrence of a weekday seeds
    its bucket directly)."""
    k: int
    ewma_alpha: float = 0.35
    buckets: Dict[int, List[float]] = field(default_factory=dict)
    n_updates: Dict[int, int] = field(default_factory=dict)

    def get(self, day_of_week: int, fallback: List[float]) -> List[float]:
        return self.buckets.get(day_of_week, fallback)

    def update(self, day_of_week: int, observed: List[float]):
        if day_of_week not in self.buckets:
            self.buckets[day_of_week] = list(observed)
            self.n_updates[day_of_week] = 1
        else:
            a = self.ewma_alpha
            prev = self.buckets[day_of_week]
            blended = [(1 - a) * p + a * o for p, o in zip(prev, observed)]
            total = sum(blended)
            self.buckets[day_of_week] = [x / total for x in blended]
            self.n_updates[day_of_week] += 1

# ---------------------------------------------------------------------------
# One-sided JS-divergence CUSUM
# ---------------------------------------------------------------------------

@dataclass
class JSCUSUMState:
    stat: BaselineStat
    mu0_js: float            # expected organic JS divergence against the week-aligned reference
    k: float                 # allowance
    h: float                 # decision interval
    c_plus: float = 0.0
    n_updates: int = 0
    alarm_triggered: bool = False
    alarm_timestamp: Optional[float] = None

    def update(self, js_t: float, timestamp: float) -> bool:
        self.c_plus = max(0.0, self.c_plus + (js_t - self.mu0_js - self.k))
        self.n_updates += 1
        if not self.alarm_triggered and self.c_plus > self.h:
            self.alarm_triggered = True
            self.alarm_timestamp = timestamp
            logger.warning(f"BIM ALARM: {self.stat.value} JS-CUSUM C+={self.c_plus:.4f} > h={self.h:.4f}")
            return True
        return False

    def reset(self, new_mu0_js: float):
        self.mu0_js = new_mu0_js
        self.c_plus = 0.0
        self.alarm_triggered = False
        self.alarm_timestamp = None

# ---------------------------------------------------------------------------
# BIM rollback decision (unchanged mechanism from v1)
# ---------------------------------------------------------------------------

class RollbackDecision(Enum):
    POISONING = "poisoning"
    ORGANIC_GROWTH = "organic"
    PENDING = "pending"

@dataclass
class BIMAlarmEvent:
    alarm_id: str
    stat: BaselineStat
    alarm_timestamp: float
    js_divergence: float
    c_plus: float
    drift_rate_per_day: float
    rollback_checkpoint_id: Optional[str] = None
    fs_isac_decision: RollbackDecision = RollbackDecision.PENDING
    resolution_timestamp: Optional[float] = None
    notes: str = ""

# ---------------------------------------------------------------------------
# Baseline Integrity Monitor
# ---------------------------------------------------------------------------

class BaselineIntegrityMonitor:
    """
    Monitors the BIN-lookup frequency distribution using a one-sided
    JS-divergence CUSUM chart against a week-aligned reference. On alarm,
    executes checkpoint rollback and requests FS-ISAC cross-validation
    (unchanged from v1).

    Empirically calibrated (see BIM_CALIBRATION_REPORT.md) so that:
      - organic traffic (with realistic weekday/weekend seasonality) stays
        below h for the large majority of days, and
      - a CSDA-rate distributional drift (~2.8%/day equivalent entropy shift)
        alarms within a few days of onset.
    """

    CHECKPOINT_INTERVAL_S = 7 * SECONDS_PER_DAY
    N_CATEGORIES = 50          # synthetic BIN-bucket cardinality
    WINDOW_SAMPLES = 2000      # observations per daily window (finite-sample noise)

    def __init__(self, seed: int = 42):
        self.cusum_states: Dict[BaselineStat, JSCUSUMState] = {}
        self.checkpoints: Dict[BaselineStat, List[BaselineCheckpoint]] = {s: [] for s in BaselineStat}
        self.alarm_log: List[BIMAlarmEvent] = []
        self.week_ref: Dict[BaselineStat, WeekAlignedReference] = {}
        self._last_checkpoint_ts: Dict[BaselineStat, float] = {}
        self._frozen: Dict[BaselineStat, bool] = {s: False for s in BaselineStat}
        self._rng = random.Random(seed)

    def initialize_stat(self, stat: BaselineStat, mu0_js: float, k: float, h: float,
                         timestamp: float, seed_distribution: List[float]):
        """Initialize the JS-CUSUM and week-aligned reference from a known-clean
        baseline distribution."""
        state = JSCUSUMState(stat=stat, mu0_js=mu0_js, k=k, h=h)
        self.cusum_states[stat] = state
        self.week_ref[stat] = WeekAlignedReference(k=len(seed_distribution))
        # seed all 7 day-of-week buckets from the clean reference so the first
        # week has something to compare against (cold start)
        for dow in range(7):
            self.week_ref[stat].update(dow, seed_distribution)
        cp = BaselineCheckpoint.create(stat, timestamp, seed_distribution)
        self.checkpoints[stat].append(cp)
        self._last_checkpoint_ts[stat] = timestamp
        logger.info(f"BIM initialized {stat.value}: mu0_js={mu0_js:.5f}, k={k:.5f}, h={h:.5f}")

    def observe_distribution(self, stat: BaselineStat, observed_dist: List[float],
                              timestamp: float) -> Optional[BIMAlarmEvent]:
        """Process one day's observed BIN-lookup frequency distribution.
        Compares against the week-aligned reference for this day-of-week,
        updates the JS-CUSUM, and (if not alarmed) rolls the reference forward."""
        if stat not in self.cusum_states:
            logger.warning(f"Stat {stat.value} not initialized")
            return None
        if self._frozen.get(stat, False):
            logger.debug(f"BIM frozen for {stat.value}; ignoring observation")
            return None

        day_of_week = int(timestamp // SECONDS_PER_DAY) % 7
        ref = self.week_ref[stat]
        reference_dist = ref.get(day_of_week, observed_dist)
        js_t = js_divergence(observed_dist, reference_dist)

        state = self.cusum_states[stat]
        alarm = state.update(js_t, timestamp)

        if not alarm:
            # only roll the reference forward on non-alarming observations,
            # so a poisoning attack doesn't poison its own baseline mid-attack
            ref.update(day_of_week, observed_dist)

        if timestamp - self._last_checkpoint_ts.get(stat, 0) >= self.CHECKPOINT_INTERVAL_S:
            if not state.alarm_triggered:
                cp = BaselineCheckpoint.create(stat, timestamp, observed_dist)
                self.checkpoints[stat].append(cp)
                self._last_checkpoint_ts[stat] = timestamp

        if alarm:
            return self._handle_alarm(stat, state, timestamp, js_t, observed_dist)
        return None

    def _handle_alarm(self, stat: BaselineStat, state: JSCUSUMState, timestamp: float,
                       js_t: float, observed_dist: List[float]) -> BIMAlarmEvent:
        cps = self.checkpoints[stat]
        rollback_cp = cps[-1] if cps else None
        elapsed_days = 1.0
        if rollback_cp:
            elapsed_days = max((timestamp - rollback_cp.timestamp) / SECONDS_PER_DAY, 1.0)
        # drift rate reported as JS-divergence-per-day above the calibrated
        # organic mean, normalized the same way the v1 scalar metric was
        # ("%/day"): (js_t - mu0_js) / mu0_js / elapsed_days.
        drift_rate = ((js_t - state.mu0_js) / state.mu0_js / elapsed_days) if state.mu0_js > 0 else 0.0

        self._frozen[stat] = True
        logger.warning(f"BIM: FREEZING {stat.value} retraining (JS={js_t:.5f}, drift={drift_rate*100:.2f}%/day-equiv)")

        alarm_id = f"BIM-{stat.value[:8]}-{int(timestamp)}"
        event = BIMAlarmEvent(
            alarm_id=alarm_id, stat=stat, alarm_timestamp=timestamp,
            js_divergence=js_t, c_plus=state.c_plus, drift_rate_per_day=drift_rate,
            rollback_checkpoint_id=rollback_cp.checkpoint_id if rollback_cp else None,
        )
        self.alarm_log.append(event)

        decision = self._fsisac_cross_validate(drift_rate)
        event.fs_isac_decision = decision
        event.resolution_timestamp = timestamp + 300

        if decision == RollbackDecision.POISONING:
            event.notes = (f"FS-ISAC: peer baseline stable. Drift is institution-specific. "
                           f"Rolling back to checkpoint {event.rollback_checkpoint_id}.")
            self._execute_rollback(stat, rollback_cp)
        else:
            event.notes = "FS-ISAC: sector-wide drift observed. Accepting new baseline (organic growth)."
            self._accept_new_baseline(stat, observed_dist, timestamp)
        return event

    def _fsisac_cross_validate(self, drift_rate: float) -> RollbackDecision:
        """Mock FS-ISAC cross-validation (Section V-D). Heuristic unchanged
        from v1: sustained upward drift above the calibrated threshold with no
        peer corroboration reads as institution-specific poisoning."""
        if drift_rate > 0.023:
            return RollbackDecision.POISONING
        return RollbackDecision.ORGANIC_GROWTH

    def _execute_rollback(self, stat: BaselineStat, checkpoint: Optional[BaselineCheckpoint]):
        if checkpoint is None:
            logger.error(f"No checkpoint to roll back to for {stat.value}")
            return
        state = self.cusum_states[stat]
        state.reset(state.mu0_js)
        self._frozen[stat] = False
        logger.info(f"BIM: Rolled back {stat.value} to checkpoint {checkpoint.checkpoint_id}")

    def _accept_new_baseline(self, stat: BaselineStat, observed_dist: List[float], ts: float):
        state = self.cusum_states[stat]
        state.reset(state.mu0_js)
        cp = BaselineCheckpoint.create(stat, ts, observed_dist)
        self.checkpoints[stat].append(cp)
        self._last_checkpoint_ts[stat] = ts
        self._frozen[stat] = False

    def summary(self) -> Dict:
        return {
            "monitored_stats": len(self.cusum_states),
            "total_alarms": len(self.alarm_log),
            "poisoning_detected": sum(1 for e in self.alarm_log if e.fs_isac_decision == RollbackDecision.POISONING),
            "organic_accepted": sum(1 for e in self.alarm_log if e.fs_isac_decision == RollbackDecision.ORGANIC_GROWTH),
        }

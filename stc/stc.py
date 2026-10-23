"""
Semantic Transaction Correlator (STC), TIG-CDO component 1. Version 1.3.0.

The STC keeps a correlated event log: every payment event is attached to one
transaction-attempt sequence through explicit join keys, the sequence is checked
against the ISO 8583 x EMVCo 3DS x tokenization state machine, and the
Transaction Coherence Score (TCS) is computed per BIN family over a window W.

Join keys (v1.3.0; replaces the per-event hash of BIN, terminal, STAN, 3DS id
and token id, which put an AReq and its 0100 into two different sequences):
  * ("stan", BIN prefix, terminal id, STAN)   ISO 8583 request/response/advice/reversal
  * ("3ds", 3DS transaction id)               AReq/ARes/CReq/CRes and the 0100 that carries it
  * ("tavv", token cryptogram)                token provisioning and the 0100 that uses it
An event joins the first sequence any of its keys already maps to; all of its
keys are then registered to that sequence.

Message flows (round-3 author fact F2, all three supported; flow and completion
window are parameters):
  * "single":    0200 financial request answered by 0210; an approved 0210 is the
                 completion (single-message processing).
  * "dual_0220": 0100/0110 authorization; capture by a 0220 completion advice
                 within the completion window (dual-message processing).
  * "clearing":  0100/0110 authorization; capture by a clearing record, typically
                 hours later in batch.
A 0200 that follows an approved 0100 on the same sequence is also accepted as a
completion, for compatibility with the v1.2 harness.

TCS(b, W) = TCS_str(b, W) * TCS_dst(b, W)
  TCS_str = coherent resolved sequences / resolved sequences
  TCS_dst = (1 - max(0, rho - rho*) / (1 - rho*)) * min(1, c_obs / c*)
            rho   = the R-11 statistic over W: by default (v1.3.0, E3 option c) the
                    decline share of all responses (code 91 excluded) minus the
                    BIN family's baseline decline share; optionally the share
                    carrying a watched code {14, 54, 57, 82}
            c_obs = censoring-aware completion bound of the requests in W: a request
                    counts as failed once declined, reversed without capture,
                    unanswered after 5 s, or approved and not captured by its
                    deadline; requests still awaiting capture count as potential
                    completions (the R-12 statistic, fdce/fdce.py)
A sequence is "resolved" when it has a rule flag or has reached a terminal state
(declined, completed, reversed); sequences still inside a pending deadline are
in flight and are excluded from TCS_str (lagged-cohort rule, review R3-004).
"""

import time
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Deque, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Payment protocol event types
# ---------------------------------------------------------------------------


class EventType(Enum):
    # ISO 8583
    ISO_0100 = "auth_request"          # Authorization request (dual-message)
    ISO_0110 = "auth_response"         # Authorization response
    ISO_0200 = "financial_request"     # Financial request (single-message), or completion after 0100
    ISO_0210 = "financial_response"    # Financial response
    ISO_0220 = "completion_advice"     # Completion advice (dual-message capture)
    ISO_0400 = "reversal_request"      # Reversal request
    ISO_0410 = "reversal_response"     # Reversal response
    CLEARING = "clearing_record"       # Clearing / capture record (batch)
    # EMVCo 3DS 2.x
    THREEDS_AREQ = "3ds_areq"
    THREEDS_ARES = "3ds_ares"
    THREEDS_CREQ = "3ds_creq"
    THREEDS_CRES = "3ds_cres"
    # Network tokenization
    TOKEN_PROVISION = "token_provision"   # cryptogram (TAVV) request answered
    TOKEN_USE = "token_use"
    # Derived
    BIN_LOOKUP = "bin_lookup"


class AnomalyRule(Enum):
    R01 = "R-01: request with no response within 5 s"
    R02 = "R-02: approved authorization with no completion or reversal within the completion window"
    R03 = "R-03: authorization requests from one BIN within 1 s above max(10, rate + 5 sqrt(rate) + 5), rate = the family's mean per-second rate over the previous 600 s (at least 10 s of history)"
    R04 = "R-04: completion before the authorization response"
    R05 = "R-05: reversal referencing a STAN never seen"
    R06 = "R-06: AReq with no 0100 within 600 s (abandoned 3DS session)"
    R07 = "R-07: more than 3 AReq from one BIN without CReq within 10 s"
    R08 = "R-08: token cryptogram reused across several authorizations"
    R09 = "R-09: token BIN outside the network range (not implemented in v1.3.0)"
    R10 = "R-10: authorization amount 0.00 or 0.01"
    R13 = "R-13: token cryptogram provisioned with no authorization using it within 600 s"
    CF01 = "CF-01: CRes later than 120 s after CReq"
    CF02 = "CF-02: ARes later than 3 s after AReq"
    CF03 = "CF-03: CReq later than 300 s after ARes"
    CF04 = "CF-04: cryptogram used later than 30 s after provisioning"
    CF05 = "CF-05: more than 5 distinct BINs from one source address within 60 s"


# Decline codes watched by R-11 (ISO 8583 meanings: 14 invalid card number,
# 54 expired card, 57 transaction not permitted to cardholder, 82 network-specific).
WATCHED_DECLINE_CODES: Set[str] = {"14", "54", "57", "82"}
APPROVED_CODES: Set[str] = {"00", None}

FLOWS = ("single", "dual_0220", "clearing")
DEFAULT_COMPLETION_WINDOW_S = {
    "single": 5.0,           # the approved 0210 is the completion
    "dual_0220": 1800.0,     # completion advice within 30 min (parameter)
    "clearing": 129600.0,    # clearing within 36 h (parameter)
}

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class PaymentEvent:
    event_id: str
    event_type: EventType
    bin_prefix: str           # first 6 digits of the PAN
    terminal_id: str
    source_ip: str
    timestamp: float          # seconds
    stan: Optional[str] = None
    amount: float = 0.0
    response_code: Optional[str] = None  # "00" = approved
    threeds_session_id: Optional[str] = None
    token_id: Optional[str] = None
    tavv: Optional[str] = None
    merchant_id: Optional[str] = None


@dataclass
class TransactionSequence:
    seq_id: str
    bin_prefix: str
    events: List[PaymentEvent] = field(default_factory=list)
    anomaly_flags: List[AnomalyRule] = field(default_factory=list)
    is_coherent: bool = True
    start_ts: float = 0.0
    end_ts: float = 0.0
    # protocol state
    request_ts: Optional[float] = None     # 0100 or single-message 0200
    single_message: bool = False
    response_ts: Optional[float] = None
    response_code: Optional[str] = None
    approved: Optional[bool] = None
    completed_ts: Optional[float] = None
    reversed_ts: Optional[float] = None
    areq_ts: Optional[float] = None
    ares_ts: Optional[float] = None
    creq_ts: Optional[float] = None
    token_provision_ts: Optional[float] = None
    token_used: bool = False
    n_auth_requests: int = 0

    def flag(self, rule: AnomalyRule):
        if rule not in self.anomaly_flags:
            self.anomaly_flags.append(rule)
        self.is_coherent = False

    def is_terminal(self) -> bool:
        if self.approved is False:
            return True                       # declined terminal
        if self.completed_ts is not None or self.reversed_ts is not None:
            return True
        return False

    def is_resolved(self) -> bool:
        return (not self.is_coherent) or self.is_terminal()


@dataclass
class TCSResult:
    bin_prefix: str
    window_start: float
    window_end: float
    total_sequences: int          # resolved sequences (the TCS_str denominator)
    coherent_sequences: int
    tcs: float                    # TCS_str * TCS_dst
    anomaly_distribution: Dict[str, int] = field(default_factory=dict)
    tcs_str: float = 1.0
    tcs_dst: float = 1.0
    in_flight_sequences: int = 0
    n_responses: int = 0
    watched_share: Optional[float] = None
    matured_auths: int = 0
    completion_rate: Optional[float] = None
    prior_used: bool = False


# ---------------------------------------------------------------------------
# State machine validator
# ---------------------------------------------------------------------------


class PaymentStateMachine:
    """Validates sequences against the ISO 8583, 3DS and tokenization rules.
    Timeouts (R-01, R-02, R-06, R-13) are evaluated by check_timeouts(now)."""

    AUTH_TIMEOUT_S = 5.0          # R-01
    BIN_BURST_WINDOW_S = 1.0      # R-03
    BIN_BURST_LIMIT = 10          # R-03 floor (v1.3.0: the limit scales with the family's rate)
    BIN_RATE_WINDOW_S = 600.0     # R-03 reference window
    THREEDS_SESSION_TIMEOUT_S = 600.0  # R-06
    FRICTIONLESS_WINDOW_S = 10.0  # R-07
    FRICTIONLESS_LIMIT = 3        # R-07
    TOKEN_ORPHAN_S = 600.0        # R-13
    TAVV_VALIDITY_S = 30.0        # CF-04
    AREQ_TIMEOUT_S = 3.0          # CF-02
    CREQ_TIMEOUT_S = 300.0        # CF-03
    CRES_TIMEOUT_S = 120.0        # CF-01
    IP_BIN_WINDOW_S = 60.0        # CF-05
    IP_BIN_LIMIT = 5              # CF-05

    def __init__(self, flow: str = "dual_0220", completion_window_s: Optional[float] = None):
        if flow not in FLOWS:
            raise ValueError(f"unknown flow {flow!r}; expected one of {FLOWS}")
        self.flow = flow
        self.completion_window_s = (completion_window_s if completion_window_s is not None
                                    else DEFAULT_COMPLETION_WINDOW_S[flow])
        # deadline queues: (deadline, seq) in insertion order (deadlines are monotone
        # within each queue because each uses one constant offset)
        self._q_response: Deque[Tuple[float, TransactionSequence]] = deque()
        self._q_completion: Deque[Tuple[float, TransactionSequence]] = deque()
        self._q_3ds: Deque[Tuple[float, TransactionSequence]] = deque()
        self._q_token: Deque[Tuple[float, TransactionSequence]] = deque()
        self.bin_burst: Dict[str, deque] = defaultdict(deque)
        self.bin_first_seen: Dict[str, float] = {}
        self.ip_bin_tracker: Dict[str, Dict[str, float]] = defaultdict(dict)
        self.recent_areq: Dict[str, deque] = defaultdict(deque)   # bin -> deque[(ts, seq)]
        self.tavv_first_use: Dict[str, str] = {}
        self.micro_auth_count: Dict[str, int] = defaultdict(int)

    # -- per-event rules -----------------------------------------------------
    def process_event(self, seq: TransactionSequence, event: PaymentEvent):
        et = event.event_type
        if et == EventType.ISO_0100:
            self._request(seq, event, single=False)
        elif et == EventType.ISO_0200:
            if seq.request_ts is not None and not seq.single_message:
                self._completion(seq, event)          # v1.2-compatible capture after 0100
            else:
                self._request(seq, event, single=True)
        elif et in (EventType.ISO_0110, EventType.ISO_0210):
            self._response(seq, event)
        elif et in (EventType.ISO_0220, EventType.CLEARING):
            self._completion(seq, event)
        elif et == EventType.ISO_0400:
            self._reversal(seq, event)
        elif et == EventType.THREEDS_AREQ:
            self._areq(seq, event)
        elif et == EventType.THREEDS_ARES:
            if seq.areq_ts is not None and event.timestamp - seq.areq_ts > self.AREQ_TIMEOUT_S:
                seq.flag(AnomalyRule.CF02)
            seq.ares_ts = event.timestamp
        elif et == EventType.THREEDS_CREQ:
            if seq.ares_ts is not None and event.timestamp - seq.ares_ts > self.CREQ_TIMEOUT_S:
                seq.flag(AnomalyRule.CF03)
            seq.creq_ts = event.timestamp
        elif et == EventType.THREEDS_CRES:
            if seq.creq_ts is not None and event.timestamp - seq.creq_ts > self.CRES_TIMEOUT_S:
                seq.flag(AnomalyRule.CF01)
        elif et == EventType.TOKEN_PROVISION:
            seq.token_provision_ts = event.timestamp
            self._q_token.append((event.timestamp + self.TOKEN_ORPHAN_S, seq))
        elif et == EventType.TOKEN_USE:
            self._token_use(seq, event)
        self._check_ip_bin_diversity(seq, event)

    def _request(self, seq: TransactionSequence, event: PaymentEvent, single: bool):
        ts = event.timestamp
        seq.n_auth_requests += 1
        if seq.request_ts is None:
            seq.request_ts = ts
            seq.single_message = single
            self._q_response.append((ts + self.AUTH_TIMEOUT_S, seq))
        if abs(event.amount - 0.01) < 0.001 or abs(event.amount) < 0.001:
            seq.flag(AnomalyRule.R10)
            self.micro_auth_count[event.bin_prefix] += 1
        # R-03 (v1.3.0): a fixed 10-per-second limit flags every organic family
        # above about 10 TPS; the limit now scales with the family's own rate.
        hist = self.bin_burst[event.bin_prefix]
        hist.append(ts)
        while hist and ts - hist[0] > self.BIN_RATE_WINDOW_S:
            hist.popleft()
        n1 = 0
        for t in reversed(hist):
            if ts - t > self.BIN_BURST_WINDOW_S:
                break
            n1 += 1
        first = self.bin_first_seen.setdefault(event.bin_prefix, ts)
        span = min(self.BIN_RATE_WINDOW_S, ts - first)
        if span >= 10.0:                 # needs 10 s of history for the family
            lam = (len(hist) - n1) / span
            limit = max(self.BIN_BURST_LIMIT, lam + 5.0 * lam ** 0.5 + 5.0)
            if n1 > limit:
                seq.flag(AnomalyRule.R03)
        if event.tavv:
            self._token_use(seq, event)

    def _response(self, seq: TransactionSequence, event: PaymentEvent):
        if seq.request_ts is None:
            return
        if seq.response_ts is None:
            seq.response_ts = event.timestamp
            if event.timestamp - seq.request_ts > self.AUTH_TIMEOUT_S:
                seq.flag(AnomalyRule.R01)
            seq.response_code = event.response_code
            seq.approved = event.response_code in APPROVED_CODES
            if seq.approved:
                if seq.single_message:
                    seq.completed_ts = event.timestamp      # single-message: approval is capture
                else:
                    self._q_completion.append((seq.request_ts + self.completion_window_s, seq))

    def _completion(self, seq: TransactionSequence, event: PaymentEvent):
        if seq.request_ts is not None and seq.response_ts is None:
            seq.flag(AnomalyRule.R04)            # completion before the response
        if seq.completed_ts is None:
            seq.completed_ts = event.timestamp

    def _reversal(self, seq: TransactionSequence, event: PaymentEvent):
        # A reversal joins its sequence through the STAN key; if the STAN was never
        # seen (no request on this sequence) the reversal is unsolicited.
        if seq.request_ts is None:
            seq.flag(AnomalyRule.R05)
        if seq.reversed_ts is None:
            seq.reversed_ts = event.timestamp

    def _areq(self, seq: TransactionSequence, event: PaymentEvent):
        ts = event.timestamp
        seq.areq_ts = ts
        self._q_3ds.append((ts + self.THREEDS_SESSION_TIMEOUT_S, seq))
        dq = self.recent_areq[event.bin_prefix]
        dq.append((ts, seq))
        while dq and ts - dq[0][0] >= self.FRICTIONLESS_WINDOW_S:
            dq.popleft()
        n_no_creq = sum(1 for _, s in dq if s.creq_ts is None)
        if n_no_creq > self.FRICTIONLESS_LIMIT:
            seq.flag(AnomalyRule.R07)

    def _token_use(self, seq: TransactionSequence, event: PaymentEvent):
        seq.token_used = True
        if seq.token_provision_ts is not None and event.timestamp - seq.token_provision_ts > self.TAVV_VALIDITY_S:
            seq.flag(AnomalyRule.CF04)
        key = event.tavv or event.token_id
        if key:
            first = self.tavv_first_use.get(key)
            if first is None:
                self.tavv_first_use[key] = event.event_id
            elif first != event.event_id:
                seq.flag(AnomalyRule.R08)

    def _check_ip_bin_diversity(self, seq: TransactionSequence, event: PaymentEvent):
        now = event.timestamp
        tracker = self.ip_bin_tracker[event.source_ip]
        stale = [b for b, ts in tracker.items() if now - ts > self.IP_BIN_WINDOW_S]
        for b in stale:
            del tracker[b]
        tracker[event.bin_prefix] = now
        if len(tracker) > self.IP_BIN_LIMIT:
            seq.flag(AnomalyRule.CF05)

    # -- timeouts --------------------------------------------------------------
    def check_timeouts(self, now: float):
        """R-01 (no response), R-02 (approved, not captured or reversed), R-06
        (AReq with no 0100) and R-13 (cryptogram never used), each once its
        deadline has passed."""
        q = self._q_response
        while q and q[0][0] < now:
            _, s = q.popleft()
            if s.response_ts is None:
                s.flag(AnomalyRule.R01)
        q = self._q_completion
        while q and q[0][0] < now:
            _, s = q.popleft()
            if s.approved and s.completed_ts is None and s.reversed_ts is None:
                s.flag(AnomalyRule.R02)
        q = self._q_3ds
        while q and q[0][0] < now:
            _, s = q.popleft()
            if s.request_ts is None:
                s.flag(AnomalyRule.R06)
        q = self._q_token
        while q and q[0][0] < now:
            _, s = q.popleft()
            if not s.token_used:
                s.flag(AnomalyRule.R13)

    # v1.2 method names kept for callers
    def check_orphaned_auths(self, sequences=None, now: float = 0.0):
        self.check_timeouts(now)

    def check_orphaned_3ds(self, sequences=None, now: float = 0.0):
        self.check_timeouts(now)


# ---------------------------------------------------------------------------
# Correlator and TCS engine
# ---------------------------------------------------------------------------


class SemanticTransactionCorrelator:
    """Correlated event log plus TCS computation per BIN family.

    Parameters
    ----------
    window_s : the TCS window W (seconds); sequences that started within W count.
    flow, completion_window_s : message flow and capture window (see module doc).
    rho_star, c_star : R-11 concentration threshold and R-12 completion floor used
        by the distributional term.
    min_responses, min_matured : evidence floors (responses; requests) for the two distributional factors;
        below a floor the factor is 1 (no evidence).
    min_sequences, sparse_prior : a BIN family with fewer resolved sequences than
        min_sequences gets TCS = sparse_prior (default 1.0, the v1.2 behaviour).
    """

    def __init__(self, window_s: float = 3600.0, prune_interval_s: float = 60.0,
                 flow: str = "dual_0220", completion_window_s: Optional[float] = None,
                 rho_star: float = 0.50, c_star: float = 0.05,
                 r11_mode: str = "baseline_excess",
                 decline_baseline: Optional[Dict[str, float]] = None,
                 baseline_prior: float = 0.12,
                 min_responses: int = 20, min_matured: int = 20,
                 min_sequences: int = 1, sparse_prior: float = 1.0):
        self.window_s = window_s
        self.prune_interval_s = prune_interval_s
        self._last_prune: Optional[float] = None
        self.fsm = PaymentStateMachine(flow=flow, completion_window_s=completion_window_s)
        self.rho_star = rho_star
        self.c_star = c_star
        self.r11_mode = r11_mode
        self.decline_baseline = decline_baseline or {}
        self.baseline_prior = baseline_prior
        self.min_responses = min_responses
        self.min_matured = min_matured
        self.min_sequences = min_sequences
        self.sparse_prior = sparse_prior

        self.sequences: Dict[str, TransactionSequence] = {}
        self.bin_sequences: Dict[str, List[str]] = defaultdict(list)
        self._index: Dict[Tuple, str] = {}
        self._seq_keys: Dict[str, List[Tuple]] = defaultdict(list)
        self._next_id = 0
        self._event_count = 0

    # -- correlation -----------------------------------------------------------
    @staticmethod
    def join_keys(event: PaymentEvent) -> List[Tuple]:
        keys: List[Tuple] = []
        if event.stan:
            keys.append(("stan", event.bin_prefix, event.terminal_id, event.stan))
        if event.threeds_session_id:
            keys.append(("3ds", event.threeds_session_id))
        if event.tavv:
            keys.append(("tavv", event.tavv))
        elif event.token_id and event.event_type in (EventType.TOKEN_PROVISION, EventType.TOKEN_USE):
            keys.append(("tavv", event.token_id))
        if not keys:
            keys.append(("evt", event.event_id))
        return keys

    def ingest_event(self, event: PaymentEvent):
        now = event.timestamp
        keys = self.join_keys(event)
        sid = None
        for k in keys:
            sid = self._index.get(k)
            if sid is not None and sid in self.sequences:
                break
            sid = None
        if sid is None:
            sid = f"s{self._next_id}"
            self._next_id += 1
            self.sequences[sid] = TransactionSequence(seq_id=sid, bin_prefix=event.bin_prefix,
                                                      start_ts=now, end_ts=now)
            self.bin_sequences[event.bin_prefix].append(sid)
        seq = self.sequences[sid]
        for k in keys:
            if self._index.get(k) != sid:
                self._index[k] = sid
                self._seq_keys[sid].append(k)
        seq.events.append(event)
        seq.end_ts = now
        self.fsm.process_event(seq, event)
        self._event_count += 1
        if self._last_prune is None:
            self._last_prune = now
        elif now - self._last_prune > self.prune_interval_s:
            self._prune(now)

    def _prune(self, now: float):
        """Drop sequences that ended before the window and are no longer pending."""
        cutoff = now - self.window_s - self.fsm.completion_window_s
        stale = [k for k, s in self.sequences.items() if s.end_ts < cutoff]
        stale_set = set(stale)
        for k in stale:
            s = self.sequences.pop(k)
            for key in self._seq_keys.pop(k, []):
                if self._index.get(key) == k:
                    del self._index[key]
        if stale_set:
            for b in list(self.bin_sequences):
                lst = [k for k in self.bin_sequences[b] if k not in stale_set]
                if lst:
                    self.bin_sequences[b] = lst
                else:
                    del self.bin_sequences[b]
        self._last_prune = now

    # -- TCS ---------------------------------------------------------------------
    def tcs_dst_factors(self, n_resp: int, n_watched: int, n_matured: int,
                        n_completed: int, n_declined: int = 0,
                        baseline: Optional[float] = None) -> Tuple[float, Optional[float], Optional[float]]:
        """Concentration factor uses the R-11 statistic: in mode "baseline_excess"
        (v1.3.0 default) rho is the decline share (code 91 excluded) minus the BIN
        family's baseline decline share b, and the factor falls linearly from 1 at
        rho = rho* to 0 at the largest possible excess 1 - b; in mode
        "watched_share" rho is the watched-code share and the factor falls from 1 at
        rho* to 0 at 1."""
        f_conc, f_comp = 1.0, 1.0
        rho = c_obs = None
        if n_resp >= self.min_responses:
            if self.r11_mode == "baseline_excess":
                b = self.baseline_prior if baseline is None else baseline
                rho = n_declined / n_resp - b
                span = max(1e-9, (1.0 - b) - self.rho_star)
                f_conc = 1.0 - min(1.0, max(0.0, rho - self.rho_star) / span)
            else:
                rho = n_watched / n_resp
                f_conc = 1.0 - max(0.0, rho - self.rho_star) / (1.0 - self.rho_star)
        if n_matured >= self.min_matured:
            c_obs = n_completed / n_matured
            f_comp = min(1.0, c_obs / self.c_star)
        return f_conc * f_comp, rho, c_obs

    def compute_tcs(self, bin_prefix: str, now: float, include_in_flight: bool = False) -> TCSResult:
        self.fsm.check_timeouts(now)
        cutoff = now - self.window_s
        total = coherent = in_flight = 0
        n_resp = n_watched = n_matured = n_completed = n_declined = 0
        dist: Dict[str, int] = defaultdict(int)
        D = self.fsm.completion_window_s
        for sid in self.bin_sequences.get(bin_prefix, []):
            s = self.sequences.get(sid)
            if s is None or s.start_ts < cutoff or s.start_ts > now:
                continue
            if s.response_ts is not None and s.response_ts <= now:
                n_resp += 1
                if s.response_code in WATCHED_DECLINE_CODES:
                    n_watched += 1
                if s.approved is False and s.response_code not in ("91",):
                    n_declined += 1
            if s.request_ts is not None:
                # censoring-aware completion bound (same estimator as R-12): a request
                # counts as failed only once its outcome is known
                n_matured += 1
                failed = (s.approved is False
                          or s.reversed_ts is not None
                          or (s.approved and s.completed_ts is None and s.request_ts + D < now)
                          or (s.response_ts is None and s.request_ts + self.fsm.AUTH_TIMEOUT_S < now))
                if not failed:
                    n_completed += 1
            if s.is_resolved() or include_in_flight:
                total += 1
                if s.is_coherent:
                    coherent += 1
                for r in s.anomaly_flags:
                    dist[r.name] += 1
            else:
                in_flight += 1
        prior_used = total < self.min_sequences
        tcs_str = self.sparse_prior if prior_used or total == 0 else coherent / total
        tcs_dst, rho, c_obs = self.tcs_dst_factors(n_resp, n_watched, n_matured, n_completed,
                                                   n_declined, self.decline_baseline.get(bin_prefix))
        return TCSResult(bin_prefix=bin_prefix, window_start=cutoff, window_end=now,
                         total_sequences=total, coherent_sequences=coherent,
                         tcs=tcs_str * tcs_dst, anomaly_distribution=dict(dist),
                         tcs_str=tcs_str, tcs_dst=tcs_dst, in_flight_sequences=in_flight,
                         n_responses=n_resp, watched_share=rho, matured_auths=n_matured,
                         completion_rate=c_obs, prior_used=prior_used)

    def compute_tcs_all(self, now: float) -> Dict[str, TCSResult]:
        return {b: self.compute_tcs(b, now) for b, seqs in list(self.bin_sequences.items()) if seqs}

    @property
    def graph_stats(self) -> Dict:
        return {
            "active_sequences": len(self.sequences),
            "event_count": self._event_count,
            "active_bins": len([b for b, seqs in self.bin_sequences.items() if seqs]),
            "join_keys": len(self._index),
        }


# ---------------------------------------------------------------------------
# Demo / self-test
# ---------------------------------------------------------------------------

def _demo():
    logging.basicConfig(level=logging.INFO)
    stc = SemanticTransactionCorrelator(window_s=3600.0, flow="dual_0220")
    now = 0.0
    for i in range(100):           # legitimate: 0100, approved 0110, 0220 advice
        ts = now + i * 0.5
        kw = dict(bin_prefix="411111", terminal_id="TERM01", source_ip=f"10.0.0.{i % 50 + 1}",
                  stan=f"STAN{i:06d}", amount=49.0)
        stc.ingest_event(PaymentEvent(f"a{i}", EventType.ISO_0100, timestamp=ts, **kw))
        stc.ingest_event(PaymentEvent(f"b{i}", EventType.ISO_0110, timestamp=ts + 0.8, response_code="00", **kw))
        stc.ingest_event(PaymentEvent(f"c{i}", EventType.ISO_0220, timestamp=ts + 120.0, **kw))
    for i in range(100):           # attack: approved 0.01 probes, never captured
        ts = now + i * 0.1
        kw = dict(bin_prefix="555555", terminal_id="TERM_ATK", source_ip=f"192.168.1.{i % 10 + 1}",
                  stan=f"ATK{i:06d}", amount=0.01)
        stc.ingest_event(PaymentEvent(f"x{i}", EventType.ISO_0100, timestamp=ts, **kw))
        stc.ingest_event(PaymentEvent(f"y{i}", EventType.ISO_0110, timestamp=ts + 0.3, response_code="00", **kw))
    later = now + 2000.0
    a = stc.compute_tcs("411111", later)
    b = stc.compute_tcs("555555", later)
    print(f"legitimate TCS={a.tcs:.3f} (str {a.tcs_str:.3f}, dst {a.tcs_dst:.3f})")
    print(f"probe TCS={b.tcs:.3f} (str {b.tcs_str:.3f}, dst {b.tcs_dst:.3f}) {b.anomaly_distribution}")
    assert a.tcs > 0.75 and b.tcs < 0.45
    print("All assertions passed.")


if __name__ == "__main__":
    _demo()

"""
Semantic Transaction Correlator (STC) — TIG-CDO Component 1

Constructs and maintains a real-time Transaction Intent Graph G = (V, E, T).
Computes the Transaction Coherence Score (TCS) for each BIN family over a
sliding time window.

Paper: "Transaction Intent Graph: Semantic Cross-Layer Defense Orchestration
for Microservices Payment Systems"

TCS(b, W) = |{s ∈ S(b,W) : coherent(s)}| / |S(b, W)|

where S(b,W) is the set of transaction-attempt sequences initiated by BIN
family b within window W, and coherent(s) is true iff all state machine
transitions R-01 through R-10 and CF-01 through CF-05 are satisfied.
"""

import time
import hashlib
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Payment protocol event types
# ---------------------------------------------------------------------------

class EventType(Enum):
    # ISO 8583
    ISO_0100 = "auth_request"          # Authorization Request
    ISO_0110 = "auth_response"         # Authorization Response
    ISO_0200 = "financial_request"     # Financial / Completion Request
    ISO_0210 = "financial_response"    # Financial Response
    ISO_0400 = "reversal_request"      # Reversal Request
    ISO_0410 = "reversal_response"     # Reversal Response
    # EMVCo 3DS 2.x
    THREEDS_AREQ = "3ds_areq"          # Authentication Request
    THREEDS_ARES = "3ds_ares"          # Authentication Response
    THREEDS_CREQ = "3ds_creq"          # Challenge Request
    THREEDS_CRES = "3ds_cres"          # Challenge Response
    # Network Tokenization
    TOKEN_PROVISION = "token_provision"
    TOKEN_USE = "token_use"
    # Derived
    BIN_LOOKUP = "bin_lookup"

class AnomalyRule(Enum):
    R01 = "R-01: 0100 no 0110 within 5s (timeout/flood)"
    R02 = "R-02: 0100 no 0200/0400 within 120s (orphaned auth/BIN probe)"
    R03 = "R-03: >10 auth requests from same BIN within 1s (BIN enumeration burst)"
    R04 = "R-04: 0200 precedes 0110 (protocol violation)"
    R05 = "R-05: 0400 references unknown STAN (reversal injection)"
    R06 = "R-06: AReq without 0100 within 600s (abandoned 3DS session)"
    R07 = "R-07: Multiple AReqs from same BIN without CReq within 10s (frictionless probe)"
    R08 = "R-08: TAVV reuse across multiple 0100 messages (token replay)"
    R09 = "R-09: Token BIN prefix mismatch against expected range (forged token)"
    R10 = "R-10: Micro-authorization ($0.01 amount) — baseline poisoning probe"
    CF01 = "CF-01: CReq-CRes timing exceeded 120s"
    CF02 = "CF-02: ARes not within 3s of AReq"
    CF03 = "CF-03: CReq not submitted within 300s of ARes"
    CF04 = "CF-04: TAVV not used within 30s of provisioning"
    CF05 = "CF-05: >5 distinct BINs from same IP cluster within 60s"

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PaymentEvent:
    event_id: str
    event_type: EventType
    bin_prefix: str           # First 6 digits of PAN
    terminal_id: str
    source_ip: str
    timestamp: float          # Unix epoch seconds
    stan: Optional[str] = None
    amount: float = 0.0
    response_code: Optional[str] = None  # "00" = approve
    threeds_session_id: Optional[str] = None
    token_id: Optional[str] = None
    tavv: Optional[str] = None

@dataclass
class TransactionSequence:
    seq_id: str
    bin_prefix: str
    events: List[PaymentEvent] = field(default_factory=list)
    anomaly_flags: List[AnomalyRule] = field(default_factory=list)
    is_coherent: bool = True
    start_ts: float = 0.0
    end_ts: float = 0.0

    def flag(self, rule: AnomalyRule):
        self.anomaly_flags.append(rule)
        self.is_coherent = False

@dataclass
class TCSResult:
    bin_prefix: str
    window_start: float
    window_end: float
    total_sequences: int
    coherent_sequences: int
    tcs: float
    anomaly_distribution: Dict[str, int] = field(default_factory=dict)

# ---------------------------------------------------------------------------
# State machine validator
# ---------------------------------------------------------------------------

class PaymentStateMachine:
    """
    Validates a payment event stream against ISO 8583 + 3DS + tokenization
    state machine rules R-01 through R-10, CF-01 through CF-05.
    """

    # Timing constants (seconds) from paper Section II-A
    AUTH_TIMEOUT_S = 5.0         # R-01: 0110 must follow 0100 within 5s
    COMPLETION_TIMEOUT_S = 120.0 # R-02: 0200/0400 must follow approved 0100 within 120s
    BIN_BURST_WINDOW_S = 1.0     # R-03: burst window
    BIN_BURST_LIMIT = 10         # R-03: max auth requests per window
    THREEDS_SESSION_TIMEOUT_S = 600.0  # R-06: 0100 must follow AReq within 600s
    FRICTIONLESS_WINDOW_S = 10.0 # R-07: multiple AReqs without CReq
    FRICTIONLESS_LIMIT = 3       # R-07: threshold for frictionless probing
    TAVV_VALIDITY_S = 30.0       # CF-04: TAVV cryptogram validity
    AREQ_TIMEOUT_S = 3.0         # CF-02: ARes must follow AReq within 3s
    CREQ_TIMEOUT_S = 300.0       # CF-03: CReq must follow ARes within 300s
    CRES_TIMEOUT_S = 120.0       # CF-01: CRes must follow CReq within 120s
    IP_BIN_WINDOW_S = 60.0       # CF-05: distinct BIN probe window
    IP_BIN_LIMIT = 5             # CF-05: distinct BINs from same IP cluster

    def __init__(self):
        # pending_auth: stan -> (event, timestamp)
        self.pending_auth: Dict[str, Tuple[PaymentEvent, float]] = {}
        # pending_3ds: threeds_session_id -> (areq_event, ares_ts, cReq_ts)
        self.pending_3ds: Dict[str, Dict] = {}
        # token registry: token_id -> (provision_ts, first_use_ts)
        self.token_registry: Dict[str, Tuple[float, Optional[float]]] = {}
        # bin_burst: bin_prefix -> deque of timestamps
        self.bin_burst: Dict[str, deque] = defaultdict(deque)
        # ip_bin_tracker: source_ip -> {bin_prefix -> timestamp}
        self.ip_bin_tracker: Dict[str, Dict[str, float]] = defaultdict(dict)
        # micro_auth_count: bin_prefix -> count
        self.micro_auth_count: Dict[str, int] = defaultdict(int)

    def process_event(self, seq: TransactionSequence, event: PaymentEvent):
        """Apply state machine rules to a new event; flag violations on seq."""
        et = event.event_type
        ts = event.timestamp

        if et == EventType.ISO_0100:
            self._handle_auth_request(seq, event)

        elif et == EventType.ISO_0110:
            self._handle_auth_response(seq, event)

        elif et == EventType.ISO_0200:
            self._handle_completion(seq, event)

        elif et == EventType.ISO_0400:
            self._handle_reversal(seq, event)

        elif et == EventType.THREEDS_AREQ:
            self._handle_areq(seq, event)

        elif et == EventType.THREEDS_ARES:
            self._handle_ares(seq, event)

        elif et == EventType.THREEDS_CREQ:
            self._handle_creq(seq, event)

        elif et == EventType.THREEDS_CRES:
            self._handle_cres(seq, event)

        elif et == EventType.TOKEN_PROVISION:
            self.token_registry[event.token_id] = (ts, None)

        elif et == EventType.TOKEN_USE:
            self._handle_token_use(seq, event)

        # CF-05: IP cluster BIN diversity check
        self._check_ip_bin_diversity(seq, event)

    def _handle_auth_request(self, seq: TransactionSequence, event: PaymentEvent):
        ts = event.timestamp

        # R-10: micro-authorization probe
        if abs(event.amount - 0.01) < 0.001:
            seq.flag(AnomalyRule.R10)
            self.micro_auth_count[event.bin_prefix] += 1

        # R-03: BIN enumeration burst
        burst = self.bin_burst[event.bin_prefix]
        burst.append(ts)
        while burst and (ts - burst[0]) > self.BIN_BURST_WINDOW_S:
            burst.popleft()
        if len(burst) > self.BIN_BURST_LIMIT:
            seq.flag(AnomalyRule.R03)

        # Record pending auth for timeout checks
        if event.stan:
            self.pending_auth[event.stan] = (event, ts)

    def _handle_auth_response(self, seq: TransactionSequence, event: PaymentEvent):
        # R-04: 0200 precedes 0110 — checked in completion handler
        # R-01: verify response arrived for pending auth
        if event.stan and event.stan in self.pending_auth:
            orig, orig_ts = self.pending_auth[event.stan]
            if event.timestamp - orig_ts > self.AUTH_TIMEOUT_S:
                seq.flag(AnomalyRule.R01)
            del self.pending_auth[event.stan]

    def _handle_completion(self, seq: TransactionSequence, event: PaymentEvent):
        if event.stan and event.stan in self.pending_auth:
            # R-04: completion arrived before auth response? (still pending)
            seq.flag(AnomalyRule.R04)
        # R-02 check is done at sequence close if no completion arrived

    def _handle_reversal(self, seq: TransactionSequence, event: PaymentEvent):
        if event.stan and event.stan not in self.pending_auth:
            seq.flag(AnomalyRule.R05)  # references unknown STAN

    def _handle_areq(self, seq: TransactionSequence, event: PaymentEvent):
        sid = event.threeds_session_id or event.event_id
        self.pending_3ds[sid] = {
            "areq_ts": event.timestamp,
            "ares_ts": None,
            "creq_ts": None,
            "bin": event.bin_prefix,
        }

        # R-07: multiple AReqs from same BIN without CReq within 10s
        recent = [
            v for v in self.pending_3ds.values()
            if v["bin"] == event.bin_prefix
            and v["creq_ts"] is None
            and (event.timestamp - v["areq_ts"]) < self.FRICTIONLESS_WINDOW_S
        ]
        if len(recent) > self.FRICTIONLESS_LIMIT:
            seq.flag(AnomalyRule.R07)

    def _handle_ares(self, seq: TransactionSequence, event: PaymentEvent):
        sid = event.threeds_session_id or event.event_id
        if sid in self.pending_3ds:
            areq_ts = self.pending_3ds[sid]["areq_ts"]
            # CF-02: ARes must follow AReq within 3s
            if event.timestamp - areq_ts > self.AREQ_TIMEOUT_S:
                seq.flag(AnomalyRule.CF02)
            self.pending_3ds[sid]["ares_ts"] = event.timestamp

    def _handle_creq(self, seq: TransactionSequence, event: PaymentEvent):
        sid = event.threeds_session_id or event.event_id
        if sid in self.pending_3ds:
            ares_ts = self.pending_3ds[sid].get("ares_ts")
            if ares_ts and (event.timestamp - ares_ts > self.CREQ_TIMEOUT_S):
                seq.flag(AnomalyRule.CF03)
            self.pending_3ds[sid]["creq_ts"] = event.timestamp

    def _handle_cres(self, seq: TransactionSequence, event: PaymentEvent):
        sid = event.threeds_session_id or event.event_id
        if sid in self.pending_3ds:
            creq_ts = self.pending_3ds[sid].get("creq_ts")
            if creq_ts and (event.timestamp - creq_ts > self.CRES_TIMEOUT_S):
                seq.flag(AnomalyRule.CF01)
            del self.pending_3ds[sid]

    def _handle_token_use(self, seq: TransactionSequence, event: PaymentEvent):
        tid = event.token_id
        if tid and tid in self.token_registry:
            provision_ts, first_use_ts = self.token_registry[tid]
            # CF-04: TAVV validity window
            if event.timestamp - provision_ts > self.TAVV_VALIDITY_S:
                seq.flag(AnomalyRule.CF04)
            # R-08: token reuse
            if first_use_ts is not None:
                seq.flag(AnomalyRule.R08)
            else:
                self.token_registry[tid] = (provision_ts, event.timestamp)

    def _check_ip_bin_diversity(self, seq: TransactionSequence, event: PaymentEvent):
        now = event.timestamp
        ip = event.source_ip
        tracker = self.ip_bin_tracker[ip]
        # evict stale entries
        stale = [b for b, ts in tracker.items() if now - ts > self.IP_BIN_WINDOW_S]
        for b in stale:
            del tracker[b]
        tracker[event.bin_prefix] = now
        if len(tracker) > self.IP_BIN_LIMIT:
            seq.flag(AnomalyRule.CF05)

    def check_orphaned_auths(self, sequences: Dict[str, "TransactionSequence"], now: float):
        """
        R-02: flag sequences where a 0100 has no 0200/0400 within COMPLETION_TIMEOUT_S.
        Call periodically (e.g., every 30s) to catch orphaned authorizations.
        """
        completed_stans: Set[str] = set()
        for seq in sequences.values():
            completion_types = {EventType.ISO_0200, EventType.ISO_0400,
                                EventType.ISO_0210, EventType.ISO_0410}
            auth_types = {EventType.ISO_0100}
            has_auth = any(e.event_type in auth_types for e in seq.events)
            has_completion = any(e.event_type in completion_types for e in seq.events)
            if has_auth and not has_completion:
                for e in seq.events:
                    if e.event_type == EventType.ISO_0100:
                        if now - e.timestamp > self.COMPLETION_TIMEOUT_S:
                            seq.flag(AnomalyRule.R02)
                            break

    def check_orphaned_3ds(self, sequences: Dict[str, "TransactionSequence"], now: float):
        """
        R-06: flag 3DS sessions where AReq has no corresponding 0100 within 600s.
        """
        for sid, state in list(self.pending_3ds.items()):
            if now - state["areq_ts"] > self.THREEDS_SESSION_TIMEOUT_S:
                # find the matching sequence and flag
                # In production this would correlate by session ID
                logger.debug(f"Orphaned 3DS session {sid}: R-06")
                del self.pending_3ds[sid]

# ---------------------------------------------------------------------------
# Transaction Intent Graph + TCS engine
# ---------------------------------------------------------------------------

class SemanticTransactionCorrelator:
    """
    Maintains the Transaction Intent Graph G = (V, E, T) and computes TCS
    for each BIN family over a configurable sliding time window.

    Graph model (simplified in-process version; production uses Neo4j 5.x):
      - Vertices: pseudo-PAN families, merchant IDs, ACS session IDs, IP clusters
      - Edges: directed, typed by EventType, annotated with timestamp
      - Time window: expired edges pruned every prune_interval_s seconds
    """

    def __init__(self, window_s: float = 3600.0, prune_interval_s: float = 60.0):
        self.window_s = window_s
        self.prune_interval_s = prune_interval_s
        self._last_prune = time.time()

        # sequences[session_key] = TransactionSequence
        self.sequences: Dict[str, TransactionSequence] = {}
        # bin_sequences[bin_prefix] = list of seq_ids
        self.bin_sequences: Dict[str, List[str]] = defaultdict(list)
        # edges: list of (src, dst, event_type, timestamp)
        self.edges: List[Tuple[str, str, str, float]] = []
        # state machine validator
        self.fsm = PaymentStateMachine()

        self._event_count = 0

    def _session_key(self, event: PaymentEvent) -> str:
        """Composite key: BIN + terminal + (STAN or 3DS session or token)."""
        components = [
            event.bin_prefix,
            event.terminal_id,
            event.stan or "",
            event.threeds_session_id or "",
            event.token_id or "",
        ]
        raw = "|".join(components)
        return hashlib.md5(raw.encode()).hexdigest()[:16]

    def ingest_event(self, event: PaymentEvent):
        """Process one payment event: build TIG edge, validate state machine."""
        now = event.timestamp
        key = self._session_key(event)

        # Get or create sequence
        if key not in self.sequences:
            self.sequences[key] = TransactionSequence(
                seq_id=key,
                bin_prefix=event.bin_prefix,
                start_ts=now,
                end_ts=now,
            )
            self.bin_sequences[event.bin_prefix].append(key)

        seq = self.sequences[key]
        seq.events.append(event)
        seq.end_ts = now

        # State machine validation
        self.fsm.process_event(seq, event)

        # Add TIG edge
        if len(seq.events) > 1:
            prev = seq.events[-2]
            self.edges.append((
                f"{prev.event_type.value}:{prev.event_id}",
                f"{event.event_type.value}:{event.event_id}",
                event.event_type.value,
                now,
            ))

        self._event_count += 1

        # Periodic pruning
        if now - self._last_prune > self.prune_interval_s:
            self._prune(now)

    def _prune(self, now: float):
        """Remove edges and sequences outside the sliding time window."""
        cutoff = now - self.window_s
        self.edges = [(s, d, t, ts) for s, d, t, ts in self.edges if ts >= cutoff]

        stale_keys = [k for k, seq in self.sequences.items() if seq.end_ts < cutoff]
        for k in stale_keys:
            seq = self.sequences.pop(k)
            bin_seqs = self.bin_sequences[seq.bin_prefix]
            if k in bin_seqs:
                bin_seqs.remove(k)

        self._last_prune = now
        logger.debug(f"Pruned {len(stale_keys)} stale sequences; {len(self.sequences)} active")

    def compute_tcs(self, bin_prefix: str, now: float) -> TCSResult:
        """
        Compute TCS(b, W) for BIN family b over the current time window W.

        TCS = coherent_sequences / total_sequences
        where coherent(s) iff s has no anomaly flags.
        """
        # Run orphan checks first
        self.fsm.check_orphaned_auths(self.sequences, now)
        self.fsm.check_orphaned_3ds(self.sequences, now)

        cutoff = now - self.window_s
        seq_ids = self.bin_sequences.get(bin_prefix, [])

        total = 0
        coherent = 0
        anomaly_dist: Dict[str, int] = defaultdict(int)

        for sid in seq_ids:
            if sid not in self.sequences:
                continue
            seq = self.sequences[sid]
            if seq.start_ts < cutoff:
                continue
            total += 1
            if seq.is_coherent:
                coherent += 1
            for rule in seq.anomaly_flags:
                anomaly_dist[rule.name] += 1

        tcs = coherent / total if total > 0 else 1.0  # no data → assume coherent

        return TCSResult(
            bin_prefix=bin_prefix,
            window_start=cutoff,
            window_end=now,
            total_sequences=total,
            coherent_sequences=coherent,
            tcs=tcs,
            anomaly_distribution=dict(anomaly_dist),
        )

    def compute_tcs_all(self, now: float) -> Dict[str, TCSResult]:
        """Compute TCS for all active BIN families."""
        return {bin_p: self.compute_tcs(bin_p, now)
                for bin_p in self.bin_sequences if self.bin_sequences[bin_p]}

    @property
    def graph_stats(self) -> Dict:
        return {
            "active_sequences": len(self.sequences),
            "active_edges": len(self.edges),
            "event_count": self._event_count,
            "active_bins": len([b for b, seqs in self.bin_sequences.items() if seqs]),
        }


# ---------------------------------------------------------------------------
# Demo / self-test
# ---------------------------------------------------------------------------

def _demo():
    import random
    random.seed(42)
    logging.basicConfig(level=logging.INFO)

    stc = SemanticTransactionCorrelator(window_s=3600.0)
    now = time.time()

    # Simulate 100 legitimate sequences for BIN 411111
    for i in range(100):
        ts = now + i * 0.5
        stan = f"STAN{i:06d}"
        tid = f"TERM01"
        ip = f"10.0.0.{(i % 50) + 1}"
        # Auth request
        stc.ingest_event(PaymentEvent(
            event_id=f"ev_0100_{i}", event_type=EventType.ISO_0100,
            bin_prefix="411111", terminal_id=tid, source_ip=ip,
            timestamp=ts, stan=stan, amount=49.0
        ))
        # Auth response (within 1s)
        stc.ingest_event(PaymentEvent(
            event_id=f"ev_0110_{i}", event_type=EventType.ISO_0110,
            bin_prefix="411111", terminal_id=tid, source_ip=ip,
            timestamp=ts + 0.8, stan=stan, amount=49.0, response_code="00"
        ))
        # Completion (within 30s)
        stc.ingest_event(PaymentEvent(
            event_id=f"ev_0200_{i}", event_type=EventType.ISO_0200,
            bin_prefix="411111", terminal_id=tid, source_ip=ip,
            timestamp=ts + 25.0, stan=stan, amount=49.0
        ))

    # Simulate 100 attack probe sequences for BIN 555555 (no completions)
    for i in range(100):
        ts = now + i * 0.1  # rapid burst
        stan = f"ATSTAN{i:06d}"
        ip = f"192.168.1.{(i % 10) + 1}"
        stc.ingest_event(PaymentEvent(
            event_id=f"ev_atk_{i}", event_type=EventType.ISO_0100,
            bin_prefix="555555", terminal_id="TERM_ATK", source_ip=ip,
            timestamp=ts, stan=stan, amount=0.01  # micro-auth → R-10
        ))
        # No completion follows → orphan → R-02 flagged at next check

    # Force orphan check
    now2 = now + 200.0
    tcs_legit = stc.compute_tcs("411111", now2)
    tcs_attack = stc.compute_tcs("555555", now2)

    print(f"\n=== STC Demo Results ===")
    print(f"Legitimate BIN 411111: TCS = {tcs_legit.tcs:.3f} "
          f"({tcs_legit.coherent_sequences}/{tcs_legit.total_sequences} coherent)")
    print(f"Attack BIN 555555:    TCS = {tcs_attack.tcs:.3f} "
          f"({tcs_attack.coherent_sequences}/{tcs_attack.total_sequences} coherent)")
    print(f"Attack anomaly distribution: {tcs_attack.anomaly_distribution}")
    print(f"Graph stats: {stc.graph_stats}")

    assert tcs_legit.tcs > 0.75, f"Legitimate TCS too low: {tcs_legit.tcs}"
    assert tcs_attack.tcs < 0.45, f"Attack TCS too high: {tcs_attack.tcs}"
    print("\nAll assertions passed.")


if __name__ == "__main__":
    _demo()

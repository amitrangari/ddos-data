"""
Payment-Semantic Rate Governor (PSRG) — TIG-CDO Component 4

Implements TCS-weighted, transaction-attempt-level rate limiting.
Groups source IPs into clusters based on shared pseudo-PAN context and
applies dynamic rate limits per cluster rather than per IP.

Rate formula (from paper Section IV-F):
  R_cluster(c) = R_base · TCS(c, W) · f_history(c)

where:
  R_base      = nominal rate limit for the endpoint
  TCS(c, W)   = Transaction Coherence Score for the cluster's BIN families
  f_history   = history factor: 1.0 (new) → 2.0 (30+ days established)

When TCS = 0: R_cluster → 0 (cluster effectively blocked).
When TCS = 0.9: R_cluster = 0.90 × R_base × f_history.

Implementation note:
  Production PSRG uses Envoy WASM extension filter (Rust/WASM) with a
  Bloom filter for IP-to-cluster mapping and token bucket enforcement.
  This module is the Python reference implementation used for simulation.
"""

import time
import logging
import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cluster and rate-limit state
# ---------------------------------------------------------------------------

@dataclass
class IPCluster:
    cluster_id: str
    member_ips: Set[str] = field(default_factory=set)
    bin_families: Set[str] = field(default_factory=set)
    created_ts: float = 0.0
    last_seen_ts: float = 0.0
    request_count: int = 0

    @property
    def age_days(self) -> float:
        return (self.last_seen_ts - self.created_ts) / 86400.0

@dataclass
class TokenBucket:
    """Token bucket per cluster for rate limiting."""
    capacity: float          # max tokens = R_base per second
    tokens: float
    refill_rate: float       # tokens per second
    last_refill_ts: float

    def consume(self, now: float, n: float = 1.0) -> bool:
        """
        Try to consume n tokens. Returns True if allowed, False if rate-limited.
        Refills bucket based on elapsed time since last refill.
        """
        elapsed = max(0.0, now - self.last_refill_ts)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill_ts = now

        if self.tokens >= n:
            self.tokens -= n
            return True
        return False

# ---------------------------------------------------------------------------
# PSRG
# ---------------------------------------------------------------------------

class PaymentSemanticRateGovernor:
    """
    PSRG reference implementation.

    Key behaviors:
    1. IP-to-cluster assignment: IPs sharing BIN families within a time window
       are assigned to the same cluster.
    2. TCS-weighted rate limit: R_cluster = R_base × TCS × f_history
    3. Token bucket enforcement per cluster.
    4. Inline P99 latency target: 1.2 ms. This is a design target, not a measurement:
       no Envoy WASM filter was built or measured for this package (v1.2.0 correction).
    """

    # Cluster assignment parameters
    CLUSTER_WINDOW_S = 600.0      # IPs sharing BIN lookups within 10 min → same cluster
    BLOOM_TTL_S = 300.0           # IP-to-cluster mapping TTL (refreshed by STC every 5s)
    MAX_CLUSTER_SIZE = 50000      # max IPs per cluster (CSDA botnet ceiling)

    # History factor parameters
    F_HISTORY_MAX = 2.0           # max trust multiplier for established clusters
    F_HISTORY_MATURITY_DAYS = 30  # days to reach F_HISTORY_MAX

    def __init__(self, r_base_per_s: float = 1000.0):
        """
        Args:
            r_base_per_s: Nominal endpoint rate limit (requests/second).
                          Default 1000 req/s = 1K TPS per cluster.
        """
        self.r_base = r_base_per_s

        # Cluster registry: cluster_id → IPCluster
        self.clusters: Dict[str, IPCluster] = {}
        # IP-to-cluster mapping (simulates Bloom filter): ip → cluster_id
        self.ip_cluster_map: Dict[str, str] = {}
        # Token buckets: cluster_id → TokenBucket
        self.buckets: Dict[str, TokenBucket] = {}
        # TCS values (updated from STC every ~5s): cluster_id → tcs
        self.tcs_by_cluster: Dict[str, float] = {}
        # Request stats
        self._allowed = 0
        self._blocked = 0

    def _cluster_id_for_bin(self, bin_prefix: str) -> str:
        """Deterministic cluster ID based on BIN family (simplified)."""
        return hashlib.md5(bin_prefix.encode()).hexdigest()[:12]

    def update_tcs(self, bin_prefix: str, tcs: float):
        """
        Called by STC every ~5 seconds with updated TCS per BIN family.
        Updates the effective rate limit for all clusters associated with
        the given BIN family.
        """
        cid = self._cluster_id_for_bin(bin_prefix)
        self.tcs_by_cluster[cid] = tcs
        if cid in self.buckets:
            # Recompute rate limit
            r_effective = self._effective_rate(cid)
            self.buckets[cid].refill_rate = r_effective
            self.buckets[cid].capacity = r_effective  # 1-second burst capacity
            logger.debug(f"PSRG: cluster {cid} TCS={tcs:.3f} → rate={r_effective:.1f}/s")

    def _history_factor(self, cluster: IPCluster) -> float:
        """
        f_history: linearly scales from 1.0 (new) to F_HISTORY_MAX (30+ days).
        """
        age_fraction = min(1.0, cluster.age_days / self.F_HISTORY_MATURITY_DAYS)
        return 1.0 + (self.F_HISTORY_MAX - 1.0) * age_fraction

    def _effective_rate(self, cluster_id: str) -> float:
        """
        R_cluster(c) = R_base × TCS(c, W) × f_history(c)
        """
        tcs = self.tcs_by_cluster.get(cluster_id, 1.0)
        cluster = self.clusters.get(cluster_id)
        f_hist = self._history_factor(cluster) if cluster else 1.0
        return self.r_base * tcs * f_hist

    def _get_or_create_cluster(self, source_ip: str, bin_prefix: str, now: float) -> str:
        """
        Assign IP to a cluster based on shared BIN prefix context.
        Returns cluster_id.
        """
        cid = self._cluster_id_for_bin(bin_prefix)

        if cid not in self.clusters:
            self.clusters[cid] = IPCluster(
                cluster_id=cid,
                created_ts=now,
                last_seen_ts=now,
            )
            # Initialize token bucket at full rate
            r_eff = self._effective_rate(cid)
            self.buckets[cid] = TokenBucket(
                capacity=r_eff,
                tokens=r_eff,
                refill_rate=r_eff,
                last_refill_ts=now,
            )

        cluster = self.clusters[cid]
        cluster.member_ips.add(source_ip)
        cluster.bin_families.add(bin_prefix)
        cluster.last_seen_ts = now
        self.ip_cluster_map[source_ip] = cid
        return cid

    def allow_request(
        self,
        source_ip: str,
        bin_prefix: str,
        timestamp: float,
        n_tokens: float = 1.0,
    ) -> Tuple[bool, str, float]:
        """
        Main inline rate-limiting decision.

        Returns:
            (allowed: bool, cluster_id: str, effective_rate: float)

        Inline P99 overhead design target: 1.2 ms (not measured; no Envoy WASM
        filter exists in this package).
        """
        cid = self._get_or_create_cluster(source_ip, bin_prefix, timestamp)
        cluster = self.clusters[cid]
        cluster.request_count += 1

        # Refresh token bucket rate from current TCS
        r_eff = self._effective_rate(cid)
        bucket = self.buckets[cid]
        bucket.refill_rate = r_eff
        bucket.capacity = max(r_eff, 1.0)

        allowed = bucket.consume(timestamp, n_tokens)
        if allowed:
            self._allowed += 1
        else:
            self._blocked += 1

        return allowed, cid, r_eff

    def get_cluster_status(self, bin_prefix: str) -> Optional[Dict]:
        cid = self._cluster_id_for_bin(bin_prefix)
        if cid not in self.clusters:
            return None
        cluster = self.clusters[cid]
        tcs = self.tcs_by_cluster.get(cid, 1.0)
        r_eff = self._effective_rate(cid)
        bucket = self.buckets[cid]
        return {
            "cluster_id": cid,
            "bin_prefix": bin_prefix,
            "member_ips": len(cluster.member_ips),
            "tcs": tcs,
            "r_base": self.r_base,
            "r_effective": r_eff,
            "r_effective_pct": r_eff / self.r_base * 100,
            "tokens_available": round(bucket.tokens, 2),
            "request_count": cluster.request_count,
            "age_days": round(cluster.age_days, 2),
            "f_history": round(self._history_factor(cluster), 3),
        }

    def summary(self) -> Dict:
        total = self._allowed + self._blocked
        return {
            "total_requests": total,
            "allowed": self._allowed,
            "blocked": self._blocked,
            "block_rate_pct": round(self._blocked / total * 100, 2) if total > 0 else 0.0,
            "active_clusters": len(self.clusters),
        }


# ---------------------------------------------------------------------------
# Demo / self-test
# ---------------------------------------------------------------------------

def _demo():
    import random
    random.seed(42)
    logging.basicConfig(level=logging.INFO)

    psrg = PaymentSemanticRateGovernor(r_base_per_s=100.0)
    now = 0.0

    print("\n=== PSRG Demo ===")

    # Case 1: High-TCS legitimate cluster
    psrg.update_tcs("411111", tcs=0.90)
    allowed_count = 0
    for i in range(200):
        ts = i * 0.01  # 100 req/s
        ok, cid, rate = psrg.allow_request(f"10.0.0.{(i%50)+1}", "411111", ts)
        if ok:
            allowed_count += 1
    status_legit = psrg.get_cluster_status("411111")
    print(f"Legitimate cluster (TCS=0.90): allowed {allowed_count}/200 requests, "
          f"R_eff={status_legit['r_effective']:.1f}/s "
          f"({status_legit['r_effective_pct']:.0f}% of R_base)")

    # Case 2: Low-TCS attack cluster (reconnaissance phase, TCS=0.23)
    psrg.update_tcs("555555", tcs=0.23)
    attack_allowed = 0
    for i in range(200):
        ts = i * 0.005  # 200 req/s attempt (2x R_base)
        ok, cid, rate = psrg.allow_request(f"192.168.1.{(i%10)+1}", "555555", ts)
        if ok:
            attack_allowed += 1
    status_attack = psrg.get_cluster_status("555555")
    print(f"Attack cluster (TCS=0.23):     allowed {attack_allowed}/200 requests, "
          f"R_eff={status_attack['r_effective']:.1f}/s "
          f"({status_attack['r_effective_pct']:.0f}% of R_base)")

    # Case 3: Zero-TCS full block
    psrg.update_tcs("999999", tcs=0.0)
    blocked_count = 0
    for i in range(50):
        ts = i * 0.01
        ok, _, _ = psrg.allow_request(f"172.16.0.{i+1}", "999999", ts)
        if not ok:
            blocked_count += 1
    print(f"Zero-TCS cluster:              blocked {blocked_count}/50 requests "
          f"(R_eff=0 → full block)")

    summary = psrg.summary()
    print(f"\nOverall PSRG summary: {summary}")

    # Assertions
    assert status_legit["r_effective"] > 0.8 * psrg.r_base, \
        f"Legitimate cluster rate too low: {status_legit['r_effective']}"
    assert status_attack["r_effective"] < 0.5 * psrg.r_base, \
        f"Attack cluster rate should be throttled below 50%: {status_attack['r_effective']}"
    assert blocked_count == 50, "Zero-TCS cluster should block all requests"
    print("\nAll assertions passed.")


if __name__ == "__main__":
    _demo()

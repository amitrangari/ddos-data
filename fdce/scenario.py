"""
FDCE scenario simulator, version 1.3.0.

Generates bot (declined-card) and organic merchant traffic and runs it through
FDCEDetector. All traffic is SYNTHETIC. Changes from v1.2 (round-3 review):

  * Completions and reversals are scheduled as events at the time they occur and
    are fed to the detector then (v1.2 called observe_completion(m, ts + 1.0) at
    time ts, a look-ahead; R3-004).
  * Three message flows (author fact F2): "single" (approved 0210 is the capture),
    "dual_0220" (0220 advice after a delay), "clearing" (capture hours later).
    Organic capture delays are drawn from a distribution per flow.
  * Every scenario, including the decline-spreading adversary, evaluates R-11 and
    R-12 after every event for the whole run (v1.2 stopped evaluating R-12 in the
    adversarial run after the first detection; R1-006, R3-025).
  * Two organic profiles: "legacy" (the v1.2 grid: 20 merchants at 3 TPS, 30 BIN
    families, uniform decline codes) and "zipf" (Zipf BIN and merchant volumes,
    per-BIN decline heterogeneity, an ASSUMED organic decline-code mix in which
    05 and 51 dominate; R3-021). Bots can use their own BIN families ("disjoint",
    the v1.2 design) or BIN families that also carry organic traffic ("shared"),
    and can route part of their traffic through organic merchant identities.
  * Bot pacing: Poisson arrivals or regular spacing with a random phase.
  * Reported per run: time to first fire by rule, bot authorizations admitted
    before the first block and in total, block rate, organic false fires by rule
    and organic transactions blocked.

The organic decline-code mix is an assumption (no public issuer-level decline
statistics were available); it is a stress setting, not a calibration.
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np

from .fdce import FDCEDetector, COMPLETION_WINDOW_S

BOT_BIN_POOL_SIZE = 4
ORGANIC_BIN_POOL_SIZE = 30
N_ORGANIC_MERCHANTS = 20
ORGANIC_COMPLETION_RATE = 0.85
LEGACY_ORGANIC_DECLINE_CODES = ["14", "54", "57", "82", "05", "51", "61"]

# ASSUMED organic decline-code mix for the "zipf" profile (shares of declines).
# ISO 8583 meanings: 05 do not honor, 51 insufficient funds, 61 exceeds withdrawal
# amount, 54 expired card, 14 invalid card number, 57 not permitted to cardholder,
# 91 issuer unavailable, 82 network-specific, 65 exceeds frequency limit,
# N7 network-specific (CVV2 failure on some networks).
ORGANIC_DECLINE_MIX = {"05": 0.34, "51": 0.30, "61": 0.06, "54": 0.07, "14": 0.04,
                       "57": 0.06, "91": 0.03, "82": 0.02, "65": 0.04, "N7": 0.04}

CARD_MIX = {
    "expired_only": {"54": 1.00},
    "mixed": {"54": 0.60, "82": 0.25, "14": 0.15},
    "spread": {"14": 0.24, "54": 0.24, "57": 0.24, "82": 0.28},
    "substitution": {"05": 0.60, "51": 0.40},
}


def capture_delay(flow: str, rng: np.random.Generator, n: int) -> np.ndarray:
    """Organic capture delay after the authorization (seconds)."""
    if flow == "single":
        return np.zeros(n)
    if flow == "dual_0220":
        return rng.lognormal(mean=math.log(120.0), sigma=0.8, size=n)   # median 120 s
    if flow == "clearing":
        return rng.uniform(6 * 3600.0, 30 * 3600.0, size=n)
    raise ValueError(flow)


@dataclass
class OrganicProfile:
    kind: str = "legacy"            # "legacy" or "zipf"
    n_bins: int = 200
    n_merchants: int = 400
    total_tps: float = 100.0
    zipf_bins: float = 1.0
    zipf_merchants: float = 1.0
    decline_rate_beta: Tuple[float, float] = (3.0, 22.0)   # mean 0.12
    mix_concentration: float = 20.0
    p_capture: float = 0.97          # approved and captured
    p_reverse: float = 0.02          # approved and reversed (rest: neither)
    new_merchant_share: float = 0.0  # merchants that start mid-run
    bin_prefix: str = "ORG"


@dataclass
class AttackProfile:
    n_merchants: int = 50
    rate_per_merchant: float = 7.0   # authorizations per second per merchant identity
    card_mix: str = "expired_only"
    spacing: str = "poisson"         # "poisson" or "regular"
    bins: str = "disjoint"           # "disjoint" or "shared"
    n_bins: Optional[int] = None     # bot BIN families (disjoint) or attacked families (shared)
    hijack_share: float = 0.0        # share of bot merchant identities that are organic merchants
    start_s: float = 0.0
    p_approve: float = 0.0           # approved share (authorize-then-reverse adversary)
    reverse_after_s: Optional[float] = None


@dataclass
class FDCEScenarioResult:
    detection_latency_s: Optional[float]
    triggered_rule: Optional[str]
    block_rate: float
    n_bot_txn: int
    n_bot_blocked: int
    n_organic_r12_false_positives: int = 0
    first_r11_s: Optional[float] = None
    first_r12_s: Optional[float] = None
    n_bot_admitted: int = 0
    n_bot_admitted_before_first_block: int = 0
    organic_r11_false_fires: int = 0
    organic_r11_false_bins: int = 0
    organic_r12_false_fires: int = 0
    n_organic_txn: int = 0
    n_organic_blocked: int = 0
    organic_merchants_over_gate: int = 0
    extra: Dict = field(default_factory=dict)


def _zipf_weights(n: int, a: float) -> np.ndarray:
    w = 1.0 / np.arange(1, n + 1) ** a
    return w / w.sum()


def _draw_codes(rng, mix: Dict[str, float], n: int) -> np.ndarray:
    codes = list(mix.keys())
    p = np.array([mix[c] for c in codes], dtype=float)
    p = p / p.sum()
    return np.array(codes, dtype=object)[rng.choice(len(codes), size=n, p=p)]


def organic_events(prof: OrganicProfile, flow: str, duration_s: float,
                   rng: np.random.Generator) -> Tuple[List[tuple], List[str], List[str], Dict]:
    """Returns (events, bin_ids, merchant_ids, info). Event tuple:
    (ts, kind, merchant, bin, txn_id, code, is_bot); kind in auth, comp, rev."""
    ev: List[tuple] = []
    if prof.kind == "legacy":
        bins = [f"{prof.bin_prefix}{i:03d}" for i in range(ORGANIC_BIN_POOL_SIZE)]
        merchants = [f"org_merchant_{i:03d}" for i in range(N_ORGANIC_MERCHANTS)]
        k = 0
        for m in merchants:
            b = bins[int(rng.integers(len(bins)))]
            n = int(rng.poisson(3.0 * duration_s))
            ts = np.sort(rng.uniform(0, duration_s, n))
            appr = rng.random(n) < ORGANIC_COMPLETION_RATE
            codes = np.array(LEGACY_ORGANIC_DECLINE_CODES, dtype=object)[rng.integers(0, 7, n)]
            delay = capture_delay(flow, rng, n)
            for t, a, c, d in zip(ts, appr, codes, delay):
                tid = f"o{k}"
                k += 1
                ev.append((float(t), "auth", m, b, tid, "00" if a else c, False))
                if a and flow != "single" and t + d < duration_s:
                    ev.append((float(t + d), "comp", m, b, tid, None, False))
        return ev, bins, merchants, {"merchant_rate_tps": {m: 3.0 for m in merchants}}

    bins = [f"{prof.bin_prefix}{i:04d}" for i in range(prof.n_bins)]
    merchants = [f"org_m{i:04d}" for i in range(prof.n_merchants)]
    wb = _zipf_weights(prof.n_bins, prof.zipf_bins)
    wm = _zipf_weights(prof.n_merchants, prof.zipf_merchants)
    base = np.array(list(ORGANIC_DECLINE_MIX.values()))
    codes_all = list(ORGANIC_DECLINE_MIX.keys())
    dec_rate = rng.beta(*prof.decline_rate_beta, size=prof.n_bins)
    mixes = rng.dirichlet(prof.mix_concentration * base, size=prof.n_bins)
    start = np.zeros(prof.n_merchants)
    if prof.new_merchant_share > 0:
        new = rng.random(prof.n_merchants) < prof.new_merchant_share
        start[new] = rng.uniform(0, duration_s / 2, new.sum())
    n = int(rng.poisson(prof.total_tps * duration_s))
    ts = np.sort(rng.uniform(0, duration_s, n))
    bi = rng.choice(prof.n_bins, size=n, p=wb)
    mi = rng.choice(prof.n_merchants, size=n, p=wm)
    keep = ts >= start[mi]
    ts, bi, mi = ts[keep], bi[keep], mi[keep]
    n = len(ts)
    u = rng.random(n)
    declined = u < dec_rate[bi]
    cu = rng.random(n)
    cum = np.cumsum(mixes, axis=1)
    code_idx = (cu[:, None] > cum[bi]).sum(axis=1)
    code_idx = np.minimum(code_idx, len(codes_all) - 1)
    outcome = rng.random(n)
    delay = capture_delay(flow, rng, n)
    rdelay = rng.uniform(5.0, 300.0, n)
    for j in range(n):
        t = float(ts[j])
        m = merchants[mi[j]]
        b = bins[bi[j]]
        tid = f"o{j}"
        if declined[j]:
            ev.append((t, "auth", m, b, tid, codes_all[code_idx[j]], False))
            continue
        ev.append((t, "auth", m, b, tid, "00", False))
        if outcome[j] < prof.p_capture:
            if flow != "single" and t + delay[j] < duration_s:
                ev.append((t + float(delay[j]), "comp", m, b, tid, None, False))
        elif outcome[j] < prof.p_capture + prof.p_reverse:
            if t + rdelay[j] < duration_s:
                ev.append((t + float(rdelay[j]), "rev", m, b, tid, None, False))
    rate = {merchants[i]: prof.total_tps * wm[i] for i in range(prof.n_merchants)}
    # long-run decline share per family excluding code 91, as an operator's history
    # would give it (used to warm the R-11 baseline)
    share91 = mixes[:, codes_all.index("91")]
    base = {bins[i]: float(dec_rate[i] * (1.0 - share91[i])) for i in range(prof.n_bins)}
    return ev, bins, merchants, {"merchant_rate_tps": rate, "bin_weights": wb, "baseline": base}


def attack_events(ap: AttackProfile, duration_s: float, rng: np.random.Generator,
                  organic_bins: List[str], organic_merchants: List[str],
                  bin_weights: Optional[np.ndarray] = None) -> Tuple[List[tuple], set, set]:
    if ap.bins == "disjoint":
        nb = ap.n_bins if ap.n_bins else max(BOT_BIN_POOL_SIZE, ap.n_merchants // 8)
        bot_bins = [f"BOT{i:03d}" for i in range(nb)]
    else:
        nb = ap.n_bins if ap.n_bins else 20
        w = bin_weights if bin_weights is not None else np.ones(len(organic_bins)) / len(organic_bins)
        idx = rng.choice(len(organic_bins), size=min(nb, len(organic_bins)), replace=False, p=w)
        bot_bins = [organic_bins[i] for i in idx]
    n_hij = int(round(ap.hijack_share * ap.n_merchants))
    hijacked = [organic_merchants[i] for i in rng.choice(len(organic_merchants), size=n_hij, replace=False)] \
        if n_hij else []
    merchants = hijacked + [f"bot_m{i:05d}" for i in range(ap.n_merchants - n_hij)]
    mix = CARD_MIX[ap.card_mix]
    ev: List[tuple] = []
    k = 0
    span = duration_s - ap.start_s
    for m in merchants:
        if ap.spacing == "regular":
            phase = rng.uniform(0, 1.0 / ap.rate_per_merchant)
            ts = ap.start_s + phase + np.arange(0, span, 1.0 / ap.rate_per_merchant)
            ts = ts[ts < duration_s]
        else:
            n = int(rng.poisson(ap.rate_per_merchant * span))
            ts = np.sort(rng.uniform(ap.start_s, duration_s, n))
        n = len(ts)
        if ap.bins == "disjoint":
            bsel = [bot_bins[int(rng.integers(len(bot_bins)))]] * n   # v1.2: one BIN per bot merchant
        else:
            bsel = [bot_bins[i] for i in rng.integers(0, len(bot_bins), n)]
        codes = _draw_codes(rng, mix, n)
        appr = rng.random(n) < ap.p_approve
        for t, b, c, a in zip(ts, bsel, codes, appr):
            tid = f"b{k}"
            k += 1
            ev.append((float(t), "auth", m, b, tid, "00" if a else c, True))
            if a and ap.reverse_after_s is not None and t + ap.reverse_after_s < duration_s:
                ev.append((float(t + ap.reverse_after_s), "rev", m, b, tid, None, True))
    return ev, set(bot_bins), set(merchants)


def run_stream(events: List[tuple], det: FDCEDetector, attack_start: float,
               bot_bins: set, bot_merchants: set, organic_rate: Dict[str, float],
               cusum=None) -> FDCEScenarioResult:
    """cusum: optional baselines.approval_cusum.BinDeclineCUSUM. It observes every
    authorization response of the unmitigated stream (as a standalone detector
    would) and never blocks."""
    events.sort(key=lambda e: e[0])
    n_bot = n_bot_blk = n_bot_adm = n_bot_adm_pre = 0
    n_org = n_org_blk = 0
    first_r11 = first_r12 = first_block = None
    first_rule = None
    blocked_txn = set()
    org_r11_bins = set()
    org_r11_fires = org_r12_fires = 0
    org_r12_merchants = set()
    n11 = n12 = 0
    for ts, kind, m, b, tid, code, bot in events:
        if kind == "auth" and cusum is not None:
            cusum.observe(b, ts, code)
        if kind == "auth":
            if det.is_blocked(b, m, ts):
                blocked_txn.add(tid)
                if bot:
                    n_bot += 1
                    n_bot_blk += 1
                    if first_block is None:
                        first_block = ts
                else:
                    n_org += 1
                    n_org_blk += 1
                continue
            if bot:
                n_bot += 1
                n_bot_adm += 1
                if first_block is None:
                    n_bot_adm_pre += 1
            else:
                n_org += 1
            det.observe_auth_request(m, ts, tid)
            det.observe_auth_response(b, ts, code, m, tid)
            det.check_r11(b, ts)
            det.check_r12(m, ts)
        elif kind == "comp":
            if tid not in blocked_txn:
                det.observe_completion(m, ts, tid)
        elif kind == "rev":
            if tid not in blocked_txn:
                det.observe_reversal(m, ts, tid)
        # new fires since last event
        while n11 < len(det.r11_fires):
            fb, ft = det.r11_fires[n11]
            n11 += 1
            if fb in bot_bins and ft >= attack_start:
                if first_r11 is None:
                    first_r11 = ft
            else:
                org_r11_fires += 1
                org_r11_bins.add(fb)
        while n12 < len(det.r12_fires):
            fm, ft = det.r12_fires[n12]
            n12 += 1
            if fm in bot_merchants and ft >= attack_start:
                if first_r12 is None:
                    first_r12 = ft
            else:
                org_r12_fires += 1
                org_r12_merchants.add(fm)
    cands = [(t, r) for t, r in ((first_r11, "R-11"), (first_r12, "R-12")) if t is not None]
    det_t = None
    if cands:
        det_t, first_rule = min(cands)
        if first_r11 is not None and first_r12 is not None and first_r11 == first_r12:
            first_rule = "R-11+R-12"
    over_gate = sum(1 for m, r in organic_rate.items() if r * 60.0 > det.r12_min_txn_per_min)
    extra = {}
    if cusum is not None:
        bot_al = [t for bb, t in cusum.alarms if bb in bot_bins and t >= attack_start]
        org_al = [bb for bb, t in cusum.alarms if bb not in bot_bins or t < attack_start]
        extra["cusum_first_alarm_s"] = (min(bot_al) - attack_start) if bot_al else None
        extra["cusum_organic_false_alarms"] = len(org_al)
        extra["cusum_organic_false_bins"] = len(set(org_al))
    return FDCEScenarioResult(
        extra=extra,
        detection_latency_s=(det_t - attack_start) if det_t is not None else None,
        triggered_rule=first_rule,
        block_rate=(n_bot_blk / n_bot) if n_bot else 0.0,
        n_bot_txn=n_bot, n_bot_blocked=n_bot_blk,
        n_organic_r12_false_positives=len(org_r12_merchants),
        first_r11_s=(first_r11 - attack_start) if first_r11 is not None else None,
        first_r12_s=(first_r12 - attack_start) if first_r12 is not None else None,
        n_bot_admitted=n_bot_adm, n_bot_admitted_before_first_block=n_bot_adm_pre,
        organic_r11_false_fires=org_r11_fires, organic_r11_false_bins=len(org_r11_bins),
        organic_r12_false_fires=org_r12_fires, n_organic_txn=n_org, n_organic_blocked=n_org_blk,
        organic_merchants_over_gate=over_gate,
    )


def make_detector(flow: str = "single", **kw) -> FDCEDetector:
    return FDCEDetector(window_s=60.0, flow=flow, **kw)


def simulate(attack: Optional[AttackProfile], organic: OrganicProfile, seed: int,
             duration_s: float = 120.0, flow: str = "single",
             detector_kwargs: Optional[Dict] = None, with_cusum: bool = False) -> FDCEScenarioResult:
    rng = np.random.default_rng(seed)
    org_ev, obins, omerch, info = organic_events(organic, flow, duration_s, rng)
    events = list(org_ev)
    bot_bins, bot_merch = set(), set()
    start = 0.0
    if attack is not None:
        aev, bot_bins, bot_merch = attack_events(attack, duration_s, rng, obins, omerch,
                                                 info.get("bin_weights"))
        events.extend(aev)
        start = attack.start_s
    kw = dict(detector_kwargs or {})
    if "baseline" in info and "baseline_init" not in kw:
        kw["baseline_init"] = info["baseline"]
    det = make_detector(flow, **kw)
    cus = None
    if with_cusum:
        from baselines.approval_cusum import BinDeclineCUSUM
        cus = BinDeclineCUSUM(baseline=info.get("baseline"))
    res = run_stream(events, det, start, bot_bins, bot_merch, info["merchant_rate_tps"], cus)
    return res


def simulate_fdce_scenario(cluster_size: int, card_type: str, intensity: float, seed: int,
                           duration_s: float = 120.0, flow: str = "single",
                           detector_kwargs: Optional[Dict] = None,
                           spacing: str = "poisson", bins: str = "disjoint",
                           organic: Optional[OrganicProfile] = None,
                           with_cusum: bool = False) -> FDCEScenarioResult:
    """The 30-scenario grid cell: cluster_size bot merchant identities, each at
    5 + 10 * intensity authorizations per second (7 to 15 per second for the
    grid intensities 0.2 to 1.0), i.e. 420 to 900 per minute against the R-12
    gate of 100 per minute."""
    ap = AttackProfile(n_merchants=cluster_size, rate_per_merchant=5.0 + intensity * 10.0,
                       card_mix=card_type, spacing=spacing, bins=bins)
    return simulate(ap, organic or OrganicProfile(kind="legacy"), seed, duration_s, flow,
                    detector_kwargs, with_cusum)


def simulate_fdce_adversarial_spread(cluster_size: int, intensity: float, seed: int,
                                     duration_s: float = 120.0, flow: str = "single",
                                     detector_kwargs: Optional[Dict] = None):
    """Decline-spreading adversary (24/24/24/28% over the watched codes), with
    R-11 and R-12 evaluated for the whole run."""
    r = simulate_fdce_scenario(cluster_size, "spread", intensity, seed, duration_s, flow,
                               detector_kwargs)
    return r, r.first_r11_s is not None

#!/usr/bin/env python3
"""
2.12 Reference-STC timing (reviews R3-007, R3-029): ingest rate and the cost of
compute_tcs_all on the in-process Python reference implementation, single
thread, at three sizes (BIN families x sequences): 100 x 20,000, 400 x 80,000,
1,000 x 200,000. Each sequence is 0100, 0110 and 0220. Wall-clock timings depend
on the machine; the platform is recorded. This measures the reference code, not
a production STC.
"""
import os
import platform
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiments._common import write  # noqa: E402
from stc.stc import SemanticTransactionCorrelator, PaymentEvent, EventType  # noqa: E402

SIZES = [(100, 20000), (400, 80000), (1000, 200000)]
REPS = 3


def one(nb, ns):
    stc = SemanticTransactionCorrelator(window_s=3600.0, flow="dual_0220")
    evs = []
    span = 3000.0
    for i in range(ns):
        ts = span * i / ns
        b = f"{400000 + (i % nb):06d}"
        kw = dict(bin_prefix=b, terminal_id="T", source_ip="10.0.0.1", stan=f"{i}", amount=20.0)
        evs.append(PaymentEvent(f"a{i}", EventType.ISO_0100, timestamp=ts, **kw))
        evs.append(PaymentEvent(f"b{i}", EventType.ISO_0110, timestamp=ts + 0.3, response_code="00", **kw))
        evs.append(PaymentEvent(f"c{i}", EventType.ISO_0220, timestamp=ts + 60.0, **kw))
    evs.sort(key=lambda e: e.timestamp)
    t0 = time.perf_counter()
    for e in evs:
        stc.ingest_event(e)
    t1 = time.perf_counter()
    stc.compute_tcs_all(span + 100.0)
    t2 = time.perf_counter()
    return len(evs) / (t1 - t0), t2 - t1


def main():
    out = {"platform": platform.platform(), "python": platform.python_version(), "processor": platform.processor(),
           "status": "wall-clock timing of the in-process Python reference STC, single thread", "sizes": []}
    for nb, ns in SIZES:
        rates, costs = [], []
        for _ in range(REPS):
            r, c = one(nb, ns)
            rates.append(r)
            costs.append(c)
        out["sizes"].append({"bin_families": nb, "sequences": ns, "events": 3 * ns,
                             "ingest_events_per_s_median": round(sorted(rates)[REPS // 2]),
                             "compute_tcs_all_s_median": round(sorted(costs)[REPS // 2], 4)})
        print(out["sizes"][-1], flush=True)
    write("stc_timing.json", out)


if __name__ == "__main__":
    main()

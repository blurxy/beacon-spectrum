#!/usr/bin/env python3
"""Detection rate against jitter, at a false-positive rate fixed on benign data.

The number that matters is not "it detected the beacon". It is: with the
threshold pinned so that only 1% of BENIGN flows alarm -- including benign
flows that are genuinely periodic, like NTP -- what fraction of beacons are
still caught as the attacker increases jitter?
"""
import sys, os, json, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
from periodogram import detect, rita_style_score, min_events, detectable_period
from simulate import beacon, poisson_flow, human_flow, periodic_benign


# Search settings, used identically for the threshold and the detection pass --
# a threshold calibrated on a different grid than the one being scored is not a
# threshold. 20s floor because real C2 sleeps are tens of seconds upward, and
# oversampling past ~4 does not add independent frequencies, only cost: measured
# 410ms/call at pmin=5/oversample=8 against 13ms here, on identical data.
PMIN = 20.0
OVERSAMPLE = 4


def score_spectral(t):
    """Score with Z^2 itself, not -log10(p).

    A p-value is the right thing to REPORT and the wrong thing to rank by here:
    a strongly periodic flow underflows float64 to 0, so every clean beacon and
    every NTP client collapses onto the same saturated score and the threshold
    pins to the ceiling. Measured: that alone dragged apparent detection at 0%%
    jitter down to 64.5%% -- an artifact of the clamp, not of the detector.
    Z^2 = 2N*R^2 is monotonic in the same evidence and has no ceiling.
    """
    _p, z, _pval, _n = detect(t, pmin=PMIN, oversample=OVERSAMPLE)
    return float(z)


def build_null(n, duration, rng):
    """Two separate benign populations, because they behave nothing alike.

    APERIODIC benign (Poisson noise, bursty human browsing) is what a
    periodicity detector is implicitly evaluated against when a paper quotes a
    single false-positive rate.

    PERIODIC benign (NTP, telemetry, health checks, backup jobs) is periodic on
    purpose, with less jitter than any competent beacon. Folding it into one
    null and reporting one number hides the only fact that matters here.
    """
    aper, per = [], []
    for i in range(n):
        if i % 2 == 0:
            aper.append(poisson_flow(rng.uniform(0.002, 0.05), duration, rng))
        else:
            aper.append(human_flow(duration, rng))
        per.append(periodic_benign(duration, rng))
    return ([f for f in aper if len(f) >= 8], [f for f in per if len(f) >= 8])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--duration", type=float, default=6 * 3600.0)
    ap.add_argument("--trials", type=int, default=300)
    ap.add_argument("--fpr", type=float, default=0.01)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--pmin", type=float, default=PMIN)
    ap.add_argument("--oversample", type=int, default=OVERSAMPLE)
    ap.add_argument("--out", default="docs/results.json")
    a = ap.parse_args()
    globals()["PMIN"] = a.pmin; globals()["OVERSAMPLE"] = a.oversample
    rng = np.random.default_rng(a.seed)

    aper, per = build_null(a.trials, a.duration, rng)
    scorers = (("spectral", score_spectral), ("rita-style", rita_style_score))
    thr, confound = {}, {}
    for name, fn in scorers:
        sa = np.array([fn(t) for t in aper])
        thr[name] = float(np.quantile(sa, 1.0 - a.fpr))
        sp = np.array([fn(t) for t in per])
        confound[name] = float((sp >= thr[name]).mean())
    print("null A: %d aperiodic benign (Poisson + bursty human)" % len(aper))
    print("null B: %d legitimately periodic benign (NTP/telemetry/backup)" % len(per))
    print("thresholds pinned at FPR=%.0f%% on null A:  spectral %.1f   rita-style %.3f"
          % (a.fpr * 100, thr["spectral"], thr["rita-style"]))
    print("\nCONFOUND -- share of null B (benign, but genuinely periodic) that alarms")
    print("at that same threshold. This is the irreducible floor: it is not noise,")
    print("it is services that are periodic on purpose and jitter less than a beacon.")
    for name, _ in scorers:
        print("  %-12s %5.1f%%" % (name, 100 * confound[name]))
    print()

    # Report jitter and PERIOD separately. Averaging over periods conflates two
    # independent limits: jitter smears phase, while a long period simply does
    # not produce enough check-ins for the statistic to clear any threshold.
    floor_n = min_events(thr["spectral"])
    print("Z2 <= 2N, so this threshold needs N >= %d check-ins: nothing slower than"
          % floor_n)
    print("one per %.0fs is detectable in this %.1fh window, at ANY jitter.\n"
          % (detectable_period(thr["spectral"], a.duration), a.duration / 3600.0))

    jitters = [0.0, 0.10, 0.20, 0.30, 0.50, 0.70]
    periods = [30.0, 60.0, 120.0, 300.0, 600.0]
    rows = []
    hdr = "%-9s" % "period" + "".join("%8s" % ("%d%%" % int(j * 100)) for j in jitters)
    print("SPECTRAL, detection rate by period and jitter")
    print(hdr)
    for P in periods:
        cells, n_ev = [], int(a.duration / P)
        for j in jitters:
            hit = tot = 0
            for _ in range(max(25, a.trials // len(periods))):
                t = beacon(P, a.duration, jitter=j, rng=rng)
                if len(t) < 8:
                    continue
                tot += 1
                hit += score_spectral(t) >= thr["spectral"]
            cells.append(hit / max(1, tot))
        rows.append({"period": P, "events": n_ev, "spectral_by_jitter": cells})
        mark = "" if n_ev >= floor_n else "   <- below the N floor"
        print("%-9s" % ("%ds" % int(P)) + "".join("%7.0f%%" % (100 * c) for c in cells) + mark)

    print("\nDISPERSION/SKEW control, same grid")
    print(hdr)
    for i, P in enumerate(periods):
        cells = []
        for j in jitters:
            hit = tot = 0
            for _ in range(max(25, a.trials // len(periods))):
                t = beacon(P, a.duration, jitter=j, rng=rng)
                if len(t) < 8:
                    continue
                tot += 1
                hit += rita_style_score(t) >= thr["rita-style"]
            cells.append(hit / max(1, tot))
        rows[i]["rita_by_jitter"] = cells
        print("%-9s" % ("%ds" % int(P)) + "".join("%7.0f%%" % (100 * c) for c in cells))
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w") as fh:
        json.dump({"fpr": a.fpr, "duration_s": a.duration, "trials": a.trials,
                   "thresholds": thr, "confound_periodic_benign": confound,
                   "min_events": min_events(thr["spectral"]),
                   "slowest_detectable_period_s": detectable_period(thr["spectral"], a.duration),
                   "jitters": jitters, "rows": rows}, fh, indent=1)
    print("\nwrote %s" % a.out)


if __name__ == "__main__":
    main()

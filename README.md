# beacon-spectrum

Finding periodic C2 check-ins in network timing — and measuring honestly what
that can and cannot do.

> **Status: research prototype.** The estimator, the synthetic corpus and the
> benchmark below are real and reproducible (`python src/benchmark.py`). Ingest
> of real pcap/Zeek logs is not built yet.

## The result that matters

Two detectors, thresholds pinned so **1% of aperiodic benign flows alarm**, over a
3-hour window. Reproduce with `python src/benchmark.py`.

**Spectral (Rayleigh Z²)** — detection rate by period and attacker jitter:

| period | 0% | 10% | 20% | 30% | 50% | 70% |
|---|---|---|---|---|---|---|
| 30 s | 100% | 100% | 100% | 100% | 0% | 0% |
| 60 s | 100% | 100% | 100% | 0% | 0% | 0% |
| 120 s | 100% | 100% | 4% | 0% | 0% | 0% |
| 300 s | 0% | 0% | 0% | 0% | 0% | 0% |
| 600 s | 0% | 0% | 0% | 0% | 0% | 0% |

**Dispersion/skew control** — same grid, ~100% almost everywhere, including 600 s
at 70% jitter.

Read those two tables alone and the control wins outright. Now the column that is
usually missing — share of **benign but genuinely periodic** flows (NTP,
telemetry, backups) that alarm at the same operating point:

| | false alarms on benign periodic traffic |
|---|---|
| spectral | **19.4%** |
| dispersion/skew | **98.0%** |

The dispersion score is not detecting beacons. It is detecting *regularity*, and
at this operating point it alarms on 98% of the periodic services on your
network. A detector that catches a 600 s beacon at 70% jitter and also pages you
for almost every NTP client has not solved the problem.

### Two independent limits, not one

The spectral table has a hard floor that is not about jitter at all.
**Z² = 2N·R², and R ≤ 1, so the statistic is bounded by 2N.** A *perfectly*
periodic beacon observed N times cannot score above twice its check-in count,
however clean it is. At this threshold that means **N ≥ 57 events** — nothing
slower than one check-in per 189 s is detectable in a 3-hour window **at any
jitter**. The 300 s and 600 s rows are zero for that reason, and no amount of
better math moves them; only a longer capture does.

Above the floor, jitter tolerance scales with N: a 30 s beacon survives 30%
jitter, a 120 s beacon only 10%, because more check-ins buy more averaging.

That gives an honest operating envelope rather than a single accuracy number:

```
detectable  iff  N >= threshold/2   AND   jitter below a period-dependent limit
```

Below the floor the correct output is **"not enough data"**, not "no beacon" —
`min_events()` and `detectable_period()` compute it, so the tool can say which
one it means.

### What this says about the problem

The hard part of beacon detection is not jitter. It is that legitimate periodic
traffic is periodic on purpose and jitters *less* than a competent beacon, so on
the periodicity axis the benign population looks more beacon-like than the beacon
does. Periodicity is a filter, not a verdict; the discriminating signal has to
come from elsewhere — destination rarity, whether a name was ever resolved,
data-volume symmetry, how long the pair has existed.

## Why not an FFT

Connection events are a **point process**: irregular arrival times, no sample
rate. An FFT assumes even spacing.

The obvious repair is to take the inter-arrival gaps and run an
irregular-sampling periodogram (Lomb-Scargle) over them. **That does not work**,
and the reason is worth stating because it is the first thing to reach for: a
beacon of period P produces gaps that are all ≈ P. That sequence is a constant
plus noise. It does not oscillate. Its periodogram is flat. The period lives in
the *value* of the gaps, not in any frequency among them.

What works is testing phase coherence of the event times directly:

```
R(f) = (1/N) · | Σₖ exp(2πi·f·tₖ) |
```

Events locked to period 1/f land at the same phase and their unit vectors add;
scattered events cancel. This is the Rayleigh test from pulsar timing. Under a
homogeneous Poisson null, `Z² = 2N·R²` is χ² with 2 degrees of freedom, which
gives a calibrated p-value rather than an arbitrary score.

Two details that are easy to get wrong:

- **Trials correction.** The p-value must be corrected for the number of
  *independent* frequencies searched (≈ span/P_min), not the grid length —
  oversampling a grid does not add independent trials. Without it a periodogram
  reliably "finds" a beacon in pure noise.
- **Do not rank by −log₁₀(p).** A strongly periodic flow underflows float64 to
  zero, so every clean beacon and every NTP client collapses onto the same
  saturated score and the threshold pins to the ceiling. Measured during
  development: that artifact alone dragged apparent detection at 0% jitter down
  to 64.5%. Rank by `Z²`, which carries the same evidence and has no ceiling.

## Honesty about the comparison

The `dispersion/skew` column is **my own reimplementation** of the
median-absolute-deviation + Bowley-skewness approach, scored on the same corpus.
It is not [RITA](https://github.com/activecm/rita) and these numbers should not
be read as benchmarking RITA. Comparing against the real tool on the same data is
the obvious next step.

The corpus is synthetic. That is deliberate — a detection-rate-versus-jitter
curve needs ground-truth labels, and real captures do not come labelled — but
synthetic benign traffic is a model of benign traffic, not benign traffic. The
next milestone is re-running the confound measurement against a real benign
baseline.

## End to end, on a capture

`python src/selftest_ingest.py` writes a pcap with a beacon planted in noise,
reads it back with no knowledge of what was planted, and recovers it:

```
wrote 501 packets (160 of them the planted beacon), 34.3 KB
parsed 4 flows back out
  round trip: 160/160 beacon packets recovered

flow                                events     period    p-value
10.0.0.5 -> 203.0.113.9:443            160      45.0s   0.00e+00  <- planted, 45.0s
10.0.0.5 -> 198.51.100.4:80            155      26.9s   1.35e-02
10.0.0.5 -> 203.0.113.200:123          112      64.0s   0.00e+00
10.0.0.7 -> 198.51.100.9:443            74      36.5s   7.83e-01
```

**Read the third row.** That is the NTP client, and it scores exactly as hard as
the beacon — p-value 0.00e+00, both of them. The statistic cannot separate them
and never will: the thing that distinguishes them is that one is on port 123
talking to a name that resolves, and the other is not. The two noisy flows are
correctly unremarkable.

This is the argument of the whole project in four rows: the periodogram did its
job perfectly and is still not a verdict.

Ingestion reads pcap and Zeek `conn.log`, and parses pcap directly rather than
via scapy or dpkt, so the tool stays dependency-free on a sensor. Only connection
STARTS are counted — a beacon is periodic in when it reaches out, and counting
every packet would measure the transfer instead of the schedule.

## Run it

```
python src/benchmark.py --trials 240 --duration 10800
```

No network, no captured traffic, no malware. Everything is generated.

## License

MIT.

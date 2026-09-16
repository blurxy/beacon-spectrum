# beacon-spectrum

Finding periodic C2 check-ins in network timing — and measuring honestly what
that can and cannot do.

> **Status: research prototype.** The estimator, the synthetic corpus and the
> benchmark below are real and reproducible (`python src/benchmark.py`). Ingest
> of real pcap/Zeek logs is not built yet.

## The result that matters

Two detectors, thresholds pinned so that **1% of aperiodic benign flows alarm**,
evaluated on 240 aperiodic-benign / 191 periodic-benign / 240-per-cell beacon
flows over a 3-hour window:

| attacker jitter | spectral (Rayleigh Z²) | dispersion/skew |
|---|---|---|
| 0%  | 57.9% | 100.0% |
| 10% | 59.6% | 99.2% |
| 20% | 36.7% | 98.8% |
| 30% | 18.8% | 96.2% |
| 50% | 0.0%  | 93.8% |
| 70% | 0.0%  | 87.1% |

Read that table alone and the dispersion score wins everywhere. Now the column
that is usually missing:

| | share of **benign but genuinely periodic** flows that alarm |
|---|---|
| spectral (Rayleigh Z²) | **23.6%** |
| dispersion/skew | **99.0%** |

The dispersion score is not detecting beacons. It is detecting *regularity*, and
your NTP client, telemetry agent, health check and backup job are all regular. At
the same operating point it alarms on 99% of them. A detector that catches 87% of
beacons at 70% jitter and also pages you for almost every periodic service on the
network has not solved the problem.

**So the hard part of beacon detection is not jitter. It is that legitimate
periodic traffic is periodic on purpose, and jitters less than a competent
beacon does.** No threshold on any periodicity statistic separates those two
populations, because on that axis the benign one looks *more* like a beacon than
the beacon does. Periodicity is a filter, not a verdict; the discriminating
signal has to come from somewhere else — destination rarity, whether a name was
ever resolved, data-volume symmetry, the duration the pair has existed.

That is the finding this repo exists to support, and it is measured, not asserted.

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

## Run it

```
python src/benchmark.py --trials 240 --duration 10800
```

No network, no captured traffic, no malware. Everything is generated.

## License

MIT.

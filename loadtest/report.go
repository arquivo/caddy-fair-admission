package loadtest

import (
	"fmt"
	"strings"
	"time"
)

// FormatReport renders results as a fixed-width table, one row per
// concurrency level, matching the shape REQUIREMENTS.md §8 asks the sweep to
// report: throughput and p50/p95/p99 vs. offered concurrency.
func FormatReport(results []LevelResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-12s %-10s %-8s %-16s %-10s %-10s %-10s\n",
		"concurrency", "requests", "errors", "throughput(req/s)", "p50", "p95", "p99")
	for _, r := range results {
		fmt.Fprintf(&b, "%-12d %-10d %-8d %-16.1f %-10s %-10s %-10s\n",
			r.Concurrency, r.Requests, r.Errors, r.ThroughputRPS,
			r.P50.Round(time.Millisecond), r.P95.Round(time.Millisecond), r.P99.Round(time.Millisecond))
	}
	return b.String()
}

// InversionReport is the outcome of comparing each level's throughput
// against the peak throughput seen at any lower-or-equal concurrency level.
type InversionReport struct {
	Inverted          bool
	PeakConcurrency   int
	PeakThroughputRPS float64
	// Detail explains the finding: which level dropped, by how much,
	// relative to the peak -- empty when Inverted is false.
	Detail string
}

// DetectInversion flags the same failure shape the Python investigation
// found (§8): throughput that peaks at some mid-range concurrency and then
// *drops* as offered concurrency keeps rising, rather than leveling off or
// continuing to climb. dropThreshold is the fraction below peak that counts
// as a genuine inversion rather than run-to-run noise (e.g. 0.15 = 15%).
func DetectInversion(results []LevelResult, dropThreshold float64) InversionReport {
	var peak InversionReport
	for _, r := range results {
		if r.ThroughputRPS > peak.PeakThroughputRPS {
			peak.PeakThroughputRPS = r.ThroughputRPS
			peak.PeakConcurrency = r.Concurrency
		}
	}
	if peak.PeakThroughputRPS == 0 {
		return peak
	}
	for _, r := range results {
		if r.Concurrency <= peak.PeakConcurrency {
			continue
		}
		drop := (peak.PeakThroughputRPS - r.ThroughputRPS) / peak.PeakThroughputRPS
		if drop >= dropThreshold {
			peak.Inverted = true
			peak.Detail = fmt.Sprintf(
				"throughput at concurrency %d (%.1f req/s) is %.0f%% below the peak of %.1f req/s at concurrency %d",
				r.Concurrency, r.ThroughputRPS, drop*100, peak.PeakThroughputRPS, peak.PeakConcurrency)
			return peak
		}
	}
	return peak
}

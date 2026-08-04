// Command loadtest drives loadtest.Sweep against a running Caddy instance
// (or any HTTP server) from the command line -- the standalone tool half of
// implementation_plan.md's Phase 11 (the "port scripts/load_test.py into
// /cmd/loadtest" deliverable). The reusable ramp/hold/measure engine itself
// lives in the importable /loadtest package so it can also be driven
// in-process from a test (see loadtest_e2e_test.go at the repo root).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/arquivo/caddy-adaptive-admission-controller/loadtest"
)

func main() {
	var (
		baseURL   = flag.String("url", "", "base URL to load test, e.g. http://127.0.0.1:8080 (required)")
		endpoints = flag.String("endpoints", "/", "comma-separated request paths to round-robin across")
		levels    = flag.String("levels", "50,75,100,150,200,250", "comma-separated offered-concurrency levels to sweep")
		rampUp    = flag.Duration("rampup", 2*time.Second, "time to stagger-start all workers at each level")
		hold      = flag.Duration("hold", 5*time.Second, "steady-state measurement window per level")
		reqTO     = flag.Duration("timeout", 10*time.Second, "per-request timeout")
		authz     = flag.String("authorization", "", "optional Authorization header value applied to every request")
		dropPct   = flag.Float64("inversion-drop-pct", 15, "flag a level as an inversion if its throughput falls this many percent below the peak seen at a lower concurrency level")
		jsonOut   = flag.String("json", "", "optional path to also write the results as JSON")
	)
	flag.Parse()

	if *baseURL == "" {
		fmt.Fprintln(os.Stderr, "loadtest: -url is required")
		os.Exit(2)
	}

	levelInts, err := parseLevels(*levels)
	if err != nil {
		fmt.Fprintf(os.Stderr, "loadtest: %v\n", err)
		os.Exit(2)
	}

	header := http.Header{}
	if *authz != "" {
		header.Set("Authorization", *authz)
	}

	target := loadtest.Target{
		BaseURL:   *baseURL,
		Endpoints: splitNonEmpty(*endpoints),
		Header:    header,
	}
	cfg := loadtest.Config{
		Levels:         levelInts,
		RampUp:         *rampUp,
		Hold:           *hold,
		RequestTimeout: *reqTO,
	}

	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        0,
			MaxIdleConnsPerHost: 4096,
			MaxConnsPerHost:     0,
			DisableCompression:  true,
		},
	}

	results, err := loadtest.Sweep(context.Background(), client, target, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "loadtest: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(loadtest.FormatReport(results))

	inv := loadtest.DetectInversion(results, *dropPct/100)
	if inv.Inverted {
		fmt.Printf("\nTHROUGHPUT INVERSION DETECTED: %s\n", inv.Detail)
	} else if inv.PeakThroughputRPS > 0 {
		fmt.Printf("\nno throughput inversion detected (peak %.1f req/s at concurrency %d)\n", inv.PeakThroughputRPS, inv.PeakConcurrency)
	}

	if *jsonOut != "" {
		f, err := os.Create(*jsonOut)
		if err != nil {
			fmt.Fprintf(os.Stderr, "loadtest: write json: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			fmt.Fprintf(os.Stderr, "loadtest: encode json: %v\n", err)
			os.Exit(1)
		}
	}

	if inv.Inverted {
		os.Exit(1)
	}
}

func parseLevels(s string) ([]int, error) {
	parts := splitNonEmpty(s)
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid concurrency level %q: %w", p, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func splitNonEmpty(s string) []string {
	raw := strings.Split(s, ",")
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		r = strings.TrimSpace(r)
		if r != "" {
			out = append(out, r)
		}
	}
	return out
}

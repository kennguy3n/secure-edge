//go:build large

// Regression tracking for the large DLP accuracy corpus.
//
// On every run, this test loads the same ~5,000-sample corpus as
// TestDLPAccuracyLarge, computes the current accuracy metrics, and
// compares them against `testdata/corpus/baseline_report.json` — the
// snapshot from the last accepted rule revision. The test fails when
// the new run regresses against the baseline:
//
//   - any TP-bearing category's recall drops by more than 2 percentage
//     points relative to the baseline, OR
//   - the overall FP rate increases by more than 1 percentage point.
//
// Both bounds are chosen to flag meaningful rule churn while tolerating
// the small per-run noise that comes from rng-seeded TN generators in
// `testdata/cmd/generate_corpus`. If the baseline does not yet exist,
// the test is skipped — first-time runs simply produce a report.
//
// When a rule update is intentional (i.e. the regression is the new
// baseline), re-run with `-update-baseline` to overwrite the snapshot:
//
//	go test -tags=large -run TestDLPAccuracyRegression ./internal/dlp/ -update-baseline
//
// Or, equivalently, copy `last_run_report.json` over `baseline_report.json`.
//
// Like the large test, this file is tagged `large` so the default fast
// smoke run remains untouched.

package dlp

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// updateBaseline, when set, overwrites the baseline_report.json file
// with the report produced by this run. Useful when a rule change has
// intentionally shifted the metrics.
var updateBaseline = flag.Bool("update-baseline", false,
	"write the current accuracy report to testdata/corpus/baseline_report.json instead of comparing against it")

// Regression bounds, intentionally laxer than the absolute budgets in
// TestDLPAccuracyLarge so that genuine improvements never fail the
// regression check, but any meaningful slip is surfaced loudly.
const (
	recallDropTolerance = 0.02 // 2 percentage points
	fpRateRiseTolerance = 0.01 // 1 percentage point
)

func baselinePath() string {
	return filepath.Join(corpusRoot(), "baseline_report.json")
}

// loadBaseline reads testdata/corpus/baseline_report.json into the
// accuracyReport struct from accuracy_large_test.go. Returns
// (nil, nil) if the file does not exist (first-run case).
func loadBaseline() (*accuracyReport, error) {
	path := baselinePath()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var r accuracyReport
	if err := json.NewDecoder(f).Decode(&r); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return &r, nil
}

func writeBaseline(r accuracyReport) error {
	path := baselinePath()
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

// indexCategories returns a category-name -> categoryReport map for
// quick diffing across runs.
func indexCategories(r accuracyReport) map[string]categoryReport {
	out := make(map[string]categoryReport, len(r.Categories))
	for _, c := range r.Categories {
		out[c.Category] = c
	}
	return out
}

func TestDLPAccuracyRegression(t *testing.T) {
	current, err := runAccuracyEvaluation(t)
	if err != nil {
		t.Fatalf("runAccuracyEvaluation: %v", err)
	}

	if *updateBaseline {
		if err := writeBaseline(current); err != nil {
			t.Fatalf("writeBaseline: %v", err)
		}
		t.Logf("baseline updated: %s", baselinePath())
		return
	}

	baseline, err := loadBaseline()
	if err != nil {
		t.Fatalf("loadBaseline: %v", err)
	}
	if baseline == nil {
		t.Skipf("no baseline_report.json yet — run with -update-baseline to seed it")
	}

	// Overall FP rate must not have risen by more than the tolerance.
	if delta := current.FPRate - baseline.FPRate; delta > fpRateRiseTolerance {
		t.Errorf("overall FP rate regression: %.4f → %.4f (delta +%.4f, tolerance %.4f)",
			baseline.FPRate, current.FPRate, delta, fpRateRiseTolerance)
	}

	// Per-category recall must not have dropped by more than the tolerance.
	baseCats := indexCategories(*baseline)
	curCats := indexCategories(current)

	// Stable iteration order for log output.
	names := make([]string, 0, len(baseCats))
	for n := range baseCats {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		base := baseCats[name]
		// Skip TN-only categories (no recall to track).
		if base.TP+base.FN == 0 {
			continue
		}
		cur, ok := curCats[name]
		if !ok {
			t.Errorf("category %q present in baseline but missing from current run", name)
			continue
		}
		if cur.TP+cur.FN == 0 {
			t.Errorf("category %q has zero positives in current run (was %d in baseline)",
				name, base.TP+base.FN)
			continue
		}
		if delta := base.Recall - cur.Recall; delta > recallDropTolerance {
			t.Errorf("category %q recall regression: %.4f → %.4f (delta -%.4f, tolerance %.4f)",
				name, base.Recall, cur.Recall, delta, recallDropTolerance)
		}
	}

	logRegressionDiff(t, *baseline, current)
}

// logRegressionDiff prints a compact category-level diff so reviewers
// can see which categories improved and which regressed even when the
// regression check passes overall.
func logRegressionDiff(t *testing.T, baseline, current accuracyReport) {
	t.Helper()
	t.Logf("=== Regression diff vs baseline (%s) ===", baseline.GeneratedAt)
	t.Logf("overall FP rate: %.4f → %.4f (Δ %+.4f)",
		baseline.FPRate, current.FPRate, current.FPRate-baseline.FPRate)
	t.Logf("overall FN rate: %.4f → %.4f (Δ %+.4f)",
		baseline.FNRate, current.FNRate, current.FNRate-baseline.FNRate)
	t.Logf("overall F1:      %.4f → %.4f (Δ %+.4f)",
		baseline.F1, current.F1, current.F1-baseline.F1)

	baseCats := indexCategories(baseline)
	curCats := indexCategories(current)
	names := make([]string, 0, len(baseCats))
	for n := range baseCats {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		base := baseCats[name]
		cur, ok := curCats[name]
		if !ok {
			continue
		}
		// Only emit rows where something actually moved.
		if base.Recall == cur.Recall && base.FPRate == cur.FPRate {
			continue
		}
		t.Logf("  %-25s recall %.4f → %.4f (Δ %+.4f)  fp_rate %.4f → %.4f (Δ %+.4f)",
			name,
			base.Recall, cur.Recall, cur.Recall-base.Recall,
			base.FPRate, cur.FPRate, cur.FPRate-base.FPRate)
	}
}

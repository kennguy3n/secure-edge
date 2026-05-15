//go:build large

// Large-scale DLP accuracy evaluation.
//
// Loads the full ~5,000-sample corpus from testdata/corpus/, runs the
// production pipeline against every sample, and reports:
//
//   - Overall FP rate, FN rate, precision, recall, F1.
//   - Per-category precision, recall, F1.
//   - Per-pattern FP count (with example labels) and FN count.
//   - List of every misclassified sample for debugging.
//
// Budget enforced as t.Fatalf at the end of the run:
//
//   - Overall FP rate     < 5%   (tightened from the smoke check)
//   - Overall FN rate     < 3%   (tightened from the smoke check)
//   - Per-category FN     < 10%  (no single category catastrophically fails)
//
// The test always writes a structured JSON report to
// testdata/corpus/last_run_report.json so CI (and the regression test
// in accuracy_regression_test.go) can archive the per-run accuracy
// snapshot for trend tracking.
//
// Tagged `large` so the default `go test ./internal/dlp/` smoke run
// stays fast. Invoke with:
//
//	go test -tags=large -run TestDLPAccuracyLarge ./internal/dlp/

package dlp

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func nowISO() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// corpusSample mirrors the JSONL record written by
// testdata/cmd/generate_corpus.
//
// The generator base64-encodes Content into ContentB64 so the
// committed corpus is invisible to GitHub's push-protection secret
// scanner (the corpus is full of format-valid synthetic Stripe /
// Twilio / GitHub PAT / etc. values by design). Decoded content is
// materialised once at load time — see loadCorpus.
type corpusSample struct {
	ID            string `json:"id"`
	Category      string `json:"category"`
	Pattern       string `json:"pattern,omitempty"`
	Content       string `json:"-"`
	ContentB64    string `json:"content_b64"`
	ExpectBlocked bool   `json:"expect_blocked"`
	Context       string `json:"context"`
	Source        string `json:"source"`
}

// categoryReport is one row in the per-category accuracy table.
type categoryReport struct {
	Category  string  `json:"category"`
	Total     int     `json:"total"`
	TP        int     `json:"tp"`
	FN        int     `json:"fn"`
	FP        int     `json:"fp"`
	TN        int     `json:"tn"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
	FPRate    float64 `json:"fp_rate"`
	FNRate    float64 `json:"fn_rate"`
}

// patternFPRow is one row in the per-pattern false positive report.
type patternFPRow struct {
	Pattern        string   `json:"pattern"`
	FPCount        int      `json:"fp_count"`
	TotalNegatives int      `json:"total_negatives"`
	FPRate         float64  `json:"fp_rate"`
	ExampleLabels  []string `json:"example_labels"`
}

// patternFNRow is one row in the per-pattern false negative report.
type patternFNRow struct {
	Pattern        string   `json:"pattern"`
	FNCount        int      `json:"fn_count"`
	TotalPositives int      `json:"total_positives"`
	FNRate         float64  `json:"fn_rate"`
	ExampleLabels  []string `json:"example_labels"`
}

// accuracyReport is the JSON structure persisted at
// testdata/corpus/last_run_report.json.
type accuracyReport struct {
	GeneratedAt    string           `json:"generated_at"`
	Corpus         string           `json:"corpus"`
	TotalSamples   int              `json:"total_samples"`
	TotalPositives int              `json:"total_positives"`
	TotalNegatives int              `json:"total_negatives"`
	TP             int              `json:"tp"`
	FN             int              `json:"fn"`
	FP             int              `json:"fp"`
	TN             int              `json:"tn"`
	Precision      float64          `json:"precision"`
	Recall         float64          `json:"recall"`
	F1             float64          `json:"f1"`
	FPRate         float64          `json:"fp_rate"`
	FNRate         float64          `json:"fn_rate"`
	Budget         budgetSnapshot   `json:"budget"`
	Categories     []categoryReport `json:"categories"`
	PatternFPs     []patternFPRow   `json:"pattern_false_positives"`
	PatternFNs     []patternFNRow   `json:"pattern_false_negatives"`
}

type budgetSnapshot struct {
	OverallFPMax  float64 `json:"overall_fp_max"`
	OverallFNMax  float64 `json:"overall_fn_max"`
	PerCategoryFN float64 `json:"per_category_fn_max"`
}

const (
	overallFPBudget  = 0.05
	overallFNBudget  = 0.03
	categoryFNBudget = 0.10
)

// repoRoot resolves the repository root by walking up from this file.
// We rely on runtime.Caller so the lookup is robust regardless of
// where `go test` is invoked from.
func repoRootFromHere() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
}

// corpusRoot returns the absolute path to testdata/corpus/.
func corpusRoot() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "testdata", "corpus"))
}

// loadCorpus walks testdata/corpus/{kind}/ and parses every *.jsonl
// file beneath it. Hand-authored .jsonl files coexist with the
// generator's synthetic-v1.jsonl outputs; both are loaded.
func loadCorpus(t *testing.T) []corpusSample {
	t.Helper()
	root := corpusRoot()
	var out []corpusSample
	for _, kind := range []string{"true_positives", "true_negatives"} {
		base := filepath.Join(root, kind)
		err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".jsonl") {
				return nil
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 1<<20), 1<<22)
			line := 0
			for scanner.Scan() {
				line++
				raw := scanner.Bytes()
				if len(raw) == 0 {
					continue
				}
				var s corpusSample
				if err := json.Unmarshal(raw, &s); err != nil {
					return fmt.Errorf("%s:%d: %w", path, line, err)
				}
				if s.ContentB64 == "" {
					return fmt.Errorf("%s:%d: missing content_b64 field (regenerate corpus)", path, line)
				}
				decoded, err := base64.StdEncoding.DecodeString(s.ContentB64)
				if err != nil {
					return fmt.Errorf("%s:%d: decode content_b64: %w", path, line, err)
				}
				s.Content = string(decoded)
				out = append(out, s)
			}
			return scanner.Err()
		})
		if err != nil {
			t.Fatalf("walk corpus %s: %v", base, err)
		}
	}
	if len(out) == 0 {
		t.Fatalf("loadCorpus: no samples found under %s — run `go run ./internal/dlp/testdata/cmd/generate_corpus`", root)
	}
	return out
}

func TestDLPAccuracyLarge(t *testing.T) {
	report, err := runAccuracyEvaluation(t)
	if err != nil {
		t.Fatalf("runAccuracyEvaluation: %v", err)
	}

	// Always persist the report — even on failure — so CI can archive
	// it for regression analysis.
	if err := writeReport(report); err != nil {
		t.Logf("writeReport: %v", err)
	}

	logReport(t, report)

	// Enforce budgets.
	if report.FPRate >= overallFPBudget {
		t.Errorf("FP rate %.4f exceeds overall budget %.4f (%d/%d negatives blocked)",
			report.FPRate, overallFPBudget, report.FP, report.TotalNegatives)
	}
	if report.FNRate >= overallFNBudget {
		t.Errorf("FN rate %.4f exceeds overall budget %.4f (%d/%d positives missed)",
			report.FNRate, overallFNBudget, report.FN, report.TotalPositives)
	}
	for _, cat := range report.Categories {
		// Per-category FN budget only applies to TP-bearing categories.
		if cat.Total == cat.FP+cat.TN {
			continue
		}
		positives := cat.TP + cat.FN
		if positives == 0 {
			continue
		}
		if cat.FNRate >= categoryFNBudget {
			t.Errorf("category %q FN rate %.4f exceeds per-category budget %.4f (%d/%d positives missed)",
				cat.Category, cat.FNRate, categoryFNBudget, cat.FN, positives)
		}
	}
}

// runAccuracyEvaluation is the core evaluation loop shared with the
// regression test. It loads the corpus, runs the pipeline, and returns
// the structured report.
func runAccuracyEvaluation(t *testing.T) (accuracyReport, error) {
	t.Helper()
	p := loadProductionPipeline(t)
	samples := loadCorpus(t)

	report := accuracyReport{
		Corpus:       filepath.Base(repoRootFromHere()) + "/agent/internal/dlp/testdata/corpus",
		TotalSamples: len(samples),
		Budget: budgetSnapshot{
			OverallFPMax:  overallFPBudget,
			OverallFNMax:  overallFNBudget,
			PerCategoryFN: categoryFNBudget,
		},
	}

	type catStats struct {
		total, tp, fn, fp, tn int
	}
	catBuckets := make(map[string]*catStats)
	getCat := func(name string) *catStats {
		s, ok := catBuckets[name]
		if !ok {
			s = &catStats{}
			catBuckets[name] = s
		}
		return s
	}

	// Pattern-level breakdowns:
	//   FP map: scanned-and-blocked pattern -> sample IDs (negatives)
	//   FN map: expected pattern             -> sample IDs (positives missed)
	patternFPSamples := make(map[string][]string)
	patternFNSamples := make(map[string][]string)
	patternFPCounts := make(map[string]int)
	patternFNCounts := make(map[string]int)
	patternTPCounts := make(map[string]int)

	totalPositives := 0
	totalNegatives := 0

	ctx := context.Background()
	for _, s := range samples {
		bucket := getCat(s.Category)
		bucket.total++
		res := p.Scan(ctx, s.Content)
		if s.ExpectBlocked {
			totalPositives++
			if res.Blocked {
				bucket.tp++
				report.TP++
				patternTPCounts[s.Pattern]++
			} else {
				bucket.fn++
				report.FN++
				patternFNCounts[s.Pattern]++
				if len(patternFNSamples[s.Pattern]) < 5 {
					patternFNSamples[s.Pattern] = append(patternFNSamples[s.Pattern], s.ID)
				}
			}
		} else {
			totalNegatives++
			if res.Blocked {
				bucket.fp++
				report.FP++
				patternFPCounts[res.PatternName]++
				if len(patternFPSamples[res.PatternName]) < 5 {
					patternFPSamples[res.PatternName] = append(patternFPSamples[res.PatternName],
						fmt.Sprintf("%s [%s]", s.ID, s.Category))
				}
			} else {
				bucket.tn++
				report.TN++
			}
		}
	}

	report.TotalPositives = totalPositives
	report.TotalNegatives = totalNegatives
	report.Precision = safeDiv(report.TP, report.TP+report.FP)
	report.Recall = safeDiv(report.TP, report.TP+report.FN)
	if report.Precision+report.Recall > 0 {
		report.F1 = 2 * report.Precision * report.Recall / (report.Precision + report.Recall)
	}
	if totalNegatives > 0 {
		report.FPRate = float64(report.FP) / float64(totalNegatives)
	}
	if totalPositives > 0 {
		report.FNRate = float64(report.FN) / float64(totalPositives)
	}

	// Build sorted category report.
	catNames := make([]string, 0, len(catBuckets))
	for name := range catBuckets {
		catNames = append(catNames, name)
	}
	sort.Strings(catNames)
	for _, name := range catNames {
		s := catBuckets[name]
		row := categoryReport{
			Category: name,
			Total:    s.total,
			TP:       s.tp,
			FN:       s.fn,
			FP:       s.fp,
			TN:       s.tn,
		}
		row.Precision = safeDiv(s.tp, s.tp+s.fp)
		row.Recall = safeDiv(s.tp, s.tp+s.fn)
		if row.Precision+row.Recall > 0 {
			row.F1 = 2 * row.Precision * row.Recall / (row.Precision + row.Recall)
		}
		if s.tn+s.fp > 0 {
			row.FPRate = float64(s.fp) / float64(s.tn+s.fp)
		}
		if s.tp+s.fn > 0 {
			row.FNRate = float64(s.fn) / float64(s.tp+s.fn)
		}
		report.Categories = append(report.Categories, row)
	}

	// Pattern FP rows — only patterns with at least one FP.
	for name, cnt := range patternFPCounts {
		row := patternFPRow{
			Pattern:        name,
			FPCount:        cnt,
			TotalNegatives: totalNegatives,
			ExampleLabels:  patternFPSamples[name],
		}
		if totalNegatives > 0 {
			row.FPRate = float64(cnt) / float64(totalNegatives)
		}
		report.PatternFPs = append(report.PatternFPs, row)
	}
	sort.Slice(report.PatternFPs, func(i, j int) bool {
		return report.PatternFPs[i].FPCount > report.PatternFPs[j].FPCount
	})

	// Pattern FN rows — only patterns with at least one FN.
	for name, cnt := range patternFNCounts {
		total := cnt + patternTPCounts[name]
		row := patternFNRow{
			Pattern:        name,
			FNCount:        cnt,
			TotalPositives: total,
			ExampleLabels:  patternFNSamples[name],
		}
		if total > 0 {
			row.FNRate = float64(cnt) / float64(total)
		}
		report.PatternFNs = append(report.PatternFNs, row)
	}
	sort.Slice(report.PatternFNs, func(i, j int) bool {
		return report.PatternFNs[i].FNCount > report.PatternFNs[j].FNCount
	})

	report.GeneratedAt = nowISO()
	return report, nil
}

func writeReport(r accuracyReport) error {
	path := filepath.Join(corpusRoot(), "last_run_report.json")
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

func logReport(t *testing.T, r accuracyReport) {
	t.Helper()
	t.Logf("=== DLP accuracy: large corpus ===")
	t.Logf("corpus=%d positives=%d negatives=%d", r.TotalSamples, r.TotalPositives, r.TotalNegatives)
	t.Logf("TP=%d FN=%d FP=%d TN=%d", r.TP, r.FN, r.FP, r.TN)
	t.Logf("precision=%.4f recall=%.4f F1=%.4f", r.Precision, r.Recall, r.F1)
	t.Logf("fp_rate=%.4f (budget %.4f)  fn_rate=%.4f (budget %.4f)",
		r.FPRate, overallFPBudget, r.FNRate, overallFNBudget)

	t.Logf("--- Per-category report ---")
	t.Logf("%-22s | %5s | %5s | %5s | %5s | %5s | %7s | %7s | %7s",
		"category", "total", "tp", "fn", "fp", "tn", "prec", "recall", "f1")
	for _, c := range r.Categories {
		t.Logf("%-22s | %5d | %5d | %5d | %5d | %5d | %7.4f | %7.4f | %7.4f",
			c.Category, c.Total, c.TP, c.FN, c.FP, c.TN, c.Precision, c.Recall, c.F1)
	}

	if len(r.PatternFPs) > 0 {
		t.Logf("--- Per-pattern false positive report ---")
		for _, row := range r.PatternFPs {
			t.Logf("Pattern %q: %d FPs out of %d negatives (%.4f%%)",
				row.Pattern, row.FPCount, row.TotalNegatives, row.FPRate*100)
			for _, lbl := range row.ExampleLabels {
				t.Logf("    - %s", lbl)
			}
		}
	}
	if len(r.PatternFNs) > 0 {
		t.Logf("--- Per-pattern false negative report ---")
		for _, row := range r.PatternFNs {
			t.Logf("Pattern %q: %d FNs out of %d positives (%.4f%%)",
				row.Pattern, row.FNCount, row.TotalPositives, row.FNRate*100)
			for _, lbl := range row.ExampleLabels {
				t.Logf("    - %s", lbl)
			}
		}
	}
}

func safeDiv(num, den int) float64 {
	if den == 0 {
		return 0
	}
	v := float64(num) / float64(den)
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return v
}

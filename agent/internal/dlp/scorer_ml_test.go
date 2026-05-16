// Tests for the ML borderline nudge in ScoreMatch (W3, draft).
//
// These tests exercise the *additive* contract of the ML signal: a
// non-zero MLScore must adjust the deterministic score only when
//
//   - SeverityThreshold > 0 (caller opted in to ML augmentation), AND
//   - the deterministic score is within mlBorderlineWidth of the
//     supplied SeverityThreshold.
//
// In every other configuration ScoreMatch must produce exactly the
// same value as the W2 deterministic pipeline. The W4 accuracy
// regression depends on that invariant.

package dlp

import "testing"

func TestScoreMatch_MLScoreIgnoredWithoutSeverityThreshold(t *testing.T) {
	w := DefaultScoreWeights()
	w.MLBoost = 5
	in := ScoreInput{
		Pattern:           Pattern{ScoreWeight: 3},
		Weights:           w,
		MLScore:           1.0,
		SeverityThreshold: 0, // explicit opt-out
	}
	if got := ScoreMatch(in); got != 3 {
		t.Errorf("ScoreMatch with SeverityThreshold=0 = %d, want 3 (ML must be inert)", got)
	}
}

func TestScoreMatch_MLScoreIgnoredOnHighConfidence(t *testing.T) {
	w := DefaultScoreWeights()
	w.MLBoost = 5
	// Deterministic score == 5, threshold == 2 — clearly above by
	// 3 points, well outside mlBorderlineWidth==1. MLScore should
	// have no effect, positive or negative.
	for _, ml := range []float32{-1.0, -0.5, 0.5, 1.0} {
		in := ScoreInput{
			Pattern:           Pattern{ScoreWeight: 5},
			Weights:           w,
			MLScore:           ml,
			SeverityThreshold: 2,
		}
		if got := ScoreMatch(in); got != 5 {
			t.Errorf("ScoreMatch(MLScore=%v) = %d, want 5 (high-confidence block immune to ML)", ml, got)
		}
	}
}

func TestScoreMatch_MLScoreLiftsBorderlineMatch(t *testing.T) {
	w := DefaultScoreWeights()
	w.MLBoost = 1
	// Deterministic score == 2, threshold == 3 — exactly one point
	// below, inside the borderline window. A positive MLScore must
	// lift the score; capped to ±MLBoost.
	//
	// Use a *realistic* non-saturated MLScore: real tanh outputs
	// from a sentence-embedding head rarely reach ±1.0; ±0.7–±0.95
	// is the typical range. The scorer must round 0.7 × 1 to 1,
	// not truncate it to 0.
	in := ScoreInput{
		Pattern:           Pattern{ScoreWeight: 2},
		Weights:           w,
		MLScore:           0.7,
		SeverityThreshold: 3,
	}
	if got := ScoreMatch(in); got != 3 {
		t.Errorf("ScoreMatch(borderline, MLScore=0.7) = %d, want 3 (lifted by +1)", got)
	}
}

func TestScoreMatch_MLScoreDropsBorderlineMatch(t *testing.T) {
	w := DefaultScoreWeights()
	w.MLBoost = 1
	// Deterministic score == 3, threshold == 3 — at the threshold,
	// inside borderline window. A negative MLScore must drag the
	// score back below the threshold.
	//
	// Realistic non-saturated MLScore (−0.85). The scorer must
	// round −0.85 × 1 to −1, not truncate it to 0.
	in := ScoreInput{
		Pattern:           Pattern{ScoreWeight: 3},
		Weights:           w,
		MLScore:           -0.85,
		SeverityThreshold: 3,
	}
	if got := ScoreMatch(in); got != 2 {
		t.Errorf("ScoreMatch(at-threshold, MLScore=-0.85) = %d, want 2 (dropped by -1)", got)
	}
}

func TestScoreMatch_MLScoreClampedByMLBoost(t *testing.T) {
	w := DefaultScoreWeights()
	w.MLBoost = 2
	// Deterministic score == 4, threshold == 3 — within borderline
	// (distance = 1). MLScore = 1.0, but the nudge must clamp to
	// ±MLBoost (2). The nudge must NOT exceed +2.
	in := ScoreInput{
		Pattern:           Pattern{ScoreWeight: 4},
		Weights:           w,
		MLScore:           1.0,
		SeverityThreshold: 3,
	}
	got := ScoreMatch(in)
	if got != 4+2 {
		t.Errorf("ScoreMatch clamp = %d, want 6 (4 + clamp(1.0 * 2)=2)", got)
	}
}

func TestScoreMatch_MLScoreFallsBackToDefaultBoost(t *testing.T) {
	// MLBoost left at zero (the default) — ScoreMatch should fall
	// back to DefaultMLBoost so the ML signal still has the
	// minimum-trust effect of ±1. Realistic MLScore == 0.6 to
	// guard against int() truncation regressions: 0.6 rounds to 1.
	w := DefaultScoreWeights()
	in := ScoreInput{
		Pattern:           Pattern{ScoreWeight: 2},
		Weights:           w,
		MLScore:           0.6,
		SeverityThreshold: 3,
	}
	if got := ScoreMatch(in); got != 3 {
		t.Errorf("ScoreMatch fallback to DefaultMLBoost = %d, want 3 (lifted by +1)", got)
	}
}

func TestScoreMatch_ZeroMLScoreIsInert(t *testing.T) {
	w := DefaultScoreWeights()
	w.MLBoost = 5
	in := ScoreInput{
		Pattern:           Pattern{ScoreWeight: 3},
		Weights:           w,
		MLScore:           0.0,
		SeverityThreshold: 3,
	}
	if got := ScoreMatch(in); got != 3 {
		t.Errorf("ScoreMatch(MLScore=0) = %d, want 3 (no nudge when MLScore is zero)", got)
	}
}

func TestScoreMatch_MLNudgeRespectsBorderlineWidth(t *testing.T) {
	// distance == mlBorderlineWidth+1 (== 2) — outside borderline,
	// nudge must NOT apply.
	w := DefaultScoreWeights()
	w.MLBoost = 1
	in := ScoreInput{
		Pattern:           Pattern{ScoreWeight: 1},
		Weights:           w,
		MLScore:           1.0,
		SeverityThreshold: 3,
	}
	if got := ScoreMatch(in); got != 1 {
		t.Errorf("ScoreMatch(distance=2) = %d, want 1 (outside borderline window)", got)
	}
}

// TestScoreMatch_MLScoreRoundsAwayFromZero covers the rounding
// contract directly. With MLBoost==1, an MLScore of 0.5 must round
// to a +1 nudge, an MLScore of −0.5 must round to −1, and
// |MLScore| < 0.5 must round to 0 (no nudge). This is a regression
// test for the int() truncation bug that made the disambiguator a
// no-op for any realistic non-saturated MLScore.
func TestScoreMatch_MLScoreRoundsAwayFromZero(t *testing.T) {
	w := DefaultScoreWeights()
	w.MLBoost = 1
	cases := []struct {
		name    string
		mlScore float32
		want    int // expected final score; base is 3, threshold is 3
	}{
		// Below the rounding boundary: nudge rounds to 0,
		// score stays at the deterministic value.
		{"plus_low", 0.2, 3},
		{"plus_at_boundary_minus", 0.49, 3},
		{"minus_low", -0.2, 3},
		{"minus_at_boundary_minus", -0.49, 3},

		// At or above the rounding boundary: nudge rounds to ±1.
		{"plus_at_boundary", 0.5, 4},
		{"plus_typical", 0.7, 4},
		{"plus_high", 0.95, 4},
		{"plus_saturated", 1.0, 4},
		{"minus_at_boundary", -0.5, 2},
		{"minus_typical", -0.7, 2},
		{"minus_high", -0.95, 2},
		{"minus_saturated", -1.0, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := ScoreInput{
				Pattern:           Pattern{ScoreWeight: 3},
				Weights:           w,
				MLScore:           tc.mlScore,
				SeverityThreshold: 3,
			}
			if got := ScoreMatch(in); got != tc.want {
				t.Errorf("ScoreMatch(MLScore=%v) = %d, want %d", tc.mlScore, got, tc.want)
			}
		})
	}
}

// TestScoreMatch_MLScoreClampedAtMLBoost2 verifies that MLBoost==2
// still rounds correctly when the MLScore is in the typical 0.3–0.9
// range. Before the fix, an MLScore of 0.3 × 2 = 0.6 truncated to 0;
// now it must round to 1.
func TestScoreMatch_MLScoreClampedAtMLBoost2(t *testing.T) {
	w := DefaultScoreWeights()
	w.MLBoost = 2
	cases := []struct {
		name    string
		mlScore float32
		want    int
	}{
		{"0.3_rounds_to_+1", 0.3, 4},
		{"0.7_rounds_to_+1", 0.7, 4},  // 0.7 * 2 = 1.4 → 1
		{"0.8_rounds_to_+2", 0.8, 5},  // 0.8 * 2 = 1.6 → 2
		{"0.95_clamps_to_+2", 0.95, 5}, // 0.95 * 2 = 1.9 → 2 (clamp ceiling)
		{"-0.3_rounds_to_-1", -0.3, 2},
		{"-0.7_rounds_to_-1", -0.7, 2},
		{"-0.8_rounds_to_-2", -0.8, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := ScoreInput{
				Pattern:           Pattern{ScoreWeight: 3},
				Weights:           w,
				MLScore:           tc.mlScore,
				SeverityThreshold: 3,
			}
			if got := ScoreMatch(in); got != tc.want {
				t.Errorf("ScoreMatch(MLScore=%v, MLBoost=2) = %d, want %d", tc.mlScore, got, tc.want)
			}
		})
	}
}

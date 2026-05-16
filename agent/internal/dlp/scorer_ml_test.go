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
	in := ScoreInput{
		Pattern:           Pattern{ScoreWeight: 2},
		Weights:           w,
		MLScore:           1.0,
		SeverityThreshold: 3,
	}
	if got := ScoreMatch(in); got != 3 {
		t.Errorf("ScoreMatch(borderline, MLScore=1) = %d, want 3 (lifted by +1)", got)
	}
}

func TestScoreMatch_MLScoreDropsBorderlineMatch(t *testing.T) {
	w := DefaultScoreWeights()
	w.MLBoost = 1
	// Deterministic score == 3, threshold == 3 — at the threshold,
	// inside borderline window. A negative MLScore must drag the
	// score back below the threshold.
	in := ScoreInput{
		Pattern:           Pattern{ScoreWeight: 3},
		Weights:           w,
		MLScore:           -1.0,
		SeverityThreshold: 3,
	}
	if got := ScoreMatch(in); got != 2 {
		t.Errorf("ScoreMatch(at-threshold, MLScore=-1) = %d, want 2 (dropped by -1)", got)
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
	// minimum-trust effect of ±1.
	w := DefaultScoreWeights()
	in := ScoreInput{
		Pattern:           Pattern{ScoreWeight: 2},
		Weights:           w,
		MLScore:           1.0,
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

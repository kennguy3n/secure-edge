// Multi-signal scoring aggregator (pipeline step 4d).
//
// Implements the scoring formula from ARCHITECTURE.md lines 148–176:
//
//	score = score_weight
//	      + (hotword ? hotword_boost : 0)
//	      + (entropy >= entropy_min ? entropy_boost : entropy_penalty)
//	      + multi_match_boost * min(num_matches - 1, multi_match_cap)
//	      + (exclusion_hit ? exclusion_penalty : 0)
//	      + ML borderline nudge (see W3 / ml package)
//
// Per-pattern overrides win over global weights when present.

package dlp

// multiMatchCap is the maximum number of "extra" matches that
// contribute multi_match_boost to the score. Without a cap a single
// blob full of emails would drown out higher-severity hits.
const multiMatchCap = 5

// mlBorderlineWidth controls how close to the pattern's severity
// threshold the deterministic score must already be before the ML
// disambiguator is allowed to influence the score. High-confidence
// blocks (score ≥ threshold + mlBorderlineWidth) and high-confidence
// non-blocks (score ≤ threshold - mlBorderlineWidth) are immune to
// the ML signal: the deterministic pipeline retains full veto power
// on every confident decision. This is the property that makes the
// ML layer reviewable line-by-line under the AGENTS.md data-path
// constraints.
const mlBorderlineWidth = 1

// ScoreInput is everything the scorer needs to score a single match.
type ScoreInput struct {
	Pattern        Pattern
	Match          Match
	HotwordPresent bool
	Entropy        float64
	NumMatches     int // total number of matches for this Pattern
	ExclusionHit   bool
	Weights        ScoreWeights

	// MLScore is the (optional) ML disambiguator output for this
	// scan, in [-1, 1]. Zero means "no ML signal" (either the ML
	// layer is disabled or the embedder errored — see
	// agent/internal/dlp/ml). Positive values lean "real match";
	// negative values lean "false positive". Only consulted by
	// ScoreMatch for borderline deterministic scores (see
	// mlBorderlineWidth).
	MLScore float32

	// SeverityThreshold is the minimum deterministic score the
	// pattern's severity must reach to be blocked. Passed in so
	// ScoreMatch can compute "how borderline is this match" without
	// reaching back into the threshold engine. Zero disables the
	// ML borderline gate — ScoreMatch then ignores MLScore.
	SeverityThreshold int
}

// ScoreMatch returns the aggregate score for one match.
func ScoreMatch(in ScoreInput) int {
	score := in.Pattern.ScoreWeight
	if score <= 0 {
		score = 1
	}

	if in.HotwordPresent {
		boost := in.Pattern.HotwordBoost
		if boost == 0 {
			boost = in.Weights.HotwordBoost
		}
		score += boost
	}

	if in.Pattern.EntropyMin > 0 {
		if in.Entropy >= in.Pattern.EntropyMin {
			score += in.Weights.EntropyBoost
		} else {
			score += in.Weights.EntropyPenalty
		}
	}

	if in.NumMatches > 1 {
		extra := in.NumMatches - 1
		if extra > multiMatchCap {
			extra = multiMatchCap
		}
		score += in.Weights.MultiMatchBoost * extra
	}

	if in.ExclusionHit {
		score += in.Weights.ExclusionPenalty
	}

	// ML borderline nudge. Only applied when:
	//   - the ML layer produced a non-zero score (MLScore != 0), and
	//   - the caller supplied a severity threshold (gates the nudge
	//     to call sites that opt in), and
	//   - the deterministic score is within mlBorderlineWidth of
	//     the threshold (so high-confidence blocks/non-blocks are
	//     never overridden).
	//
	// The nudge magnitude is capped at MLBoost (default 1) so the
	// ML layer can flip a borderline match across the line in either
	// direction but cannot drag a clearly-above match below it.
	if in.MLScore != 0 && in.SeverityThreshold > 0 {
		distance := score - in.SeverityThreshold
		if distance < 0 {
			distance = -distance
		}
		if distance <= mlBorderlineWidth {
			boost := in.Weights.MLBoost
			if boost <= 0 {
				boost = DefaultMLBoost
			}
			nudge := int(in.MLScore * float32(boost))
			if nudge > boost {
				nudge = boost
			} else if nudge < -boost {
				nudge = -boost
			}
			score += nudge
		}
	}

	return score
}

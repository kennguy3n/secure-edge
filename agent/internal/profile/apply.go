package profile

import (
	"context"
	"errors"
	"fmt"
)

// CategoryPolicy is one row in the batch passed to PolicyStore.ApplyProfileTx.
// Mirrors store.CategoryPolicy field-for-field so the adapter in
// cmd/agent can copy values across the package boundary without
// taking an import dependency on store from within profile.
type CategoryPolicy struct {
	Category string
	Action   string
}

// PolicyStore is the subset of store.Store the profile applier needs.
// Keeping it as an interface avoids a profile→store import cycle and
// lets apply_test.go drive the call sequence with an in-memory fake.
//
// ApplyProfileTx is the load-bearing path for a profile import — it
// writes every category policy and the DLP config atomically inside a
// single SQLite transaction so a half-applied profile can never be
// observed. SetPolicy / SetDLPConfig remain on the interface for the
// per-row API surface (PUT /api/policies/:category and PUT
// /api/dlp/config) and for fakes used by older tests.
type PolicyStore interface {
	SetPolicy(ctx context.Context, category, action string) error
	GetDLPConfig(ctx context.Context) (DLPConfigSnapshot, error)
	SetDLPConfig(ctx context.Context, cfg DLPConfigSnapshot) error
	ApplyProfileTx(ctx context.Context, categories []CategoryPolicy, dlpConfig *DLPConfigSnapshot) error
}

// DLPConfigSnapshot mirrors store.DLPConfig field-for-field. Keeping
// the snapshot type in the profile package lets the API and main
// wire the boundary without the profile package importing store.
type DLPConfigSnapshot struct {
	ThresholdCritical int
	ThresholdHigh     int
	ThresholdMedium   int
	ThresholdLow      int
	HotwordBoost      int
	EntropyBoost      int
	EntropyPenalty    int
	ExclusionPenalty  int
	MultiMatchBoost   int
}

// PolicyReloader is the subset of policy.Engine the profile applier
// needs. May be nil — callers that don't run a policy engine (e.g.
// the Native Messaging mode) skip the reload step.
type PolicyReloader interface {
	Reload(ctx context.Context) error
}

// ApplyOptions wires the applier to its collaborators. PolicyStore
// must be non-nil; the others may be nil to opt out of that step.
type ApplyOptions struct {
	PolicyStore PolicyStore
	Reloader    PolicyReloader
	// DLPSink, when non-nil, is invoked with the merged DLP snapshot
	// after it has been written to the store. Callers use this hook
	// to push the new thresholds and weights into the live DLP
	// pipeline — without it the persisted values would only take
	// effect on the next agent restart, silently diverging from
	// what GET /api/dlp/config and GET /api/profile report.
	DLPSink func(DLPConfigSnapshot)
}

// ErrProfilePersistedNotLive is returned by Apply when the profile
// committed to disk successfully but the live policy engine failed
// to reload. Callers (the API and cmd/agent's boot path) surface a
// "restart required" warning to the operator because the agent will
// continue running the previous in-memory policy until restart even
// though SQLite reflects the new profile.
var ErrProfilePersistedNotLive = errors.New("profile: persisted but not live — restart required")

// Apply pushes the profile's category actions and DLP thresholds into
// the store inside a single transaction, then rebuilds the live policy
// engine. The persist step is all-or-nothing: validation runs against
// every value before the transaction is opened, so a partial profile
// can never be observed on disk.
//
// Errors during the commit short-circuit before the live pipeline is
// updated, leaving the agent on its previous policy. Errors after
// the commit return ErrProfilePersistedNotLive so callers know the
// on-disk picture moved forward but a restart is needed for the
// in-memory engine to catch up.
func (p *Profile) Apply(ctx context.Context, opts ApplyOptions) error {
	if p == nil {
		return errors.New("profile: apply on nil profile")
	}
	if opts.PolicyStore == nil {
		return errors.New("profile: PolicyStore is required")
	}

	categories := make([]CategoryPolicy, 0, len(p.Categories))
	for cat, act := range p.Categories {
		categories = append(categories, CategoryPolicy{Category: cat, Action: act})
	}

	var merged DLPConfigSnapshot
	var mergedPtr *DLPConfigSnapshot
	if t := p.DLPThresholds; t != nil {
		// Merge in the profile's overrides on top of the existing
		// row so a profile that only ships ThresholdCritical leaves
		// every other knob untouched.
		cur, err := opts.PolicyStore.GetDLPConfig(ctx)
		if err != nil {
			return fmt.Errorf("profile: read dlp_config: %w", err)
		}
		merged = mergeDLP(cur, *t)
		mergedPtr = &merged
	}

	if err := opts.PolicyStore.ApplyProfileTx(ctx, categories, mergedPtr); err != nil {
		return fmt.Errorf("profile: apply tx: %w", err)
	}

	// Persist succeeded. From here on the on-disk picture reflects
	// the new profile; any failure must surface as
	// ErrProfilePersistedNotLive so the operator knows a restart
	// (not a re-import) is the remediation.
	if mergedPtr != nil && opts.DLPSink != nil {
		opts.DLPSink(merged)
	}
	if opts.Reloader != nil {
		if err := opts.Reloader.Reload(ctx); err != nil {
			return fmt.Errorf("%w: %v", ErrProfilePersistedNotLive, err)
		}
	}
	return nil
}

// mergeDLP returns cur with any non-zero field from override copied
// over. Zero is treated as "leave the existing knob alone" so
// partial profiles don't accidentally reset every threshold to 0.
func mergeDLP(cur DLPConfigSnapshot, override DLPThresholds) DLPConfigSnapshot {
	out := cur
	if override.ThresholdCritical != 0 {
		out.ThresholdCritical = override.ThresholdCritical
	}
	if override.ThresholdHigh != 0 {
		out.ThresholdHigh = override.ThresholdHigh
	}
	if override.ThresholdMedium != 0 {
		out.ThresholdMedium = override.ThresholdMedium
	}
	if override.ThresholdLow != 0 {
		out.ThresholdLow = override.ThresholdLow
	}
	if override.HotwordBoost != 0 {
		out.HotwordBoost = override.HotwordBoost
	}
	if override.EntropyBoost != 0 {
		out.EntropyBoost = override.EntropyBoost
	}
	if override.EntropyPenalty != 0 {
		out.EntropyPenalty = override.EntropyPenalty
	}
	if override.ExclusionPenalty != 0 {
		out.ExclusionPenalty = override.ExclusionPenalty
	}
	if override.MultiMatchBoost != 0 {
		out.MultiMatchBoost = override.MultiMatchBoost
	}
	return out
}

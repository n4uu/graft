package tarball

import (
	"context"

	"github.com/n4uu/graft/internal/policy"
	"github.com/n4uu/graft/internal/registry"
	"github.com/n4uu/graft/internal/signals"
)

// Inspector returns the deep-inspection hook for signals.Evaluator: fetch
// the version's tarball (and its predecessor's, for the diff), inspect,
// and turn findings into signals.
func Inspector(reg *registry.Client, pol *policy.Policy) func(context.Context, *signals.Finding, *registry.Manifest, *registry.Manifest) []signals.Signal {
	return func(ctx context.Context, f *signals.Finding, m, prev *registry.Manifest) []signals.Signal {
		if m.Dist.Tarball == "" {
			return nil
		}
		raw, err := reg.Tarball(ctx, m.Dist.Tarball)
		if err != nil {
			return nil
		}
		cur, err := Read(raw)
		if err != nil {
			return nil
		}
		var old *Package
		if prev != nil && prev.Dist.Tarball != "" {
			if b, err := reg.Tarball(ctx, prev.Dist.Tarball); err == nil {
				old, _ = Read(b)
			}
		}
		var out []signals.Signal
		seen := map[string]bool{}
		for _, fd := range Inspect(cur, old) {
			w, ok := pol.Signals[fd.Kind]
			if !ok || seen[fd.Kind+fd.Detail] {
				continue
			}
			seen[fd.Kind+fd.Detail] = true
			out = append(out, signals.Signal{ID: fd.Kind, Points: w.Points, Group: w.Group, Detail: fd.Detail})
		}
		return out
	}
}

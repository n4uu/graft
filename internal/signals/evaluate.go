// Package signals decides how suspicious a resolved package version is,
// from its registry history, its dependencies, and who it claims to be.
package signals

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/n4uu/graft/internal/policy"
	"github.com/n4uu/graft/internal/registry"
	"github.com/n4uu/graft/internal/semver"
)

// Signal is one reason a version looks wrong.
type Signal struct {
	ID     string  `json:"id"`
	Points float64 `json:"points"` // after group damping
	Group  string  `json:"group"`
	Detail string  `json:"detail"`
	Ref    string  `json:"ref,omitempty"`

	scale float64 // fraction of the policy weight, kept for re-scoring
}

// Finding is the verdict on one name@version.
type Finding struct {
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Score       float64   `json:"score"`
	Level       string    `json:"level"`
	Signals     []Signal  `json:"signals,omitempty"`
	Published   time.Time `json:"published,omitzero"`
	Publisher   string    `json:"publisher,omitempty"`
	Predecessor string    `json:"compared_with,omitempty"`
	Error       string    `json:"error,omitempty"`

	repo string // repository key, for the cross-package burst check
}

// Spec is name@version.
func (f *Finding) Spec() string { return f.Name + "@" + f.Version }

// Evaluator holds what evaluation needs.
type Evaluator struct {
	Registry *registry.Client
	Policy   *policy.Policy
	// At evaluates against the registry as it stood at this time (zero:
	// now). Versions published later are invisible; versions unpublished
	// since can't be brought back.
	At time.Time
	// Deep fetches tarballs of versions that already look suspicious and
	// inspects their contents.
	Deep    bool
	Inspect func(ctx context.Context, f *Finding, m, prev *registry.Manifest) []Signal
}

func (e *Evaluator) packument(ctx context.Context, name string) (*registry.Packument, error) {
	p, err := e.Registry.Packument(ctx, name)
	if err != nil || p.Missing || e.At.IsZero() {
		return p, err
	}
	return p.At(e.At), nil
}

func (e *Evaluator) add(f *Finding, id, detail, ref string) {
	e.addScaled(f, id, 1, detail, ref)
}

// addScaled adds a signal at a fraction of its policy weight.
func (e *Evaluator) addScaled(f *Finding, id string, scale float64, detail, ref string) {
	w, ok := e.Policy.Signals[id]
	if !ok {
		return
	}
	f.Signals = append(f.Signals, Signal{ID: id, Points: w.Points * scale, Group: w.Group, Detail: detail, Ref: ref, scale: scale})
}

// Evaluate scores one version.
func (e *Evaluator) Evaluate(ctx context.Context, name, version string) *Finding {
	f := &Finding{Name: name, Version: version}
	defer e.finish(f)

	if e.Policy.Skips(name) {
		return f
	}
	if in, ok := e.Policy.Known.Match(name, version); ok {
		ref := ""
		if len(in.Refs) > 0 {
			ref = in.Refs[0]
		}
		e.add(f, "known_malicious", fmt.Sprintf("%s (%s)", in.Name, in.Date), ref)
	}

	p, err := e.packument(ctx, name)
	if err != nil {
		if !errors.Is(err, registry.ErrOffline) {
			f.Error = err.Error()
		} else {
			f.Error = "not in offline cache"
		}
		return f
	}
	if p.Missing {
		e.add(f, "package_missing", "the registry has no package by this name (removed, or private to another registry)", "")
		return f
	}
	if p.SecurityHolding() {
		e.add(f, "security_holding", "npm replaced the package with a security placeholder, which it does after confirming malware", "https://www.npmjs.com/package/"+name)
	}

	m := p.Versions[version]
	at, published := p.Published(version)
	f.Published = at
	switch {
	case m == nil && p.Unpublished(version):
		e.add(f, "unpublished", fmt.Sprintf("published %s and removed since; the registry kept only the timestamp", at.Format(time.RFC3339)), "")
	case m == nil && !published:
		e.add(f, "never_published", "the registry has no record of this version ever existing; the lockfile may have been edited", "")
	}
	if m == nil {
		e.releaseBurst(f, p, version, nil)
		e.identity(ctx, f, p, nil)
		return f
	}
	f.Publisher = m.NpmUser.Name
	f.repo = m.Repository.RepoKey()
	if f.repo == "" {
		f.repo = p.Repository.RepoKey()
	}

	if d := strings.ToLower(m.Deprecated); d != "" {
		// Only malware-type wording. Maintenance deprecations routinely say
		// "security vulnerabilities" or "do not use" (glob, inflight) and
		// aren't what this signal is for.
		for _, w := range []string{"malware", "malicious", "compromised", "compromise", "backdoor", "hijack", "security holding"} {
			if strings.Contains(d, w) {
				e.add(f, "deprecated_security", "deprecated: "+m.Deprecated, "")
				break
			}
		}
	}

	prev := p.Predecessor(version)
	if prev != nil {
		f.Predecessor = prev.Version
		e.publishing(f, p, m, prev, at)
		e.installScripts(f, m, prev)
		e.dependencies(ctx, f, m, prev, at)
	}
	e.releaseBurst(f, p, version, m)
	e.identity(ctx, f, p, m)

	if e.Deep && e.Inspect != nil {
		if e.score(f) >= e.Policy.Thresholds.Medium || len(m.InstallScripts()) > 0 {
			f.Signals = append(f.Signals, e.Inspect(ctx, f, m, prev)...)
		}
	}
	return f
}

// publishing compares how this version and the one before it reached the
// registry. A project that publishes from CI through OIDC, with provenance,
// doesn't go back to a laptop and a token without a reason.
func (e *Evaluator) publishing(f *Finding, p *registry.Packument, m, prev *registry.Manifest, at time.Time) {
	if prev.NpmUser.TrustedPublisher != nil && m.NpmUser.TrustedPublisher == nil {
		e.add(f, "trusted_publisher_dropped", fmt.Sprintf("%s was published by %s through trusted publishing (OIDC); this version by the account %q", prev.Version, prev.NpmUser.Name, m.NpmUser.Name), "")
	}
	if prev.Dist.Attestations != nil && m.Dist.Attestations == nil {
		e.add(f, "provenance_dropped", fmt.Sprintf("%s carried a provenance attestation; this version has none", prev.Version), "")
	}
	if m.NpmUser.Name != "" && m.NpmUser.TrustedPublisher == nil && len(p.Versions) >= 3 && !p.PublishedBy(m.NpmUser.Name, at) {
		e.add(f, "publisher_new", fmt.Sprintf("first version ever published by %q", m.NpmUser.Name), "")
	}
	if prev.GitHead != "" && m.GitHead == "" {
		e.add(f, "githead_missing", fmt.Sprintf("%s recorded the git commit it was built from; this version doesn't", prev.Version), "")
	}
}

func (e *Evaluator) installScripts(f *Finding, m, prev *registry.Manifest) {
	now, before := m.InstallScripts(), prev.InstallScripts()
	if len(now) == 0 || len(before) > 0 || e.Policy.AllowsInstallScript(f.Name) {
		return
	}
	var parts []string
	for _, k := range []string{"preinstall", "install", "postinstall"} {
		if s, ok := now[k]; ok {
			parts = append(parts, fmt.Sprintf("%s: %q", k, s))
		}
	}
	e.add(f, "install_script_added", fmt.Sprintf("new since %s: %s", prev.Version, strings.Join(parts, ", ")), "")
}

// dependencies looks at every dependency this version adds. The axios and
// Mastra compromises didn't touch the package's own code at all: they
// added one dependency, published hours earlier, whose install script did
// the work.
func (e *Evaluator) dependencies(ctx context.Context, f *Finding, m, prev *registry.Manifest, at time.Time) {
	before := prev.AllDeps()
	var added []string
	for d := range m.AllDeps() {
		if _, ok := before[d]; !ok {
			added = append(added, d)
		}
	}
	sort.Strings(added)
	for _, d := range added {
		e.add(f, "dependency_added", fmt.Sprintf("%s@%s is new since %s", d, m.AllDeps()[d], prev.Version), "")
		dp, err := e.packument(ctx, d)
		if err != nil || dp == nil || dp.Missing {
			continue
		}
		if dp.SecurityHolding() {
			e.add(f, "dependency_malicious", fmt.Sprintf("the added dependency %s has since been replaced by an npm security placeholder", d), "https://www.npmjs.com/package/"+d)
		}
		if in, ok := e.Policy.Known.Match(d, "*"); ok {
			e.add(f, "dependency_malicious", fmt.Sprintf("the added dependency %s is in the known-malicious feed (%s)", d, in.Name), firstRef(in))
		}
		// A new dependency from the same people or the same repository is
		// a project splitting itself up (sharp adding @img/sharp-linux-riscv64,
		// wooorm adding his own devlop), not something grafted on.
		parent, _ := e.packument(ctx, f.Name)
		related := parent != nil && (sharedPublishers(parent, dp) ||
			(dp.Repository.RepoKey() != "" && dp.Repository.RepoKey() == f.repo))
		first, ok := firstPublish(dp)
		if age := at.Sub(first); ok && !related && age < time.Duration(e.Policy.YoungDays)*24*time.Hour {
			detail := fmt.Sprintf("%s first appeared on the registry %s before this release", d, human(age))
			if pub := dp.History(); len(pub) > 0 {
				who := pub[len(pub)-1].NpmUser.Name
				if who != "" && who != m.NpmUser.Name {
					detail += fmt.Sprintf(", published by %q, not by this package's publisher", who)
				}
			}
			// Days old is a different thing from hours old: plain-crypto-js
			// was 18 hours old, easy-day-js under a day. A library that's
			// been out for three weeks gets half the weight.
			scale := 1.0
			if age > 7*24*time.Hour {
				scale = 0.5
			}
			e.addScaled(f, "young_dependency", scale, detail, "")
		}
		if dm := resolve(dp, m.AllDeps()[d], at); dm != nil {
			if s := dm.InstallScripts(); len(s) > 0 {
				e.add(f, "dependency_install_script", fmt.Sprintf("%s@%s, which %s resolved to when published, runs %s on install", d, dm.Version, m.AllDeps()[d], firstScript(s)), "")
			}
		}
		if target, how, ok := Lookalike(d, e.Policy.Popular, e.Policy.IsPopular); ok && !related && !established(dp, at) {
			e.add(f, "lookalike_name", fmt.Sprintf("added dependency %s resembles %s (%s)", d, target, how), "")
		}
	}
}

// releaseBurst: other lines of the same package released in the same
// window. Only worth a point on its own (see the policy notes), but the
// axios compromise pushed 1.14.1 and 0.30.4 39 minutes apart.
func (e *Evaluator) releaseBurst(f *Finding, p *registry.Packument, version string, m *registry.Manifest) {
	at, ok := p.Published(version)
	if !ok {
		return
	}
	if m != nil && m.Dist.Attestations != nil {
		return
	}
	line := semver.Parse(version).Line()
	var near []string
	for v, ts := range p.Time {
		if v == version || v == "created" || v == "modified" {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil || absDur(t.Sub(at)) > e.Policy.BurstWindow.Duration {
			continue
		}
		sv := semver.Parse(v)
		if !sv.Valid() || sv.Line() == line || sv.Prerelease() {
			continue
		}
		if om := p.Versions[v]; om != nil && om.Dist.Attestations != nil {
			continue
		}
		note := fmt.Sprintf("%s (%s %s)", v, human(absDur(t.Sub(at))), map[bool]string{true: "later", false: "earlier"}[t.After(at)])
		if p.Unpublished(v) {
			note += ", since removed"
		}
		near = append(near, note)
	}
	if len(near) > 0 {
		sort.Strings(near)
		e.add(f, "release_burst", "other release lines published alongside: "+strings.Join(near, "; "), "")
	}
}

// identity: lookalike names, and lookalikes that copy the original's
// description or repository without sharing a single publisher with it. It
// works from the package document when the version itself is gone.
func (e *Evaluator) identity(ctx context.Context, f *Finding, p *registry.Packument, m *registry.Manifest) {
	if m == nil {
		m = &registry.Manifest{Description: p.Description, Repository: p.Repository}
		if h := p.History(); len(h) > 0 {
			m = h[len(h)-1]
		}
	}
	target, how, ok := Lookalike(f.Name, e.Policy.Popular, e.Policy.IsPopular)
	if !ok {
		return
	}
	now := e.At
	if now.IsZero() {
		now = time.Now()
	}
	settled := established(p, now)
	tp, err := e.packument(ctx, target)
	if err != nil || tp == nil || tp.Missing {
		if !settled {
			e.add(f, "lookalike_name", fmt.Sprintf("name resembles %s (%s)", target, how), "")
		}
		return
	}
	shared := sharedPublishers(p, tp)
	repo := m.Repository.RepoKey()
	if repo == "" {
		repo = p.Repository.RepoKey()
	}
	sameRepo := repo != "" && repo == tp.Repository.RepoKey()
	desc := m.Description
	if desc == "" {
		desc = p.Description
	}
	sameDesc := len(desc) > 20 && strings.EqualFold(strings.TrimSpace(desc), strings.TrimSpace(tp.Description))
	// Forks copy descriptions all the time (source-map-js is a fork of
	// source-map with its description intact). Pointing the repository
	// field at the original project is different: that's claiming to be it.
	switch {
	case shared:
		return // a sibling package from the same people (jest / jest-util)
	case sameRepo:
		what := "repository (" + tp.Repository.RepoKey() + ")"
		if sameDesc {
			what = "description and " + what
		}
		e.add(f, "impersonation", fmt.Sprintf("claims %s's %s, but no account that published %s has ever published this package", target, what, target), "")
	case settled:
		return // preact, enquirer, colord: similar names, years of history
	case sameDesc:
		e.add(f, "lookalike_name", fmt.Sprintf("name resembles %s (%s) and copies its description; a fork, or a squat", target, how), "")
	default:
		e.add(f, "lookalike_name", fmt.Sprintf("name resembles %s (%s)", target, how), "")
	}
}

func sharedPublishers(a, b *registry.Packument) bool {
	names := map[string]bool{}
	for _, m := range b.Versions {
		if n := m.NpmUser.Name; n != "" && m.NpmUser.TrustedPublisher == nil {
			names[strings.ToLower(n)] = true
		}
	}
	for _, mt := range b.Maintainers {
		names[strings.ToLower(mt.Name)] = true
	}
	for _, m := range a.Versions {
		if names[strings.ToLower(m.NpmUser.Name)] {
			return true
		}
	}
	for _, mt := range a.Maintainers {
		if names[strings.ToLower(mt.Name)] {
			return true
		}
	}
	return false
}

// established: on the registry for over a year with at least ten
// releases. Typosquats are young; preact and enquirer have looked like
// react and inquirer for a decade. Impersonation (claiming the original's
// repository) is still checked for established packages.
func established(p *registry.Packument, at time.Time) bool {
	first, ok := firstPublish(p)
	return ok && at.Sub(first) > 365*24*time.Hour && len(p.Time) >= 12
}

// resolve picks the version of dp that range rng would have installed at
// time at: the highest satisfying version published by then. Ranges that
// aren't semver (tags, git, aliases) fall back to the newest version.
func resolve(dp *registry.Packument, rng string, at time.Time) *registry.Manifest {
	var best, newest *registry.Manifest
	for _, dm := range dp.Versions {
		if t, ok := dp.Published(dm.Version); !ok || t.After(at) {
			continue
		}
		v := semver.Parse(dm.Version)
		if newest == nil || semver.Compare(v, semver.Parse(newest.Version)) > 0 {
			newest = dm
		}
		match, ok := semver.Satisfies(v, rng)
		if !ok {
			continue
		}
		if match && (best == nil || semver.Compare(v, semver.Parse(best.Version)) > 0) {
			best = dm
		}
	}
	if _, ok := semver.Satisfies(semver.Parse("0.0.0"), rng); !ok {
		return newest
	}
	return best
}

// firstPublish is the earliest timestamp in the time record. The "created"
// field can't be trusted for this: when npm swaps a package for a security
// placeholder it recreates the document, and plain-crypto-js now claims to
// have been created four hours after the attack.
func firstPublish(p *registry.Packument) (time.Time, bool) {
	var first time.Time
	for k, v := range p.Time {
		if k == "modified" {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			continue
		}
		if first.IsZero() || t.Before(first) {
			first = t
		}
	}
	return first, !first.IsZero()
}

// finish applies group damping and sets the score and level.
func (e *Evaluator) finish(f *Finding) {
	byGroup := map[string][]int{}
	for i, s := range f.Signals {
		byGroup[s.Group] = append(byGroup[s.Group], i)
	}
	for _, idx := range byGroup {
		sort.SliceStable(idx, func(a, b int) bool { return f.Signals[idx[a]].Points > f.Signals[idx[b]].Points })
		for rank, i := range idx {
			f.Signals[i].Points = round(f.Signals[i].Points * math.Pow(e.Policy.GroupDecay, float64(rank)))
		}
	}
	sort.SliceStable(f.Signals, func(i, j int) bool { return f.Signals[i].Points > f.Signals[j].Points })
	f.Score = round(e.score(f))
	f.Level = e.Policy.Level(f.Score)
}

func (e *Evaluator) score(f *Finding) float64 {
	s := 0.0
	for _, sig := range f.Signals {
		s += sig.Points
	}
	return s
}

// Rescore re-applies damping after signals were added outside Evaluate
// (the cross-package pass).
func (e *Evaluator) Rescore(f *Finding) {
	ws := e.Policy.Signals
	for i := range f.Signals {
		if w, ok := ws[f.Signals[i].ID]; ok {
			scale := f.Signals[i].scale
			if scale == 0 {
				scale = 1
			}
			f.Signals[i].Points = w.Points * scale
		}
	}
	e.finish(f)
}

// EvaluateAll scores many versions with bounded concurrency, then runs the
// cross-package checks.
func (e *Evaluator) EvaluateAll(ctx context.Context, specs [][2]string, workers int) []*Finding {
	if workers <= 0 {
		workers = 12
	}
	out := make([]*Finding, len(specs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for i, s := range specs {
		wg.Add(1)
		go func(i int, name, version string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = e.Evaluate(ctx, name, version)
		}(i, s[0], s[1])
	}
	wg.Wait()
	e.publisherBurst(out)
	return out
}

// publisherBurst flags versions that one account published across several
// unrelated packages in a short window. Per-package history can't see a
// phished maintainer whose every release looks like the last one; the
// burst across packages can.
func (e *Evaluator) publisherBurst(fs []*Finding) {
	byPub := map[string][]*Finding{}
	for _, f := range fs {
		if f == nil || f.Publisher == "" || f.Published.IsZero() {
			continue
		}
		if f.Publisher == "GitHub Actions" || f.Publisher == "npm" {
			continue // CI identity and npm itself, not a person
		}
		byPub[f.Publisher] = append(byPub[f.Publisher], f)
	}
	win := e.Policy.PublisherBurst.Window.Duration
	for pub, list := range byPub {
		sort.Slice(list, func(i, j int) bool { return list[i].Published.Before(list[j].Published) })
		for i, f := range list {
			owners := map[string]bool{}
			var names []string
			for _, g := range list {
				if absDur(g.Published.Sub(list[i].Published)) <= win {
					owners[owner(g)] = true
					names = append(names, g.Spec())
				}
			}
			if len(owners) >= e.Policy.PublisherBurst.MinOwners {
				sort.Strings(names)
				own := make([]string, 0, len(owners))
				for o := range owners {
					own = append(own, o)
				}
				sort.Strings(own)
				e.add(f, "publisher_burst", fmt.Sprintf("%q published %d packages in your tree owned by %d different projects (%s) within %s: %s",
					pub, len(names), len(owners), strings.Join(own, ", "), win, strings.Join(trim(names, 6), ", ")), "")
				// A phished maintainer's releases look like the previous ones
				// in every metadata field; the payload is in the code. With
				// -deep, every member of a burst gets its tarball diffed.
				if e.Deep && e.Inspect != nil {
					if p, err := e.packument(context.Background(), f.Name); err == nil && !p.Missing {
						if m := p.Versions[f.Version]; m != nil {
							f.Signals = append(f.Signals, e.Inspect(context.Background(), f, m, p.Predecessor(f.Version))...)
						}
					}
				}
				e.Rescore(f)
			}
		}
	}
}

// owner is the organisation or user a package's repository lives under
// (github.com/chalk/chalk -> chalk). Without a repository it falls back to
// the npm scope, then the package name.
func owner(f *Finding) string {
	if parts := strings.Split(f.repo, "/"); len(parts) >= 3 {
		return strings.ToLower(parts[1])
	}
	if strings.HasPrefix(f.Name, "@") {
		return strings.SplitN(f.Name, "/", 2)[0]
	}
	return f.Name
}

func trim(xs []string, n int) []string {
	if len(xs) <= n {
		return xs
	}
	return append(xs[:n:n], fmt.Sprintf("and %d more", len(xs)-n))
}

func firstRef(in *policy.Incident) string {
	if len(in.Refs) > 0 {
		return in.Refs[0]
	}
	return ""
}

func firstScript(s map[string]string) string {
	for _, k := range []string{"preinstall", "install", "postinstall"} {
		if v, ok := s[k]; ok {
			return fmt.Sprintf("%s %q", k, v)
		}
	}
	return ""
}

func human(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()+0.5))
	case d < 48*time.Hour:
		return fmt.Sprintf("%.0fh", d.Hours())
	}
	return fmt.Sprintf("%.0f days", d.Hours()/24)
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func round(x float64) float64 { return math.Round(x*100) / 100 }

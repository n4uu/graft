// Package scan ties lockfiles, node_modules and the npm cache to the
// evaluator and produces one result for the report writers.
package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"github.com/n4uu/graft/internal/cacache"
	"github.com/n4uu/graft/internal/lockfile"
	"github.com/n4uu/graft/internal/signals"
)

// Item is one locked package and its finding.
type Item struct {
	Package   lockfile.Package `json:"package"`
	Finding   *signals.Finding `json:"finding"`
	Installed string           `json:"installed_version,omitempty"`
}

// LockResult is the outcome for one lockfile.
type LockResult struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	Packages  int    `json:"packages"`
	Evaluated int    `json:"evaluated"`
	Skipped   int    `json:"skipped_non_registry"`
	Items     []Item `json:"items"`
	Error     string `json:"error,omitempty"`
}

// CacheItem is a tarball from the npm cache and its finding.
type CacheItem struct {
	Entry   cacache.Entry    `json:"entry"`
	Finding *signals.Finding `json:"finding"`
}

// Result is everything one run found.
type Result struct {
	Lockfiles []LockResult       `json:"lockfiles"`
	Cache     []CacheItem        `json:"npm_cache,omitempty"`
	CacheDir  string             `json:"npm_cache_dir,omitempty"`
	Checked   []*signals.Finding `json:"checked,omitempty"` // graft check
	Notes     []string           `json:"notes,omitempty"`
}

// Options select what to look at.
type Options struct {
	Dev         bool   // include devDependencies
	NodeModules bool   // compare installed package.json versions to the lockfile
	NpmCache    string // scan this _cacache directory too
	Workers     int
}

// Run audits lockfiles (and optionally node_modules and the npm cache).
func Run(ctx context.Context, ev *signals.Evaluator, paths []string, opts Options) (*Result, error) {
	res := &Result{}
	var files []string
	for _, p := range paths {
		found, err := lockfile.Discover(p)
		if err != nil {
			return nil, err
		}
		files = append(files, found...)
	}

	type locked struct {
		path string
		lf   *lockfile.Lockfile
		err  error
	}
	var lfs []locked
	want := map[[2]string]bool{}
	for _, f := range files {
		lf, err := lockfile.Parse(f)
		lfs = append(lfs, locked{f, lf, err})
		if err != nil {
			continue
		}
		for _, p := range lf.Packages {
			if p.Registry && (opts.Dev || !p.Dev) {
				want[[2]string{p.Name, p.Version}] = true
			}
		}
	}

	var cached []cacache.Entry
	if opts.NpmCache != "" {
		es, err := cacache.Scan(opts.NpmCache)
		if err != nil {
			res.Notes = append(res.Notes, "npm cache: "+err.Error())
		}
		res.CacheDir = opts.NpmCache
		cached = es
		for _, e := range es {
			want[[2]string{e.Name, e.Version}] = true
		}
	}

	specs := make([][2]string, 0, len(want))
	for s := range want {
		specs = append(specs, s)
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i][0]+specs[i][1] < specs[j][0]+specs[j][1] })
	byspec := map[[2]string]*signals.Finding{}
	for _, f := range ev.EvaluateAll(ctx, specs, opts.Workers) {
		byspec[[2]string{f.Name, f.Version}] = f
	}

	for _, l := range lfs {
		if l.err != nil {
			res.Lockfiles = append(res.Lockfiles, LockResult{Path: l.path, Error: l.err.Error()})
			continue
		}
		lr := LockResult{Path: l.lf.Path, Kind: l.lf.Kind, Packages: len(l.lf.Packages)}
		for _, p := range l.lf.Packages {
			if !p.Registry {
				lr.Skipped++
				continue
			}
			if p.Dev && !opts.Dev {
				continue
			}
			lr.Evaluated++
			f := byspec[[2]string{p.Name, p.Version}]
			it := Item{Package: p, Finding: f}
			if opts.NodeModules && l.lf.Kind == "npm" && p.Path != "" {
				if v, ok := installedVersion(filepath.Dir(l.lf.Path), p.Path); ok && v != p.Version {
					it.Installed = v
					it.Finding = withMismatch(ev, f, p, v)
				}
			}
			lr.Items = append(lr.Items, it)
		}
		sort.SliceStable(lr.Items, func(i, j int) bool { return lr.Items[i].Finding.Score > lr.Items[j].Finding.Score })
		res.Lockfiles = append(res.Lockfiles, lr)
	}

	for _, e := range cached {
		res.Cache = append(res.Cache, CacheItem{Entry: e, Finding: byspec[[2]string{e.Name, e.Version}]})
	}
	sort.SliceStable(res.Cache, func(i, j int) bool { return res.Cache[i].Finding.Score > res.Cache[j].Finding.Score })
	return res, nil
}

// installedVersion reads node_modules/<path>/package.json next to a lockfile.
func installedVersion(dir, path string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(path), "package.json"))
	if err != nil {
		return "", false
	}
	var m struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(b, &m) != nil || m.Version == "" {
		return "", false
	}
	return m.Version, true
}

// withMismatch copies a finding and adds installed_mismatch. The copy
// matters: the same name@version may be installed cleanly elsewhere.
func withMismatch(ev *signals.Evaluator, f *signals.Finding, p lockfile.Package, installed string) *signals.Finding {
	c := *f
	c.Signals = append([]signals.Signal(nil), f.Signals...)
	w := ev.Policy.Signals["installed_mismatch"]
	c.Signals = append(c.Signals, signals.Signal{
		ID: "installed_mismatch", Points: w.Points, Group: w.Group,
		Detail: "the lockfile installed " + p.Version + " but " + p.Path + "/package.json now says " + installed +
			": something rewrote the package's manifest after install",
	})
	ev.Rescore(&c)
	return &c
}

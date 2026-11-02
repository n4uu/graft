// Package report writes scan results as text, JSON or SARIF.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/n4uu/graft/internal/policy"
	"github.com/n4uu/graft/internal/scan"
	"github.com/n4uu/graft/internal/signals"
)

// Counts tallies findings by level across lockfiles, cache and checks.
func Counts(r *scan.Result) map[string]int {
	c := map[string]int{}
	seen := map[string]bool{}
	count := func(f *signals.Finding) {
		if f == nil || seen[f.Spec()] {
			return
		}
		seen[f.Spec()] = true
		c[f.Level]++
	}
	for _, l := range r.Lockfiles {
		for _, it := range l.Items {
			count(it.Finding)
		}
	}
	for _, it := range r.Cache {
		count(it.Finding)
	}
	for _, f := range r.Checked {
		count(f)
	}
	return c
}

// Worst returns the highest level present.
func Worst(r *scan.Result) string {
	worst := "none"
	for l, n := range Counts(r) {
		if n > 0 && policy.LevelRank(l) > policy.LevelRank(worst) {
			worst = l
		}
	}
	return worst
}

// JSON writes the full result.
func JSON(w io.Writer, r *scan.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Text writes a human report, listing findings at or above min.
func Text(w io.Writer, r *scan.Result, min string, verbose bool) {
	show := func(f *signals.Finding) bool {
		return f != nil && policy.LevelRank(f.Level) >= policy.LevelRank(min)
	}
	for _, l := range r.Lockfiles {
		if l.Error != "" {
			fmt.Fprintf(w, "%s\n  error: %s\n\n", l.Path, l.Error)
			continue
		}
		fmt.Fprintf(w, "%s  (%s, %d packages, %d checked against the registry", l.Path, l.Kind, l.Packages, l.Evaluated)
		if l.Skipped > 0 {
			fmt.Fprintf(w, ", %d git/file/url deps skipped", l.Skipped)
		}
		fmt.Fprintln(w, ")")
		n := 0
		for _, it := range l.Items {
			if !show(it.Finding) {
				continue
			}
			n++
			where := "transitive"
			if it.Package.Direct {
				where = "direct"
			}
			if it.Package.Dev {
				where += ", dev"
			}
			loc := ""
			if it.Package.Line > 0 {
				loc = fmt.Sprintf("  line %d", it.Package.Line)
			}
			finding(w, it.Finding, where+loc, verbose)
		}
		if n == 0 {
			fmt.Fprintf(w, "  nothing at %s or above\n", min)
		}
		fmt.Fprintln(w)
	}

	var cache []scan.CacheItem
	for _, it := range r.Cache {
		if show(it.Finding) {
			cache = append(cache, it)
		}
	}
	if r.CacheDir != "" {
		fmt.Fprintf(w, "npm cache %s  (%d tarballs)\n", r.CacheDir, len(r.Cache))
		sort.SliceStable(cache, func(i, j int) bool { return cache[i].Entry.Fetched.Before(cache[j].Entry.Fetched) })
		for _, it := range cache {
			finding(w, it.Finding, "downloaded "+it.Entry.Fetched.Format("2006-01-02 15:04:05 MST"), verbose)
		}
		if len(cache) == 0 {
			fmt.Fprintf(w, "  nothing at %s or above\n", min)
		}
		fmt.Fprintln(w)
	}

	for _, f := range r.Checked {
		finding(w, f, "", true)
	}

	c := Counts(r)
	fmt.Fprintf(w, "%d critical, %d high, %d medium, %d low\n", c["critical"], c["high"], c["medium"], c["low"])
	for _, n := range r.Notes {
		fmt.Fprintf(w, "note: %s\n", n)
	}
}

func finding(w io.Writer, f *signals.Finding, where string, verbose bool) {
	head := fmt.Sprintf("  %-8s %5.1f  %s", strings.ToUpper(f.Level), f.Score, f.Spec())
	if where != "" {
		head += "  (" + where + ")"
	}
	fmt.Fprintln(w, head)
	if f.Error != "" {
		fmt.Fprintf(w, "                 error: %s\n", f.Error)
	}
	if !f.Published.IsZero() && verbose {
		pub := f.Published.Format(time.RFC3339)
		if f.Publisher != "" {
			pub += " by " + f.Publisher
		}
		if f.Predecessor != "" {
			pub += ", compared with " + f.Predecessor
		}
		fmt.Fprintf(w, "                 published %s\n", pub)
	}
	for _, s := range f.Signals {
		fmt.Fprintf(w, "         %+5.1f   %-26s %s\n", s.Points, s.ID, s.Detail)
		if s.Ref != "" && verbose {
			fmt.Fprintf(w, "                 %-26s %s\n", "", s.Ref)
		}
	}
}

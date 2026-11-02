package signals

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n4uu/graft/internal/policy"
	"github.com/n4uu/graft/internal/registry"
)

// The packuments under testdata/registry are real registry documents
// (reduced), so these tests run graft against what the registry says about
// real incidents today.

func fixture(t *testing.T, name string) *registry.Packument {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("../../testdata/registry", strings.ReplaceAll(name, "/", "__")+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var p registry.Packument
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	return &p
}

func evaluator(t *testing.T, feed bool, ps ...*registry.Packument) *Evaluator {
	t.Helper()
	c := registry.New("", true) // offline: anything not seeded is a miss
	c.Seed(ps...)
	pol := policy.Default()
	if !feed {
		pol.Known = nil
	}
	return &Evaluator{Registry: c, Policy: pol}
}

func all(t *testing.T, names ...string) []*registry.Packument {
	var out []*registry.Packument
	for _, n := range names {
		out = append(out, fixture(t, n))
	}
	return out
}

func ids(f *Finding) map[string]bool {
	out := map[string]bool{}
	for _, s := range f.Signals {
		out[s.ID] = true
	}
	return out
}

func expect(t *testing.T, f *Finding, level string, signals ...string) {
	t.Helper()
	got := ids(f)
	for _, s := range signals {
		if !got[s] {
			t.Errorf("%s: missing %s; got %s", f.Spec(), s, describe(f))
		}
	}
	if level != "" && f.Level != level {
		t.Errorf("%s: level %s (score %.2f), want %s; %s", f.Spec(), f.Level, f.Score, level, describe(f))
	}
}

func describe(f *Finding) string {
	var b strings.Builder
	for _, s := range f.Signals {
		fmt.Fprintf(&b, "\n  %+.2f %s: %s", s.Points, s.ID, s.Detail)
	}
	return b.String()
}

var ctx = context.Background()

func TestAxiosToday(t *testing.T) {
	e := evaluator(t, true, all(t, "axios", "plain-crypto-js", "crypto-js")...)
	f := e.Evaluate(ctx, "axios", "1.14.1")
	expect(t, f, "critical", "known_malicious", "unpublished", "release_burst")
	if f.Published.Format(time.RFC3339) != "2026-03-31T00:21:58Z" {
		t.Errorf("publish time %v", f.Published)
	}
	if !strings.Contains(describe(f), "0.30.4 (39m later), since removed") {
		t.Errorf("burst detail: %s", describe(f))
	}
	expect(t, e.Evaluate(ctx, "plain-crypto-js", "4.2.1"), "critical", "known_malicious", "security_holding", "unpublished")

	// Without the feed, the registry alone still says enough.
	e = evaluator(t, false, all(t, "axios", "plain-crypto-js")...)
	expect(t, e.Evaluate(ctx, "axios", "1.14.1"), "high", "unpublished")
	expect(t, e.Evaluate(ctx, "plain-crypto-js", "4.2.1"), "critical", "security_holding", "unpublished")
}

func TestEasyDayJSImpersonatesDayjs(t *testing.T) {
	// No feed: this is graft working it out from metadata alone. The live
	// 1.11.21 is the decoy the attacker published a day before the payload.
	e := evaluator(t, false, all(t, "easy-day-js", "dayjs")...)
	f := e.Evaluate(ctx, "easy-day-js", "1.11.21")
	expect(t, f, "medium", "impersonation")
	if d := describe(f); !strings.Contains(d, "claims dayjs's description and repository (github.com/iamkun/dayjs)") {
		t.Errorf("impersonation detail: %s", d)
	}
	expect(t, e.Evaluate(ctx, "easy-day-js", "1.11.22"), "critical", "unpublished", "impersonation")
}

func TestQixPhishingToday(t *testing.T) {
	e := evaluator(t, true, all(t, "chalk", "debug", "ms")...)
	expect(t, e.Evaluate(ctx, "chalk", "5.6.1"), "critical", "known_malicious", "unpublished")
	expect(t, e.Evaluate(ctx, "debug", "4.4.2"), "critical", "known_malicious", "unpublished")
}

func TestOrdinaryReleasesStayQuiet(t *testing.T) {
	e := evaluator(t, true, all(t, "axios", "express", "lodash", "dayjs", "crypto-js", "chalk", "debug", "ms")...)
	for _, spec := range []string{
		"axios@1.14.0", "axios@1.15.0", "axios@0.30.3",
		"express@5.3.0", "express@4.22.3", "express@4.21.2",
		"lodash@4.17.21", "lodash@4.18.1",
		"dayjs@1.11.23", "dayjs@1.11.19",
		"crypto-js@4.2.0", "chalk@5.6.2", "chalk@6.0.1", "debug@4.4.3", "debug@4.4.1", "ms@2.1.3",
	} {
		name, version, _ := strings.Cut(spec, "@")
		f := e.Evaluate(ctx, name, version)
		if f.Error != "" {
			t.Errorf("%s: %s", spec, f.Error)
		}
		if f.Level != "none" && f.Level != "low" {
			t.Errorf("%s: %s (%.2f)%s", spec, f.Level, f.Score, describe(f))
		}
	}
	// express 4.22.1 and 5.2.1 really were published 58 seconds apart by
	// one legitimate maintainer. That's a release_burst and nothing more.
	f := e.Evaluate(ctx, "express", "4.22.1")
	expect(t, f, "low", "release_burst")
}

// TestAxiosAtTheTime rebuilds the registry as it stood at 01:05 UTC on
// 2026-03-31, after both malicious axios versions were out and before npm
// pulled them, with no feed: would graft have caught it on the night?
//
// Everything except the two axios manifests and plain-crypto-js's own
// versions comes from the real documents. Those were removed from the
// registry, so they're rebuilt from public reporting: 1.14.1 and 0.30.4
// added plain-crypto-js (nothing else is changed in the rebuilt manifest);
// they were
// published with a maintainer's stolen long-lived token, so from an
// existing maintainer account and without trusted publishing or
// provenance; plain-crypto-js 4.2.1's postinstall ran setup.js. The
// timestamps are the registry's own.
func TestAxiosAtTheTime(t *testing.T) {
	night := time.Date(2026, 3, 31, 1, 5, 0, 0, time.UTC)

	ax := fixture(t, "axios")
	// The account behind the hand-published 0.30.x line, renamed so no real
	// person's name ends up attached to the reconstruction.
	maint := registry.Publisher{Name: "maintainer"}
	for _, m := range ax.Versions {
		if m.NpmUser.TrustedPublisher == nil {
			m.NpmUser = maint
		}
	}
	for v, prev := range map[string]string{"1.14.1": "1.14.0", "0.30.4": "0.30.3"} {
		m := *ax.Versions[prev]
		m.Version = v
		m.Dependencies = map[string]string{"plain-crypto-js": "^4.2.1"}
		for k, r := range ax.Versions[prev].Dependencies {
			m.Dependencies[k] = r
		}
		m.NpmUser = maint
		m.Dist = registry.Dist{Tarball: "https://registry.npmjs.org/axios/-/axios-" + v + ".tgz"}
		m.GitHead = ""
		ax.Versions[v] = &m
	}

	pc := fixture(t, "plain-crypto-js")
	pc.Versions = map[string]*registry.Manifest{
		"4.2.0": {Name: "plain-crypto-js", Version: "4.2.0", NpmUser: registry.Publisher{Name: "attacker-account"}},
		"4.2.1": {Name: "plain-crypto-js", Version: "4.2.1", NpmUser: registry.Publisher{Name: "attacker-account"},
			Scripts: map[string]string{"postinstall": "node setup.js"}},
	}
	pc.Repository = registry.Repository{}

	e := evaluator(t, false, ax, pc, fixture(t, "crypto-js"))
	e.At = night

	f := e.Evaluate(ctx, "axios", "1.14.1")
	expect(t, f, "critical",
		"trusted_publisher_dropped", "provenance_dropped", "githead_missing",
		"dependency_added", "young_dependency", "dependency_install_script", "lookalike_name", "release_burst")
	t.Logf("axios@1.14.1 at %s: %s %.2f%s", night.Format("15:04Z"), f.Level, f.Score, describe(f))
	if f.Predecessor != "1.14.0" {
		t.Errorf("compared with %s", f.Predecessor)
	}
	if d := describe(f); !strings.Contains(d, "plain-crypto-js first appeared on the registry 18h before this release") {
		t.Errorf("young dependency detail: %s", d)
	}

	// The old 0.x line was always published by hand, so there's no OIDC or
	// provenance to lose. The dependency alone carries it.
	g := e.Evaluate(ctx, "axios", "0.30.4")
	expect(t, g, "high", "young_dependency", "dependency_install_script", "lookalike_name", "release_burst")
	t.Logf("axios@0.30.4: %s %.2f%s", g.Level, g.Score, describe(g))
	if ids(g)["trusted_publisher_dropped"] || ids(g)["provenance_dropped"] {
		t.Errorf("0.30.4 compared against the wrong line: %s", describe(g))
	}

	// And 1.14.0, the version right before, is clean at the same instant.
	h := e.Evaluate(ctx, "axios", "1.14.0")
	if h.Level != "none" {
		t.Errorf("1.14.0 at the time: %s %s", h.Level, describe(h))
	}
}

// TestPublisherBurst rebuilds the 2025-09-08 phishing as the registry saw
// it at 13:25 UTC: one account, a new patch release of each of several
// unrelated packages, minutes apart, each release looking exactly like the
// one before. Per-package checks see nothing; the burst does.
func TestPublisherBurst(t *testing.T) {
	type rel struct{ name, version, repo, at string }
	burst := []rel{
		{"ansi-styles", "6.2.2", "chalk/ansi-styles", "13:12:10"},
		{"debug", "4.4.2", "debug-js/debug", "13:12:39"},
		{"chalk", "5.6.1", "chalk/chalk", "13:13:05"},
		{"supports-color", "10.2.1", "chalk/supports-color", "13:13:28"},
		{"color-convert", "3.1.1", "Qix-/color-convert", "13:14:53"},
	}
	var ps []*registry.Packument
	var specs [][2]string
	for _, r := range burst {
		prevAt := "2025-08-01T10:00:00.000Z"
		p := &registry.Packument{
			Name: r.name,
			Time: map[string]string{"created": "2014-01-01T00:00:00.000Z", "1.0.0": prevAt, r.version: "2025-09-08T" + r.at + ".000Z"},
			Versions: map[string]*registry.Manifest{
				"1.0.0":   {Name: r.name, Version: "1.0.0", NpmUser: registry.Publisher{Name: "qix"}, Repository: registry.Repository{URL: "github:" + r.repo}},
				r.version: {Name: r.name, Version: r.version, NpmUser: registry.Publisher{Name: "qix"}, Repository: registry.Repository{URL: "github:" + r.repo}},
			},
		}
		ps = append(ps, p)
		specs = append(specs, [2]string{r.name, r.version})
	}
	// A monorepo release: one account, many packages, one repository.
	for i := 0; i < 5; i++ {
		n := fmt.Sprintf("@babel/plugin-%d", i)
		ps = append(ps, &registry.Packument{
			Name: n,
			Time: map[string]string{"created": "2018-01-01T00:00:00.000Z", "7.0.0": "2025-07-01T00:00:00.000Z", "7.28.4": "2025-09-08T13:10:00.000Z"},
			Versions: map[string]*registry.Manifest{
				"7.0.0":  {Name: n, Version: "7.0.0", NpmUser: registry.Publisher{Name: "nicolo-ribaudo"}, Repository: registry.Repository{URL: "https://github.com/babel/babel.git"}},
				"7.28.4": {Name: n, Version: "7.28.4", NpmUser: registry.Publisher{Name: "nicolo-ribaudo"}, Repository: registry.Repository{URL: "https://github.com/babel/babel.git"}},
			},
		})
		specs = append(specs, [2]string{n, "7.28.4"})
	}

	e := evaluator(t, false, ps...)
	e.At = time.Date(2025, 9, 8, 13, 25, 0, 0, time.UTC)
	for _, f := range e.EvaluateAll(ctx, specs, 4) {
		burstHit := ids(f)["publisher_burst"]
		if strings.HasPrefix(f.Name, "@babel/") == burstHit {
			t.Errorf("%s: publisher_burst=%v%s", f.Spec(), burstHit, describe(f))
		}
	}
}

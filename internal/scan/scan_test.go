package scan

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n4uu/graft/internal/policy"
	"github.com/n4uu/graft/internal/registry"
	"github.com/n4uu/graft/internal/signals"
)

func evaluator(t *testing.T) *signals.Evaluator {
	t.Helper()
	c := registry.New("", true)
	for _, n := range []string{"axios", "plain-crypto-js", "crypto-js", "chalk", "debug", "ms", "express", "dayjs", "easy-day-js", "lodash"} {
		b, err := os.ReadFile(filepath.Join("../../testdata/registry", n+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var p registry.Packument
		if err := json.Unmarshal(b, &p); err != nil {
			t.Fatal(err)
		}
		c.Seed(&p)
	}
	return &signals.Evaluator{Registry: c, Policy: policy.Default()}
}

func TestSweep(t *testing.T) {
	ev := evaluator(t)
	res, err := Run(context.Background(), ev, []string{"../../testdata/sweep"}, Options{
		Dev: true, NodeModules: true, NpmCache: "../../testdata/npm-cache/_cacache",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Lockfiles) != 1 {
		t.Fatalf("lockfiles: %+v", res.Lockfiles)
	}
	var pc *Item
	for i, it := range res.Lockfiles[0].Items {
		if it.Package.Name == "plain-crypto-js" {
			pc = &res.Lockfiles[0].Items[i]
		}
	}
	if pc == nil || pc.Installed != "4.2.0" {
		t.Fatalf("installed version not read: %+v", pc)
	}
	found := false
	for _, s := range pc.Finding.Signals {
		if s.ID == "installed_mismatch" && strings.Contains(s.Detail, "now says 4.2.0") {
			found = true
		}
	}
	if !found || pc.Finding.Level != "critical" {
		t.Errorf("mismatch not reported: %+v", pc.Finding.Signals)
	}

	// The npm cache remembers the bad tarballs and when they arrived.
	hits := map[string]string{}
	for _, c := range res.Cache {
		hits[c.Entry.Spec()] = c.Finding.Level
	}
	if hits["axios@1.14.1"] != "critical" || hits["plain-crypto-js@4.2.1"] != "critical" || hits["lodash@4.17.21"] != "none" {
		t.Errorf("cache findings: %v", hits)
	}
}

func TestMismatchDoesNotLeakIntoSharedFinding(t *testing.T) {
	ev := evaluator(t)
	res, err := Run(context.Background(), ev, []string{"../../testdata/sweep", "../../testdata/lockfiles/npm-v3"}, Options{Dev: true, NodeModules: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range res.Lockfiles {
		if !strings.Contains(l.Path, "npm-v3") {
			continue
		}
		for _, it := range l.Items {
			for _, s := range it.Finding.Signals {
				if s.ID == "installed_mismatch" {
					t.Errorf("%s: mismatch from another project leaked in", it.Package.Spec())
				}
			}
		}
	}
}

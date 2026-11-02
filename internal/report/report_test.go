package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/n4uu/graft/internal/lockfile"
	"github.com/n4uu/graft/internal/policy"
	"github.com/n4uu/graft/internal/scan"
	"github.com/n4uu/graft/internal/signals"
)

func sample() *scan.Result {
	f := &signals.Finding{Name: "axios", Version: "1.14.1", Score: 25, Level: "critical", Signals: []signals.Signal{
		{ID: "known_malicious", Points: 20, Group: "verdict", Detail: "axios takeover"},
		{ID: "unpublished", Points: 4, Group: "verdict", Detail: "removed"},
	}}
	ok := &signals.Finding{Name: "ms", Version: "2.1.3", Level: "none"}
	return &scan.Result{Lockfiles: []scan.LockResult{{
		Path: "/repo/app/package-lock.json", Kind: "npm", Packages: 2, Evaluated: 2,
		Items: []scan.Item{
			{Package: lockfile.Package{Name: "axios", Version: "1.14.1", Line: 20, Direct: true, Registry: true}, Finding: f},
			{Package: lockfile.Package{Name: "ms", Version: "2.1.3", Line: 40, Registry: true}, Finding: ok},
		},
	}}}
}

func TestSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, sample(), "low", "test", "/repo"); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct{ ID string }
				}
			}
			Results []struct {
				RuleID    string
				Level     string
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string }
						Region           struct{ StartLine int }
					}
				}
				PartialFingerprints map[string]string
			}
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	r := log.Runs[0]
	if log.Version != "2.1.0" || len(r.Results) != 1 {
		t.Fatalf("results: %+v", r.Results)
	}
	res := r.Results[0]
	loc := res.Locations[0].PhysicalLocation
	if res.RuleID != "known_malicious" || res.Level != "error" || loc.ArtifactLocation.URI != "app/package-lock.json" || loc.Region.StartLine != 20 || res.PartialFingerprints["graft/v1"] == "" {
		t.Errorf("result: %+v", res)
	}
	// every signal the policy can emit has a rule
	rules := map[string]bool{}
	for _, ru := range r.Tool.Driver.Rules {
		rules[ru.ID] = true
	}
	for id := range policy.Default().Signals {
		if !rules[id] {
			t.Errorf("no SARIF rule for signal %s", id)
		}
	}
}

func TestTextAndWorst(t *testing.T) {
	var buf bytes.Buffer
	Text(&buf, sample(), "medium", false)
	out := buf.String()
	if !strings.Contains(out, "CRITICAL  25.0  axios@1.14.1  (direct  line 20)") || strings.Contains(out, "ms@2.1.3") {
		t.Errorf("text:\n%s", out)
	}
	if Worst(sample()) != "critical" {
		t.Error("worst")
	}
}

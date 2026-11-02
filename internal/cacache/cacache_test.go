package cacache

import (
	"testing"
	"time"
)

func TestScan(t *testing.T) {
	es, err := Scan("../../testdata/npm-cache/_cacache")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]time.Time{}
	for _, e := range es {
		got[e.Spec()] = e.Fetched
	}
	if len(got) != 4 {
		t.Fatalf("entries: %v", got)
	}
	// fetched twice; the earlier fetch wins
	if got["axios@1.14.1"].Format(time.RFC3339) != "2026-03-31T00:48:12Z" {
		t.Errorf("axios fetch time %v", got["axios@1.14.1"])
	}
	if _, ok := got["@acme/agent-kit@0.9.2"]; !ok {
		t.Error("scoped tarball missed")
	}
}

func TestTarballSpec(t *testing.T) {
	for u, want := range map[string]string{
		"https://registry.npmjs.org/axios/-/axios-1.14.1.tgz":                    "axios@1.14.1",
		"https://registry.npmjs.org/@acme/agent-kit/-/agent-kit-0.9.2.tgz":       "@acme/agent-kit@0.9.2",
		"https://registry.npmjs.org/@acme%2fagent-kit/-/agent-kit-0.9.2.tgz":     "@acme/agent-kit@0.9.2",
		"https://registry.yarnpkg.com/debug/-/debug-4.4.2.tgz":                   "debug@4.4.2",
		"https://registry.npmjs.org/plain-crypto-js/-/plain-crypto-js-4.2.1.tgz": "plain-crypto-js@4.2.1",
	} {
		n, v, ok := TarballSpec(u)
		if !ok || n+"@"+v != want {
			t.Errorf("%s -> %s@%s %v", u, n, v, ok)
		}
	}
	for _, bad := range []string{"https://registry.npmjs.org/axios", "https://example.com/x.tgz", "https://registry.npmjs.org/a/-/b-1.0.0.tgz"} {
		if _, _, ok := TarballSpec(bad); ok {
			t.Errorf("%s parsed", bad)
		}
	}
}

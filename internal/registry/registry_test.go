package registry

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func load(t *testing.T, name string) *Packument {
	t.Helper()
	b, err := os.ReadFile("../../testdata/registry/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var p Packument
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	return &p
}

func TestRealDocuments(t *testing.T) {
	ax := load(t, "axios")
	if !ax.Unpublished("1.14.1") || !ax.Unpublished("0.30.4") || ax.Unpublished("1.14.0") || ax.Unpublished("9.9.9") {
		t.Error("Unpublished")
	}
	if ax.SecurityHolding() || !load(t, "plain-crypto-js").SecurityHolding() {
		t.Error("SecurityHolding")
	}
	m := ax.Versions["1.14.0"]
	if m.NpmUser.TrustedPublisher == nil || m.Dist.Attestations == nil || m.GitHead == "" {
		t.Errorf("1.14.0 publish metadata: %+v", m.NpmUser)
	}
	// Predecessor follows the release line, not the semver neighbour.
	if p := ax.Predecessor("1.15.0"); p == nil || p.Version != "1.14.0" {
		t.Errorf("predecessor of 1.15.0: %v", p)
	}
	if p := ax.Predecessor("0.30.3"); p == nil || !strings.HasPrefix(p.Version, "0.30.") {
		t.Errorf("predecessor of 0.30.3: %v", p)
	}
	night := time.Date(2026, 3, 31, 1, 5, 0, 0, time.UTC)
	then := ax.At(night)
	if _, ok := then.Versions["1.15.0"]; ok {
		t.Error("At kept a later version")
	}
	if _, ok := then.Time["1.14.1"]; !ok {
		t.Error("At dropped a timestamp from before the cut")
	}
	ed := load(t, "easy-day-js")
	if ed.Repository.RepoKey() != load(t, "dayjs").Repository.RepoKey() {
		t.Errorf("repo keys %q vs %q", ed.Repository.RepoKey(), load(t, "dayjs").Repository.RepoKey())
	}
}

func TestRepoKey(t *testing.T) {
	want := "github.com/iamkun/dayjs"
	for _, u := range []string{"git+https://github.com/iamkun/dayjs.git", "https://github.com/iamkun/dayjs", "github:iamkun/dayjs", "iamkun/dayjs", "git@github.com:iamkun/dayjs.git", "git://github.com/iamkun/dayjs.git"} {
		if got := (Repository{URL: u}).RepoKey(); got != want {
			t.Errorf("%s -> %s", u, got)
		}
	}
}

func TestClientCacheAndOffline(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		switch strings.ToLower(r.URL.EscapedPath()) {
		case "/@acme%2fagent-kit":
			w.Write([]byte(`{"name":"@acme/agent-kit","readme":"` + strings.Repeat("x", 5000) + `","versions":{"0.9.2":{"name":"@acme/agent-kit","version":"0.9.2","dist":{}}},"time":{"0.9.2":"2026-06-17T08:00:00.000Z"}}`))
		case "/nope":
			w.WriteHeader(404)
		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	c := New(dir, false)
	c.Base = srv.URL
	p, err := c.Packument(context.Background(), "@acme/agent-kit")
	if err != nil || p.Versions["0.9.2"] == nil {
		t.Fatalf("scoped fetch: %v %v", p, err)
	}
	if p, _ := c.Packument(context.Background(), "nope"); p == nil || !p.Missing {
		t.Error("404 not reported as missing")
	}

	off := New(dir, true)
	off.Base = srv.URL
	if p, err := off.Packument(context.Background(), "@acme/agent-kit"); err != nil || p.Versions["0.9.2"] == nil {
		t.Errorf("offline replay: %v", err)
	}
	if p, err := off.Packument(context.Background(), "nope"); err != nil || !p.Missing {
		t.Errorf("cached 404: %v %v", p, err)
	}
	if _, err := off.Packument(context.Background(), "never-seen"); !errors.Is(err, ErrOffline) {
		t.Errorf("offline miss: %v", err)
	}
	if hits != 2 {
		t.Errorf("server hit %d times", hits)
	}
	// the README never reaches the cache
	b, _ := os.ReadFile(c.cachePath("@acme/agent-kit"))
	if strings.Contains(string(b), "xxxxx") {
		t.Error("cache kept fields graft doesn't read")
	}
}

func TestSlimKeepsWhatEvaluationReads(t *testing.T) {
	ax := load(t, "axios")
	s := ax.Slim()
	m, n := ax.Versions["1.14.0"], s.Versions["1.14.0"]
	if n.NpmUser.TrustedPublisher == nil || n.Dist.Attestations == nil || n.GitHead != m.GitHead ||
		len(n.Dependencies) != len(m.Dependencies) || n.Scripts["prepare"] != "" {
		t.Errorf("slim lost or kept the wrong fields: %+v", n)
	}
	b1, _ := json.Marshal(ax)
	b2, _ := json.Marshal(s)
	if len(b2) > len(b1)/2 {
		t.Errorf("slim is %d bytes vs %d", len(b2), len(b1))
	}
	if !s.Unpublished("1.14.1") {
		t.Error("time record lost")
	}
}

package lockfile

import (
	"path/filepath"
	"strings"
	"testing"
)

func parse(t *testing.T, rel string) *Lockfile {
	t.Helper()
	lf, err := Parse(filepath.Join("../../testdata/lockfiles", rel))
	if err != nil {
		t.Fatal(err)
	}
	return lf
}

func find(lf *Lockfile, name string) *Package {
	for i := range lf.Packages {
		if lf.Packages[i].Name == name {
			return &lf.Packages[i]
		}
	}
	return nil
}

func TestNPMv3(t *testing.T) {
	lf := parse(t, "npm-v3/package-lock.json")
	if lf.Kind != "npm" || lf.Version != "3" {
		t.Errorf("kind %s v%s", lf.Kind, lf.Version)
	}
	ax := find(lf, "axios")
	if ax == nil || ax.Version != "1.14.1" || !ax.Direct || !ax.Registry || ax.Line == 0 {
		t.Fatalf("axios = %+v", ax)
	}
	if pc := find(lf, "plain-crypto-js"); pc == nil || pc.Direct || pc.Version != "4.2.1" {
		t.Errorf("plain-crypto-js = %+v", pc)
	}
	// npm:alias resolves to the real registry name.
	if dj := find(lf, "dayjs"); dj == nil || dj.Alias != "dayjs-legacy" || dj.Version != "1.11.19" {
		t.Errorf("alias = %+v", dj)
	}
	// git dependency: listed, not sent to the registry.
	if w := find(lf, "widgets"); w == nil || w.Registry {
		t.Errorf("git dep = %+v", w)
	}
	// nested install path and a dev flag
	if d := find(lf, "debug"); d == nil || d.Path != "node_modules/express/node_modules/debug" || d.Direct {
		t.Errorf("nested = %+v", d)
	}
	if c := find(lf, "chalk"); c == nil || !c.Dev || !c.Direct {
		t.Errorf("dev = %+v", c)
	}
}

func TestNPMv1(t *testing.T) {
	lf := parse(t, "npm-v1/package-lock.json")
	if p := find(lf, "plain-crypto-js"); p == nil || p.Path != "node_modules/axios/node_modules/plain-crypto-js" {
		t.Errorf("nested v1 = %+v", p)
	}
	if p := find(lf, "easy-day-js"); p == nil || p.Alias != "date-lib" || p.Version != "1.11.22" {
		t.Errorf("v1 alias = %+v", p)
	}
}

func TestYarnClassic(t *testing.T) {
	lf := parse(t, "yarn-classic/yarn.lock")
	if lf.Kind != "yarn" {
		t.Fatalf("kind %s", lf.Kind)
	}
	if p := find(lf, "@acme/agent-kit"); p == nil || p.Version != "0.9.2" || p.Line != 4 {
		t.Errorf("scoped = %+v", p)
	}
	if p := find(lf, "easy-day-js"); p == nil || p.Version != "1.11.22" || !strings.HasPrefix(p.Integrity, "sha512-") {
		t.Errorf("easy-day-js = %+v", p)
	}
	if p := find(lf, "local-utils"); p == nil || p.Registry {
		t.Errorf("file: dep = %+v", p)
	}
}

func TestYarnBerry(t *testing.T) {
	lf := parse(t, "yarn-berry/yarn.lock")
	if lf.Kind != "yarn-berry" || lf.Version != "8" {
		t.Fatalf("kind %s v%s", lf.Kind, lf.Version)
	}
	if p := find(lf, "debug"); p == nil || p.Version != "4.4.2" || !p.Registry || p.Line == 0 {
		t.Errorf("debug = %+v", p)
	}
	if p := find(lf, "app"); p == nil || p.Registry {
		t.Errorf("workspace = %+v", p)
	}
}

func TestPNPM(t *testing.T) {
	v9 := parse(t, "pnpm-v9/pnpm-lock.yaml")
	if p := find(v9, "@acme/agent-kit"); p == nil || p.Version != "0.9.2" || !p.Direct || p.Line == 0 {
		t.Errorf("v9 scoped = %+v", p)
	}
	if p := find(v9, "easy-day-js"); p == nil || p.Direct {
		t.Errorf("v9 transitive = %+v", p)
	}
	v6 := parse(t, "pnpm-v6/pnpm-lock.yaml")
	if p := find(v6, "@babel/runtime"); p == nil || p.Version != "7.26.0" {
		t.Errorf("v6 peer suffix = %+v", p)
	}
	if p := find(v6, "debug"); p == nil || !p.Direct {
		t.Errorf("v6 direct = %+v", p)
	}
}

func TestPNPMv5Key(t *testing.T) {
	for key, want := range map[string]string{
		"/axios/1.14.1":                  "axios@1.14.1",
		"/@scope/pkg/2.0.0_react@18.3.1": "@scope/pkg@2.0.0",
		"/axios@1.14.1":                  "axios@1.14.1",
		"@scope/pkg@2.0.0(react@18.3.1)": "@scope/pkg@2.0.0",
	} {
		n, v := pnpmKey(key)
		if n+"@"+v != want {
			t.Errorf("pnpmKey(%q) = %s@%s, want %s", key, n, v, want)
		}
	}
}

func TestDiscover(t *testing.T) {
	got, err := Discover("../../testdata/lockfiles")
	if err != nil || len(got) != 6 {
		t.Fatalf("discover: %v %v", got, err)
	}
}

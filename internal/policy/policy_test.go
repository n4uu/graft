package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	p := Default()
	if p.Level(20) != "critical" || p.Level(7) != "high" || p.Level(4.5) != "medium" || p.Level(1) != "low" || p.Level(0.5) != "none" {
		t.Error("levels")
	}
	if in, ok := p.Known.Match("axios", "1.14.1"); !ok || in.Date != "2026-03-31" {
		t.Errorf("feed match: %+v", in)
	}
	if _, ok := p.Known.Match("axios", "1.14.0"); ok {
		t.Error("clean version matched")
	}
	if _, ok := p.Known.Match("plain-crypto-js", "4.2.0"); !ok {
		t.Error("wildcard entry")
	}
	if !p.IsPopular("dayjs") || p.IsPopular("easy-day-js") {
		t.Error("popular list")
	}
	if p.BurstWindow.Hours() != 2 || p.PublisherBurst.MinOwners != 3 {
		t.Error("durations")
	}
}

func TestOverride(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "p.yaml")
	os.WriteFile(f, []byte("signals:\n  lookalike_name: {points: 0, group: identity}\nallow:\n  packages: [left-pad]\n"), 0o644)
	p, err := Load(f)
	if err != nil {
		t.Fatal(err)
	}
	if p.Signals["lookalike_name"].Points != 0 || p.Signals["impersonation"].Points != 6 || !p.Skips("left-pad") {
		t.Errorf("override merge: %+v", p.Signals["lookalike_name"])
	}
	os.WriteFile(f, []byte("signals:\n  made_up: {points: 1, group: x}\n"), 0o644)
	if _, err := Load(f); err == nil {
		t.Error("unknown signal accepted")
	}
	os.WriteFile(f, []byte("thresholds: {critical: 1, high: 2, medium: 3, low: 4}\n"), 0o644)
	if _, err := Load(f); err == nil {
		t.Error("inverted thresholds accepted")
	}
}

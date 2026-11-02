// Package policy holds graft's tunables: signal weights, thresholds,
// allowlists, the known-malicious feed and the popular-package list. All of
// it is data embedded from data/, and every part can be replaced from a
// file without rebuilding.
package policy

import (
	"bufio"
	_ "embed"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed data/default.yaml
var defaultYAML []byte

//go:embed data/known.yaml
var knownYAML []byte

//go:embed data/popular.txt
var popularTxt string

// Weight is one signal's points and correlation group.
type Weight struct {
	Points float64 `yaml:"points"`
	Group  string  `yaml:"group"`
}

// Policy is the evaluation configuration.
type Policy struct {
	Thresholds struct {
		Critical float64 `yaml:"critical"`
		High     float64 `yaml:"high"`
		Medium   float64 `yaml:"medium"`
		Low      float64 `yaml:"low"`
	} `yaml:"thresholds"`
	GroupDecay     float64  `yaml:"group_decay"`
	YoungDays      int      `yaml:"young_days"`
	BurstWindow    Duration `yaml:"burst_window"`
	PublisherBurst struct {
		Window    Duration `yaml:"window"`
		MinOwners int      `yaml:"min_owners"`
	} `yaml:"publisher_burst"`
	Signals map[string]Weight `yaml:"signals"`
	Allow   struct {
		InstallScripts []string `yaml:"install_scripts"`
		Packages       []string `yaml:"packages"`
	} `yaml:"allow"`

	Known   Feed     `yaml:"-"`
	Popular []string `yaml:"-"`
}

// Duration parses "2h", "30m".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	d.Duration = v
	return nil
}

// Default returns the embedded policy, feed and popular list.
func Default() *Policy {
	p, err := parse(defaultYAML)
	if err != nil {
		panic("embedded policy: " + err.Error())
	}
	if p.Known, err = ParseFeed(knownYAML); err != nil {
		panic("embedded feed: " + err.Error())
	}
	p.Popular = parseList(popularTxt)
	return p
}

// Load reads a policy file. Fields it omits keep their default values, so
// a file can override just a weight or an allowlist.
func Load(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := Default()
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	over := *p
	over.Signals = map[string]Weight{}
	if err := dec.Decode(&over); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for k, w := range over.Signals {
		if _, ok := p.Signals[k]; !ok {
			return nil, fmt.Errorf("%s: unknown signal %q", path, k)
		}
		p.Signals[k] = w
	}
	over.Signals = p.Signals
	if err := over.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &over, nil
}

func parse(b []byte) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, err
	}
	return &p, p.validate()
}

func (p *Policy) validate() error {
	t := p.Thresholds
	if !(t.Critical > t.High && t.High > t.Medium && t.Medium > t.Low && t.Low > 0) {
		return fmt.Errorf("thresholds must satisfy critical > high > medium > low > 0")
	}
	if p.GroupDecay <= 0 || p.GroupDecay > 1 {
		return fmt.Errorf("group_decay must be in (0,1]")
	}
	for k, w := range p.Signals {
		if w.Points < 0 || w.Group == "" {
			return fmt.Errorf("signal %s: needs points >= 0 and a group", k)
		}
	}
	return nil
}

func parseList(s string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return out
}

// Level maps a score to a severity name.
func (p *Policy) Level(score float64) string {
	t := p.Thresholds
	switch {
	case score >= t.Critical:
		return "critical"
	case score >= t.High:
		return "high"
	case score >= t.Medium:
		return "medium"
	case score >= t.Low:
		return "low"
	}
	return "none"
}

// LevelRank orders levels for -fail-on comparisons.
func LevelRank(l string) int {
	switch l {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	case "none":
		return 0
	}
	return -1
}

// AllowsInstallScript reports whether name may add install scripts.
func (p *Policy) AllowsInstallScript(name string) bool { return contains(p.Allow.InstallScripts, name) }

// Skips reports whether name is excluded from evaluation.
func (p *Policy) Skips(name string) bool { return contains(p.Allow.Packages, name) }

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// IsPopular reports whether name is on the popular list.
func (p *Policy) IsPopular(name string) bool {
	i := sort.SearchStrings(p.Popular, name)
	return i < len(p.Popular) && p.Popular[i] == name
}

// DefaultYAML returns the embedded policy source, comments included.
func DefaultYAML() []byte { return defaultYAML }

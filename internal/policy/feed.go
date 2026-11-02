package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Incident is one entry of the known-malicious feed.
type Incident struct {
	Name     string              `yaml:"incident"`
	Date     string              `yaml:"date"`
	Refs     []string            `yaml:"refs"`
	Packages map[string][]string `yaml:"packages"`
}

// Feed is a list of incidents.
type Feed []Incident

// ParseFeed decodes a feed document.
func ParseFeed(b []byte) (Feed, error) {
	var f Feed
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	for _, in := range f {
		if in.Name == "" || len(in.Packages) == 0 {
			return nil, fmt.Errorf("feed entry without incident name or packages")
		}
	}
	return f, nil
}

// LoadFeed reads an extra feed file and appends it to the policy's feed.
func (p *Policy) LoadFeed(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	f, err := ParseFeed(b)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	p.Known = append(p.Known, f...)
	return nil
}

// Match returns the incident that lists name@version, if any.
func (f Feed) Match(name, version string) (*Incident, bool) {
	for i := range f {
		for _, v := range f[i].Packages[name] {
			if v == "*" || v == version {
				return &f[i], true
			}
		}
	}
	return nil, false
}

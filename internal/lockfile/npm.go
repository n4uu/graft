package lockfile

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/n4uu/graft/internal/semver"
)

type npmEntry struct {
	Name         string                     `json:"name"`
	Version      string                     `json:"version"`
	Resolved     string                     `json:"resolved"`
	Integrity    string                     `json:"integrity"`
	Dev          bool                       `json:"dev"`
	Optional     bool                       `json:"optional"`
	DevOptional  bool                       `json:"devOptional"`
	Link         bool                       `json:"link"`
	Dependencies map[string]json.RawMessage `json:"dependencies"` // v1: nested entries; v2+ root: ranges
	DevDeps      map[string]string          `json:"devDependencies"`
	OptDeps      map[string]string          `json:"optionalDependencies"`
}

type npmLock struct {
	LockfileVersion int                        `json:"lockfileVersion"`
	Packages        map[string]*npmEntry       `json:"packages"`
	Dependencies    map[string]json.RawMessage `json:"dependencies"`
}

func parseNPM(b []byte) (*Lockfile, error) {
	var l npmLock
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, err
	}
	lf := &Lockfile{Kind: "npm", Version: fmt.Sprint(l.LockfileVersion)}
	idx := newLineIndex(b)

	if len(l.Packages) > 0 {
		direct := map[string]bool{}
		if root := l.Packages[""]; root != nil {
			for k := range root.Dependencies {
				direct[k] = true
			}
			for k := range root.DevDeps {
				direct[k] = true
			}
			for k := range root.OptDeps {
				direct[k] = true
			}
		}
		keys := make([]string, 0, len(l.Packages))
		for k := range l.Packages {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, key := range keys {
			e := l.Packages[key]
			if key == "" || e.Link || e.Version == "" {
				continue
			}
			i := strings.LastIndex(key, "node_modules/")
			if i < 0 {
				continue // workspace package source dir, not an install
			}
			installed := key[i+len("node_modules/"):]
			p := Package{
				Name: installed, Version: e.Version, Resolved: e.Resolved, Integrity: e.Integrity,
				Dev: e.Dev || e.DevOptional, Optional: e.Optional, Path: key,
				Direct: direct[installed] && strings.Count(key, "node_modules/") == 1,
			}
			if e.Name != "" && e.Name != installed {
				p.Name, p.Alias = e.Name, installed
			}
			p.Registry = isRegistryURL(e.Resolved) && semver.Parse(e.Version).Valid()
			p.Line, _ = lineOf(b, idx, `"`+key+`":`, 0)
			lf.Packages = append(lf.Packages, p)
		}
		return lf, nil
	}

	// lockfileVersion 1: nested "dependencies" objects.
	var walk func(deps map[string]json.RawMessage, path string, top bool)
	walk = func(deps map[string]json.RawMessage, path string, top bool) {
		names := make([]string, 0, len(deps))
		for k := range deps {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, name := range names {
			var e npmEntry
			if json.Unmarshal(deps[name], &e) != nil || e.Version == "" {
				continue
			}
			p := Package{
				Name: name, Version: e.Version, Resolved: e.Resolved, Integrity: e.Integrity,
				Dev: e.Dev, Optional: e.Optional, Path: path + "node_modules/" + name, Direct: top,
			}
			// v1 aliases: "version": "npm:real-name@1.2.3"
			if strings.HasPrefix(e.Version, "npm:") {
				real, v := splitSpec(strings.TrimPrefix(e.Version, "npm:"))
				p.Name, p.Version, p.Alias = real, v, name
			}
			p.Registry = isRegistryURL(e.Resolved) && semver.Parse(p.Version).Valid()
			p.Line, _ = lineOf(b, idx, `"`+name+`": {`, 0)
			lf.Packages = append(lf.Packages, p)
			if len(e.Dependencies) > 0 {
				walk(e.Dependencies, p.Path+"/", false)
			}
		}
	}
	walk(l.Dependencies, "", true)
	return lf, nil
}

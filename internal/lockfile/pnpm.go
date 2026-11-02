package lockfile

import (
	"strings"

	"github.com/n4uu/graft/internal/semver"
	"gopkg.in/yaml.v3"
)

type pnpmLock struct {
	LockfileVersion any                       `yaml:"lockfileVersion"`
	Importers       map[string]pnpmImporter   `yaml:"importers"`
	Dependencies    map[string]any            `yaml:"dependencies"`    // v5/v6 single project
	DevDependencies map[string]any            `yaml:"devDependencies"` // v5/v6 single project
	Packages        map[string]pnpmPackage    `yaml:"packages"`
	Snapshots       map[string]map[string]any `yaml:"snapshots"`
}

type pnpmImporter struct {
	Dependencies         map[string]any `yaml:"dependencies"`
	DevDependencies      map[string]any `yaml:"devDependencies"`
	OptionalDependencies map[string]any `yaml:"optionalDependencies"`
}

type pnpmPackage struct {
	Resolution struct {
		Integrity string `yaml:"integrity"`
		Tarball   string `yaml:"tarball"`
		Type      string `yaml:"type"`
	} `yaml:"resolution"`
	Name     string `yaml:"name"`
	Version  string `yaml:"version"`
	Dev      bool   `yaml:"dev"`
	Optional bool   `yaml:"optional"`
}

// parsePNPM handles three key styles:
//
//	v5:  /axios/1.14.1          /@scope/name/1.0.0_peer@2.0.0
//	v6:  /axios@1.14.1          /@scope/name@1.0.0(peer@2.0.0)
//	v9:  axios@1.14.1           @scope/name@1.0.0   (peers only in snapshots)
func parsePNPM(b []byte) (*Lockfile, error) {
	var l pnpmLock
	if err := yaml.Unmarshal(b, &l); err != nil {
		return nil, err
	}
	lf := &Lockfile{Kind: "pnpm", Version: toString(l.LockfileVersion)}
	idx := newLineIndex(b)

	direct := map[string]bool{}
	addDirect := func(m map[string]any) {
		for k := range m {
			direct[k] = true
		}
	}
	for _, imp := range l.Importers {
		addDirect(imp.Dependencies)
		addDirect(imp.DevDependencies)
		addDirect(imp.OptionalDependencies)
	}
	addDirect(l.Dependencies)
	addDirect(l.DevDependencies)

	seen := map[string]bool{}
	for key, e := range l.Packages {
		name, version := pnpmKey(key)
		if e.Name != "" {
			name = e.Name
		}
		if e.Version != "" {
			version = e.Version
		}
		if name == "" || seen[name+"@"+version] {
			continue
		}
		seen[name+"@"+version] = true
		p := Package{
			Name: name, Version: version, Integrity: e.Resolution.Integrity, Resolved: e.Resolution.Tarball,
			Dev: e.Dev, Optional: e.Optional, Path: key, Direct: direct[name],
		}
		p.Registry = e.Resolution.Type == "" && e.Resolution.Integrity != "" && semver.Parse(version).Valid()
		if p.Resolved != "" && !isRegistryURL(p.Resolved) {
			p.Registry = false
		}
		p.Line, _ = lineOf(b, idx, key+":", 0)
		if p.Line == 0 {
			p.Line, _ = lineOf(b, idx, "'"+key+"':", 0)
		}
		lf.Packages = append(lf.Packages, p)
	}
	return lf, nil
}

func pnpmKey(key string) (string, string) {
	k := strings.TrimPrefix(key, "/")
	if i := strings.IndexByte(k, '('); i > 0 {
		k = k[:i] // v6 peer suffix
	}
	// v6/v9: name@version, where name may start with @scope/. A v5 key
	// with a peer suffix (/pkg/1.0.0_react@18.3.1) also contains an @, so
	// the part before it has to look like a package name to count.
	if at := strings.LastIndex(k, "@"); at > 0 {
		name, v := k[:at], k[at+1:]
		if !strings.Contains(v, "/") && validName(name) {
			return name, v
		}
	}
	// v5: name/version or @scope/name/version, peers after "_"
	if i := strings.IndexByte(k, '_'); i > 0 {
		k = k[:i]
	}
	slash := strings.LastIndex(k, "/")
	if slash <= 0 {
		return "", ""
	}
	return k[:slash], k[slash+1:]
}

func validName(n string) bool {
	if strings.HasPrefix(n, "@") {
		return strings.Count(n, "/") == 1
	}
	return !strings.Contains(n, "/")
}

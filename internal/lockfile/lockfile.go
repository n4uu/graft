// Package lockfile reads the dependency lockfiles of the three npm-registry
// package managers into one flat list of resolved packages.
//
// Supported: package-lock.json / npm-shrinkwrap.json (lockfileVersion 1, 2
// and 3), yarn.lock (classic v1 and berry), pnpm-lock.yaml (v5, v6, v9).
package lockfile

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Package is one resolved dependency.
type Package struct {
	Name      string `json:"name"`            // real registry name
	Version   string `json:"version"`         // exact resolved version
	Alias     string `json:"alias,omitempty"` // installed-as name for npm:alias deps
	Resolved  string `json:"resolved,omitempty"`
	Integrity string `json:"integrity,omitempty"`
	Dev       bool   `json:"dev,omitempty"`
	Optional  bool   `json:"optional,omitempty"`
	Direct    bool   `json:"direct,omitempty"` // declared by the project itself
	Path      string `json:"path,omitempty"`   // install path (npm) or lock key
	Registry  bool   `json:"registry"`         // false for git, file, link and tarball-URL deps
	Line      int    `json:"line,omitempty"`   // 1-based line of the entry in the lockfile
}

// Spec is name@version.
func (p Package) Spec() string { return p.Name + "@" + p.Version }

// Lockfile is a parsed lockfile.
type Lockfile struct {
	Path     string    `json:"path"`
	Kind     string    `json:"kind"` // npm, yarn, yarn-berry, pnpm
	Version  string    `json:"version,omitempty"`
	Packages []Package `json:"packages"`
}

// Names lockfiles are recognised by.
var Names = map[string]string{
	"package-lock.json":   "npm",
	"npm-shrinkwrap.json": "npm",
	"yarn.lock":           "yarn",
	"pnpm-lock.yaml":      "pnpm",
}

// Parse reads one lockfile, choosing the parser by file name.
func Parse(path string) (*Lockfile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	kind, ok := Names[filepath.Base(path)]
	if !ok {
		return nil, fmt.Errorf("%s: not a recognised lockfile name", path)
	}
	var lf *Lockfile
	switch kind {
	case "npm":
		lf, err = parseNPM(b)
	case "yarn":
		lf, err = parseYarn(b)
	case "pnpm":
		lf, err = parsePNPM(b)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	lf.Path = path
	sort.SliceStable(lf.Packages, func(i, j int) bool {
		if lf.Packages[i].Name != lf.Packages[j].Name {
			return lf.Packages[i].Name < lf.Packages[j].Name
		}
		return lf.Packages[i].Version < lf.Packages[j].Version
	})
	return lf, nil
}

// Discover finds lockfiles under root, skipping node_modules and VCS
// directories. A path that is itself a lockfile is returned as is.
func Discover(root string) ([]string, error) {
	st, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return []string{root}, nil
	}
	var out []string
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable subtree: skip, keep walking
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git", ".hg", ".svn", ".yarn", ".pnpm-store":
				return filepath.SkipDir
			}
			return nil
		}
		if _, ok := Names[d.Name()]; ok {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

// lineIndex maps byte offsets to line numbers.
type lineIndex []int

func newLineIndex(b []byte) lineIndex {
	idx := lineIndex{0}
	for i, c := range b {
		if c == '\n' {
			idx = append(idx, i+1)
		}
	}
	return idx
}

func (l lineIndex) line(off int) int {
	return sort.Search(len(l), func(i int) bool { return l[i] > off })
}

// lineOf returns the line of the first occurrence of needle at or after
// from, and the offset just past it, or 0 if absent.
func lineOf(b []byte, idx lineIndex, needle string, from int) (int, int) {
	if from >= len(b) {
		return 0, from
	}
	i := strings.Index(string(b[from:]), needle)
	if i < 0 {
		return 0, from
	}
	return idx.line(from + i), from + i + len(needle)
}

// splitSpec splits "name@range" where name may be scoped ("@a/b@^1").
func splitSpec(s string) (name, rest string) {
	at := strings.LastIndex(s, "@")
	if at <= 0 {
		return s, ""
	}
	return s[:at], s[at+1:]
}

// isRegistryURL reports whether a resolved URL points at an npm registry
// tarball rather than git, a local path or an arbitrary URL.
func isRegistryURL(u string) bool {
	if u == "" {
		return true // npm omits resolved for some registry deps
	}
	switch {
	case strings.HasPrefix(u, "git"), strings.HasPrefix(u, "file:"), strings.HasPrefix(u, "link:"),
		strings.HasPrefix(u, "github:"), strings.Contains(u, "codeload.github.com"):
		return false
	}
	return strings.Contains(u, "/-/") // registry tarball layout: /<name>/-/<name>-<v>.tgz
}

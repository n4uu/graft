// Package cacache reads npm's content-addressable cache index
// (~/.npm/_cacache/index-v5) to list every registry tarball a machine has
// downloaded, and when.
//
// After an incident the lockfile usually gets fixed first, and node_modules
// rebuilt. The cache index is append-only and survives both: if
// axios-1.14.1.tgz was ever fetched on this host, there's a line for it,
// with a millisecond timestamp.
package cacache

import (
	"bufio"
	"encoding/json"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Entry is one cached tarball.
type Entry struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	URL       string    `json:"url"`
	Integrity string    `json:"integrity,omitempty"`
	Fetched   time.Time `json:"fetched"`
	Index     string    `json:"index_file"`
}

// Spec is name@version.
func (e Entry) Spec() string { return e.Name + "@" + e.Version }

type indexLine struct {
	Key       string `json:"key"`
	Integrity string `json:"integrity"`
	Time      int64  `json:"time"`
}

// DefaultDir is where npm keeps its cache on this machine.
func DefaultDir() string {
	if d := os.Getenv("npm_config_cache"); d != "" {
		return filepath.Join(d, "_cacache")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	if os.PathSeparator == '\\' {
		if la := os.Getenv("LocalAppData"); la != "" {
			return filepath.Join(la, "npm-cache", "_cacache")
		}
	}
	return filepath.Join(home, ".npm", "_cacache")
}

// Scan reads every bucket under dir/index-v5. Each bucket line is
// "<sha1 of json>\t<json>"; a key may appear several times (re-fetches),
// and the earliest fetch is the one that matters for a timeline.
func Scan(dir string) ([]Entry, error) {
	root := filepath.Join(dir, "index-v5")
	if _, err := os.Stat(root); err != nil {
		return nil, err
	}
	first := map[string]Entry{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		for sc.Scan() {
			_, js, ok := strings.Cut(sc.Text(), "\t")
			if !ok {
				continue
			}
			var l indexLine
			if json.Unmarshal([]byte(js), &l) != nil || l.Key == "" {
				continue
			}
			u := strings.TrimPrefix(l.Key, "make-fetch-happen:request-cache:")
			name, version, ok := TarballSpec(u)
			if !ok {
				continue
			}
			e := Entry{Name: name, Version: version, URL: u, Integrity: l.Integrity, Fetched: time.UnixMilli(l.Time).UTC(), Index: p}
			if have, ok := first[u]; !ok || e.Fetched.Before(have.Fetched) {
				first[u] = e
			}
		}
		return nil
	})
	out := make([]Entry, 0, len(first))
	for _, e := range first {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fetched.Before(out[j].Fetched) })
	return out, err
}

// TarballSpec parses a registry tarball URL:
//
//	https://registry.npmjs.org/axios/-/axios-1.14.1.tgz
//	https://registry.npmjs.org/@scope/name/-/name-2.0.0.tgz
func TarballSpec(raw string) (name, version string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", false
	}
	path, err := url.PathUnescape(u.EscapedPath())
	if err != nil {
		return "", "", false
	}
	before, file, found := strings.Cut(strings.TrimPrefix(path, "/"), "/-/")
	if !found || !strings.HasSuffix(file, ".tgz") {
		return "", "", false
	}
	name = before
	base := name
	if i := strings.LastIndex(name, "/"); i >= 0 {
		base = name[i+1:]
	}
	file = strings.TrimSuffix(file, ".tgz")
	if !strings.HasPrefix(file, base+"-") {
		return "", "", false
	}
	return name, strings.TrimPrefix(file, base+"-"), true
}

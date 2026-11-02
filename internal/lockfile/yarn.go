package lockfile

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"

	"github.com/n4uu/graft/internal/semver"
	"gopkg.in/yaml.v3"
)

func parseYarn(b []byte) (*Lockfile, error) {
	if bytes.Contains(b, []byte("\n__metadata:")) || bytes.HasPrefix(b, []byte("__metadata:")) {
		return parseBerry(b)
	}
	return parseYarnClassic(b)
}

// parseYarnClassic reads the v1 format, which is YAML-like but not YAML:
//
//	"axios@^1.14.0", axios@^1.13.0:
//	  version "1.14.1"
//	  resolved "https://registry.yarnpkg.com/axios/-/axios-1.14.1.tgz#..."
//	  integrity sha512-...
func parseYarnClassic(b []byte) (*Lockfile, error) {
	lf := &Lockfile{Kind: "yarn", Version: "1"}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var cur *Package
	line := 0
	flush := func() {
		if cur != nil && cur.Version != "" {
			cur.Registry = cur.Registry && isRegistryURL(cur.Resolved) && semver.Parse(cur.Version).Valid()
			lf.Packages = append(lf.Packages, *cur)
		}
		cur = nil
	}
	for sc.Scan() {
		line++
		text := sc.Text()
		if strings.TrimSpace(text) == "" || strings.HasPrefix(text, "#") {
			continue
		}
		if !strings.HasPrefix(text, " ") {
			flush()
			header := strings.TrimSuffix(text, ":")
			first := strings.TrimSpace(strings.Split(header, ",")[0])
			first = strings.Trim(first, `"`)
			name, rng := splitSpec(first)
			cur = &Package{Name: name, Path: header, Line: line, Registry: true}
			// alias@npm:real@range
			if strings.HasPrefix(rng, "npm:") {
				real, _ := splitSpec(strings.TrimPrefix(rng, "npm:"))
				cur.Alias, cur.Name = name, real
			}
			if strings.Contains(rng, "://") || strings.HasPrefix(rng, "file:") || strings.HasPrefix(rng, "link:") {
				cur.Registry = false
			}
			continue
		}
		if cur == nil || strings.HasPrefix(text, "    ") {
			continue // nested dependency lists
		}
		key, val, _ := strings.Cut(strings.TrimSpace(text), " ")
		val = unquote(val)
		switch key {
		case "version":
			cur.Version = val
		case "resolved":
			cur.Resolved = val
		case "integrity":
			cur.Integrity = val
		}
	}
	flush()
	return lf, sc.Err()
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if u, err := strconv.Unquote(s); err == nil {
		return u
	}
	return strings.Trim(s, `"`)
}

// parseBerry reads yarn 2+ lockfiles, which are real YAML:
//
//	"axios@npm:^1.14.0":
//	  version: 1.14.1
//	  resolution: "axios@npm:1.14.1"
//	  checksum: 10c0/...
func parseBerry(b []byte) (*Lockfile, error) {
	var doc map[string]map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	lf := &Lockfile{Kind: "yarn-berry"}
	if md, ok := doc["__metadata"]; ok {
		lf.Version = toString(md["version"])
	}
	idx := newLineIndex(b)
	for key, e := range doc {
		if key == "__metadata" {
			continue
		}
		res := toString(e["resolution"])
		name, ref := splitSpec(res)
		p := Package{Name: name, Version: toString(e["version"]), Path: key, Integrity: toString(e["checksum"])}
		switch {
		case strings.HasPrefix(ref, "npm:"):
			p.Version = strings.TrimPrefix(ref, "npm:")
			p.Registry = semver.Parse(p.Version).Valid()
		default:
			// workspace:, patch:, link:, portal:, file:, git and URL refs
			p.Registry = false
		}
		// key "alias@npm:real@^1" for aliases
		kn, krest := splitSpec(strings.Trim(strings.Split(key, ",")[0], `" `))
		if strings.HasPrefix(krest, "npm:") && strings.Contains(strings.TrimPrefix(krest, "npm:"), "@") {
			p.Alias = kn
		}
		needle := key
		if !strings.Contains(string(b), needle+":") {
			needle = strings.Split(key, ",")[0]
		}
		p.Line, _ = lineOf(b, idx, needle, 0)
		lf.Packages = append(lf.Packages, p)
	}
	return lf, nil
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int:
		return strconv.Itoa(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case nil:
		return ""
	}
	return ""
}

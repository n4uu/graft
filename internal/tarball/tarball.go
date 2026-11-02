// Package tarball inspects package tarballs without extracting or running
// anything: it reads the gzipped tar in memory and looks at what the
// install scripts would execute.
package tarball

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Package is a tarball's contents.
type Package struct {
	Files   map[string][]byte // path relative to the package root
	Scripts map[string]string // from the tarball's own package.json
	Version string
}

// Limits keep a hostile tarball (zip bomb, huge file count) from eating
// the machine.
const (
	maxTotal = 128 << 20
	maxFile  = 16 << 20
	maxFiles = 20000
)

// Read parses a .tgz. npm packs everything under a top-level directory
// (usually "package/"), which is stripped.
func Read(tgz []byte) (*Package, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(io.LimitReader(gz, maxTotal))
	p := &Package{Files: map[string][]byte{}}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return p, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		if len(p.Files) >= maxFiles {
			return p, fmt.Errorf("more than %d files", maxFiles)
		}
		name := path.Clean(h.Name)
		if i := strings.IndexByte(name, '/'); i >= 0 {
			name = name[i+1:]
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxFile))
		if err != nil {
			return p, err
		}
		p.Files[name] = b
	}
	if pj, ok := p.Files["package.json"]; ok {
		var m struct {
			Version string            `json:"version"`
			Scripts map[string]string `json:"scripts"`
		}
		if json.Unmarshal(pj, &m) == nil {
			p.Scripts, p.Version = m.Scripts, m.Version
		}
	}
	return p, nil
}

// Finding is one thing the inspection noticed.
type Finding struct {
	Kind   string // obfuscated_code, install_script_behaviour, self_tampering
	File   string
	Detail string
}

var (
	reHexIdent  = regexp.MustCompile(`_0x[0-9a-f]{4,6}`)
	reRotate    = regexp.MustCompile(`\[['"]push['"]\]\(\s*[\w$]{1,12}\[['"]shift['"]\]\(\)\s*\)`)
	reHexEscape = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	reNodeFile  = regexp.MustCompile(`(?:^|[\s;&|])node\s+(?:-[^\s]+\s+)*["']?\.?/?([\w./-]+\.(?:c|m)?js)`)
	reShellFile = regexp.MustCompile(`(?:^|[\s;&|])(?:sh|bash)\s+["']?\.?/?([\w./-]+\.sh)`)
)

// behaviours the install-time code is checked for, with what each means.
var behaviours = []struct {
	re   *regexp.Regexp
	what string
}{
	{regexp.MustCompile(`child_process|\bexecSync\b|\bspawnSync?\b|\bexecFile\b`), "starts processes"},
	{regexp.MustCompile(`require\(\s*['"](?:node:)?(?:https?|net|dns|tls|dgram)['"]\s*\)|\bfetch\(|\baxios\b|XMLHttpRequest`), "makes network requests"},
	{regexp.MustCompile(`NPM_TOKEN|NODE_AUTH_TOKEN|GITHUB_TOKEN|GH_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET|\.npmrc|_authToken`), "reads publish or cloud credentials"},
	{regexp.MustCompile(`(?i)(?:curl|wget)\s[^|]*\|\s*(?:sh|bash)|powershell(?:\.exe)?\s+-(?:e|enc|encodedcommand)\b|iex\s*\(|Invoke-Expression`), "downloads and runs a script"},
	{regexp.MustCompile(`\beval\s*\(|new\s+Function\s*\(|\.constructor\(\s*['"]return`), "evaluates dynamically built code"},
	{regexp.MustCompile(`os\.platform\(\)|process\.platform`), "branches on the operating system"},
	{regexp.MustCompile(`(?i)trufflehog|\.ssh[/\\]|id_rsa|wallet|keychain|Login Data`), "looks for secrets or wallets on disk"},
}

var tamper = []struct {
	re   *regexp.Regexp
	what string
}{
	{regexp.MustCompile(`unlink(?:Sync)?\(\s*__filename|rm(?:Sync)?\(\s*__filename|unlink(?:Sync)?\([^)]*['"](?:setup|install|postinstall|preinstall)\.js['"]`), "deletes itself after running"},
	{regexp.MustCompile(`(?:rename|copyFile|writeFile)(?:Sync)?\([^)]*package\.(?:json|md)`), "rewrites the package's own package.json"},
}

// Inspect looks at a version's install scripts and the files they run,
// and, given the previous version, at files that are new or grew a lot.
func Inspect(cur, prev *Package) []Finding {
	var out []Finding
	targets := installTargets(cur)
	for _, f := range targets {
		src := string(cur.Files[f])
		var did []string
		for _, b := range behaviours {
			if b.re.MatchString(src) {
				did = append(did, b.what)
			}
		}
		if len(did) >= 2 {
			out = append(out, Finding{"install_script_behaviour", f, fmt.Sprintf("%s, run on install, %s", f, strings.Join(did, ", "))})
		}
		for _, t := range tamper {
			if t.re.MatchString(src) {
				out = append(out, Finding{"self_tampering", f, fmt.Sprintf("%s %s", f, t.what)})
			}
		}
	}

	// Obfuscation: any install target, plus JS that is new since the last
	// version or more than three times its old size.
	check := map[string]string{}
	for _, f := range targets {
		check[f] = "run on install"
	}
	if prev != nil {
		for f, b := range cur.Files {
			if !isJS(f) {
				continue
			}
			if _, already := check[f]; already {
				continue // "run on install" says more than "new"
			}
			old, existed := prev.Files[f]
			switch {
			case !existed:
				check[f] = "new in this version"
			case len(b) > 3*len(old)+4096:
				check[f] = fmt.Sprintf("grew from %d to %d bytes", len(old), len(b))
			}
		}
	}
	names := make([]string, 0, len(check))
	for f := range check {
		names = append(names, f)
	}
	sort.Strings(names)
	for _, f := range names {
		if why := obfuscated(cur.Files[f]); why != "" {
			out = append(out, Finding{"obfuscated_code", f, fmt.Sprintf("%s (%s): %s", f, check[f], why)})
		}
	}
	return out
}

func isJS(f string) bool {
	return strings.HasSuffix(f, ".js") || strings.HasSuffix(f, ".cjs") || strings.HasSuffix(f, ".mjs")
}

// installTargets are the files preinstall/install/postinstall execute.
func installTargets(p *Package) []string {
	seen := map[string]bool{}
	var out []string
	for _, k := range []string{"preinstall", "install", "postinstall"} {
		s := p.Scripts[k]
		for _, re := range []*regexp.Regexp{reNodeFile, reShellFile} {
			for _, m := range re.FindAllStringSubmatch(s, -1) {
				f := path.Clean(strings.TrimPrefix(m[1], "./"))
				if _, ok := p.Files[f]; ok && !seen[f] {
					seen[f] = true
					out = append(out, f)
				}
			}
		}
	}
	return out
}

// obfuscated returns why a file looks machine-obfuscated, or "".
func obfuscated(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	s := string(b)
	var why []string
	if n := len(reHexIdent.FindAllStringIndex(s, 200)); n >= 30 {
		why = append(why, fmt.Sprintf("%d _0x-style identifiers", n))
	}
	if reRotate.MatchString(s) && strings.Contains(s, "parseInt(") {
		why = append(why, "javascript-obfuscator string array rotation")
	}
	if n := len(reHexEscape.FindAllStringIndex(s, 2000)); n >= 400 && float64(n*4) > 0.2*float64(len(s)) {
		why = append(why, fmt.Sprintf("%d \\x escapes", n))
	}
	if a, z := longestBase64Run(s); z-a >= 2000 && entropy(s[a:z]) > 5.5 {
		why = append(why, fmt.Sprintf("a %d-byte base64 blob", z-a))
	}
	longest := 0
	for _, line := range strings.Split(s, "\n") {
		if len(line) > longest {
			longest = len(line)
		}
	}
	if longest > 20000 && entropy(s) > 5.2 && len(why) > 0 {
		why = append(why, fmt.Sprintf("%d-character line", longest))
	}
	return strings.Join(why, ", ")
}

// longestBase64Run returns the bounds of the longest run of base64
// characters. (Go's regexp caps repeat counts at 1000, so {2000,} is out.)
func longestBase64Run(s string) (int, int) {
	bestA, bestZ, start := 0, 0, -1
	for i := 0; i <= len(s); i++ {
		in := i < len(s) && (s[i] >= 'A' && s[i] <= 'Z' || s[i] >= 'a' && s[i] <= 'z' || s[i] >= '0' && s[i] <= '9' || s[i] == '+' || s[i] == '/' || s[i] == '=')
		switch {
		case in && start < 0:
			start = i
		case !in && start >= 0:
			if i-start > bestZ-bestA {
				bestA, bestZ = start, i
			}
			start = -1
		}
	}
	return bestA, bestZ
}

// entropy is Shannon entropy in bits per byte.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	h := 0.0
	n := float64(len(s))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

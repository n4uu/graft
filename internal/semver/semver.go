// Package semver is the subset of semantic versioning graft needs: parse,
// compare, and decide whether two versions sit on the same release line.
package semver

import (
	"strconv"
	"strings"
)

// Version is a parsed semver 2.0 version. Build metadata is dropped, as it
// has no precedence.
type Version struct {
	Major, Minor, Patch int
	Pre                 []string
	Raw                 string
	ok                  bool
}

// Parse accepts "1.2.3", "v1.2.3", "1.2.3-beta.1+build". Anything else
// returns a Version with Valid() false, which sorts before valid ones.
func Parse(s string) Version {
	v := Version{Raw: s}
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	core, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return v
	}
	nums := [3]int{}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || (len(p) > 1 && p[0] == '0') {
			return v
		}
		nums[i] = n
	}
	v.Major, v.Minor, v.Patch = nums[0], nums[1], nums[2]
	if hasPre {
		if pre == "" {
			return v
		}
		v.Pre = strings.Split(pre, ".")
	}
	v.ok = true
	return v
}

// Valid reports whether the string parsed as semver.
func (v Version) Valid() bool { return v.ok }

// Prerelease reports whether the version has a pre-release tag.
func (v Version) Prerelease() bool { return len(v.Pre) > 0 }

// Compare returns -1, 0 or 1 following semver precedence rules.
func Compare(a, b Version) int {
	if a.ok != b.ok {
		if a.ok {
			return 1
		}
		return -1
	}
	if !a.ok {
		return strings.Compare(a.Raw, b.Raw)
	}
	for _, d := range [][2]int{{a.Major, b.Major}, {a.Minor, b.Minor}, {a.Patch, b.Patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a.Pre) == 0 && len(b.Pre) == 0:
		return 0
	case len(a.Pre) == 0:
		return 1
	case len(b.Pre) == 0:
		return -1
	}
	for i := 0; i < len(a.Pre) && i < len(b.Pre); i++ {
		x, y := a.Pre[i], b.Pre[i]
		xn, xerr := strconv.Atoi(x)
		yn, yerr := strconv.Atoi(y)
		switch {
		case xerr == nil && yerr == nil:
			if xn != yn {
				if xn < yn {
					return -1
				}
				return 1
			}
		case xerr == nil:
			return -1 // numeric identifiers sort before alphanumeric
		case yerr == nil:
			return 1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	switch {
	case len(a.Pre) < len(b.Pre):
		return -1
	case len(a.Pre) > len(b.Pre):
		return 1
	}
	return 0
}

// Line is the release line a version belongs to: the major version, or
// major.minor below 1.0 where minors are breaking. 1.14.1 and 1.13.6 share
// a line; 1.14.1 and 0.30.4 don't.
func (v Version) Line() string {
	if !v.ok {
		return "?"
	}
	if v.Major == 0 {
		return "0." + strconv.Itoa(v.Minor)
	}
	return strconv.Itoa(v.Major)
}

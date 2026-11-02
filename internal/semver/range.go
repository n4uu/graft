package semver

import (
	"strconv"
	"strings"
)

// Satisfies reports whether v matches an npm range. Supported: exact
// versions, comparators (>=, <=, >, <, =), caret, tilde, x-ranges and
// partial versions, hyphen ranges, whitespace-joined intersections and
// || unions. ok is false for things that aren't ranges at all (git URLs,
// file: paths, dist-tags other than latest), so callers can fall back.
func Satisfies(v Version, rng string) (match, ok bool) {
	rng = strings.TrimSpace(rng)
	if !v.Valid() {
		return false, false
	}
	for _, alt := range strings.Split(rng, "||") {
		cs, ok := comparators(strings.TrimSpace(alt))
		if !ok {
			return false, false
		}
		if v.Prerelease() && !allowsPre(cs, v) {
			continue
		}
		all := true
		for _, c := range cs {
			if !c.test(v) {
				all = false
				break
			}
		}
		if all {
			return true, true
		}
	}
	return false, true
}

type comparator struct {
	op string
	v  Version
}

func (c comparator) test(v Version) bool {
	d := Compare(v, c.v)
	switch c.op {
	case ">=":
		return d >= 0
	case ">":
		return d > 0
	case "<=":
		return d <= 0
	case "<":
		return d < 0
	}
	return d == 0
}

// allowsPre: npm only lets a prerelease satisfy a range if some comparator
// names a prerelease on the same major.minor.patch.
func allowsPre(cs []comparator, v Version) bool {
	for _, c := range cs {
		if c.v.Prerelease() && c.v.Major == v.Major && c.v.Minor == v.Minor && c.v.Patch == v.Patch {
			return true
		}
	}
	return false
}

func comparators(s string) ([]comparator, bool) {
	if s == "" || s == "*" || s == "x" || s == "X" || s == "latest" {
		return []comparator{{">=", Parse("0.0.0")}}, true
	}
	if a, b, found := strings.Cut(s, " - "); found {
		lo, _, ok1 := partial(strings.TrimSpace(a))
		hi, n, ok2 := partial(strings.TrimSpace(b))
		if !ok1 || !ok2 {
			return nil, false
		}
		if n == 3 {
			return []comparator{{">=", lo}, {"<=", hi}}, true
		}
		return []comparator{{">=", lo}, {"<", bump(hi, n)}}, true
	}
	var out []comparator
	for _, tok := range strings.Fields(s) {
		cs, ok := one(tok)
		if !ok {
			return nil, false
		}
		out = append(out, cs...)
	}
	return out, len(out) > 0
}

func one(tok string) ([]comparator, bool) {
	op := ""
	for _, p := range []string{">=", "<=", ">", "<", "=", "^", "~", "v"} {
		if strings.HasPrefix(tok, p) {
			op, tok = p, strings.TrimPrefix(tok, p)
			break
		}
	}
	if op == "v" {
		op = ""
	}
	tok = strings.TrimPrefix(tok, "v")
	base, n, ok := partial(tok)
	if !ok {
		return nil, false
	}
	switch op {
	case "^":
		hi := Version{ok: true}
		switch {
		case base.Major > 0 || n == 1:
			hi.Major = base.Major + 1
		case base.Minor > 0 || n == 2:
			hi.Minor = base.Minor + 1
		default:
			hi.Patch = base.Patch + 1
		}
		return []comparator{{">=", base}, {"<", hi}}, true
	case "~":
		if n == 1 {
			return []comparator{{">=", base}, {"<", bump(base, 1)}}, true
		}
		return []comparator{{">=", base}, {"<", bump(base, 2)}}, true
	case ">", "<=":
		if n < 3 { // >1.2 means >=1.3.0; <=1.2 means <1.3.0
			if op == ">" {
				return []comparator{{">=", bump(base, n)}}, true
			}
			return []comparator{{"<", bump(base, n)}}, true
		}
		return []comparator{{op, base}}, true
	case ">=", "<":
		return []comparator{{op, base}}, true
	}
	// bare or "=": partial versions are x-ranges
	if n == 3 {
		return []comparator{{"=", base}}, true
	}
	if n == 0 {
		return []comparator{{">=", Parse("0.0.0")}}, true
	}
	return []comparator{{">=", base}, {"<", bump(base, n)}}, true
}

// partial parses "1", "1.2", "1.2.x", "1.2.3-beta", returning how many
// numeric parts were given.
func partial(s string) (Version, int, bool) {
	core, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) > 3 || core == "" {
		return Version{}, 0, false
	}
	v := Version{ok: true}
	n := 0
	for i, p := range parts {
		if p == "x" || p == "X" || p == "*" {
			break
		}
		x, err := strconv.Atoi(p)
		if err != nil || x < 0 {
			return Version{}, 0, false
		}
		switch i {
		case 0:
			v.Major = x
		case 1:
			v.Minor = x
		case 2:
			v.Patch = x
		}
		n++
	}
	if hasPre && n == 3 {
		v.Pre = strings.Split(pre, ".")
	}
	return v, n, true
}

// bump increments the last given part: bump(1.2, 2) = 1.3.0.
func bump(v Version, n int) Version {
	out := Version{ok: true}
	switch n {
	case 1:
		out.Major = v.Major + 1
	case 2:
		out.Major, out.Minor = v.Major, v.Minor+1
	default:
		out.Major, out.Minor, out.Patch = v.Major, v.Minor, v.Patch+1
	}
	return out
}

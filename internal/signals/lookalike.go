package signals

import (
	"strings"
)

// decorations are the words typosquatters glue onto a real name:
// plain-crypto-js, easy-day-js, node-axios, lodash-utils. Matching them
// explicitly keeps the rule narrow; "react-dom" or "lodash.merge" add a
// word that isn't on the list and don't match.
var decorations = []string{
	"plain", "easy", "simple", "fast", "faster", "node", "nodejs", "js", "lite", "light",
	"pro", "safe", "secure", "real", "true", "official", "core", "utils", "util", "lib",
	"plus", "next", "new", "v2", "extra", "better", "super", "mini", "tiny", "dev", "pkg",
}

// normalise drops separators so dayjs, day-js and day.js compare equal.
// The scope stays part of the name: @emnapi/core is not @babel/core.
func normalise(s string) string {
	s = strings.ToLower(s)
	return strings.NewReplacer("-", "", "_", "", ".", "", "@", "", "/", "").Replace(s)
}

func stripJS(s string) string {
	if len(s) > 4 && strings.HasSuffix(s, "js") {
		return s[:len(s)-2]
	}
	return s
}

// Lookalike returns the popular package name resembles, and how. Rules run
// strongest first across the whole list, so "cryptojs" lands on crypto-js
// (same name, separators dropped) rather than on bcryptjs (one edit).
func Lookalike(name string, popular []string, isPopular func(string) bool) (target, how string, ok bool) {
	if isPopular(name) || strings.HasPrefix(name, "@types/") {
		return "", "", false
	}
	// @zkochan/js-yaml: a copy published openly under the author's own
	// scope. That's how forks are supposed to be named.
	if strings.HasPrefix(name, "@") {
		if _, bare, ok := strings.Cut(name, "/"); ok && isPopular(bare) {
			return "", "", false
		}
	}
	n := normalise(name)
	rules := []func(pn string) (string, bool){
		func(pn string) (string, bool) {
			return "same name with different separators", n == pn || stripJS(n) == stripJS(pn)
		},
		func(pn string) (string, bool) {
			return "one edit away", len(pn) >= 5 && damerau(n, pn) == 1
		},
		func(pn string) (string, bool) {
			if len(pn) < 5 {
				return "", false // "jest" + "util" is jest-util, not a squat
			}
			for _, d := range decorations {
				if n == d+pn || n == pn+d || stripJS(n) == d+stripJS(pn) || n == d+stripJS(pn)+"js" {
					return "\"" + d + "\" added to the name", true
				}
			}
			return "", false
		},
		func(pn string) (string, bool) {
			return "two edits away", len(pn) >= 8 && damerau(n, pn) == 2
		},
	}
	for _, rule := range rules {
		for _, p := range popular {
			pn := normalise(p)
			if len(pn) < 4 {
				continue
			}
			if why, hit := rule(pn); hit {
				return p, why, true
			}
		}
	}
	return "", "", false
}

// damerau is the optimal string alignment distance (Levenshtein plus
// adjacent transpositions, which is how "axois" happens).
func damerau(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	if abs(len(ra)-len(rb)) > 2 {
		return 3
	}
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

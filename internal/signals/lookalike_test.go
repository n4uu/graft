package signals

import (
	"testing"

	"github.com/n4uu/graft/internal/policy"
)

func TestLookalike(t *testing.T) {
	p := policy.Default()
	hit := map[string]string{
		"plain-crypto-js": "crypto-js",
		"easy-day-js":     "dayjs",
		"axois":           "axios",
		"expresss":        "express",
		"day-js":          "dayjs",
		"node-axios":      "axios",
		"lodash-utils":    "lodash",
		"cryptojs":        "crypto-js",
		"ethers-official": "ethers",
	}
	for name, want := range hit {
		got, _, ok := Lookalike(name, p.Popular, p.IsPopular)
		if !ok || got != want {
			t.Errorf("Lookalike(%q) = %q %v, want %q", name, got, ok, want)
		}
	}
	for _, name := range []string{
		"react-dom", "lodash.merge", "chalk-template", "jest-util", "dayjs", "colors",
		"@types/lodash", "mime-db", "date-fns-tz", "express-session", "ws", "uuid",
	} {
		if got, how, ok := Lookalike(name, p.Popular, p.IsPopular); ok {
			t.Errorf("Lookalike(%q) = %q (%s), want no match", name, got, how)
		}
	}
}

func TestDamerau(t *testing.T) {
	for _, c := range []struct {
		a, b string
		d    int
	}{{"axios", "axois", 1}, {"axios", "axio", 1}, {"express", "expresss", 1}, {"lodash", "lodahs", 1}, {"abc", "abc", 0}, {"crypto", "cyrpot", 2}} {
		if got := damerau(c.a, c.b); got != c.d {
			t.Errorf("damerau(%s,%s) = %d, want %d", c.a, c.b, got, c.d)
		}
	}
}

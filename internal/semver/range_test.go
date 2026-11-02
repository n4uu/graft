package semver

import "testing"

func TestSatisfies(t *testing.T) {
	cases := []struct {
		v, r string
		want bool
	}{
		{"4.2.1", "^4.2.1", true}, {"4.3.0", "^4.2.1", true}, {"5.0.0", "^4.2.1", false}, {"4.2.0", "^4.2.1", false},
		{"0.2.5", "^0.2.3", true}, {"0.3.0", "^0.2.3", false}, {"0.0.3", "^0.0.3", true}, {"0.0.4", "^0.0.3", false},
		{"1.2.9", "~1.2.3", true}, {"1.3.0", "~1.2.3", false}, {"1.9.0", "~1", true},
		{"1.6.0", "1.x", true}, {"2.0.0", "1.x", false}, {"1.2.7", "1.2", true}, {"1.3.0", "1.2", false},
		{"1.5.0", ">=1.2.0 <2.0.0", true}, {"2.0.0", ">=1.2.0 <2.0.0", false},
		{"2.5.0", "1.2.3 - 2.3", false}, {"2.3.9", "1.2.3 - 2.3", true},
		{"3.0.0", "^1.0.0 || ^3.0.0", true}, {"2.0.0", "^1.0.0 || ^3.0.0", false},
		{"1.0.0-beta.2", "^1.0.0", false}, {"1.0.0-beta.2", "^1.0.0-beta.1", true},
		{"7.0.0", "*", true}, {"1.2.3", "1.2.3", true}, {"1.2.4", "=1.2.3", false},
		{"1.6.0", ">1.5", true}, {"1.5.9", ">1.5", false}, {"1.5.9", "<=1.5", true},
	}
	for _, c := range cases {
		got, ok := Satisfies(Parse(c.v), c.r)
		if !ok || got != c.want {
			t.Errorf("Satisfies(%s, %q) = %v ok=%v, want %v", c.v, c.r, got, ok, c.want)
		}
	}
	for _, r := range []string{"github:a/b", "file:../x", "next", "npm:foo@1"} {
		if _, ok := Satisfies(Parse("1.0.0"), r); ok {
			t.Errorf("%q treated as a range", r)
		}
	}
}

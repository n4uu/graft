package semver

import (
	"sort"
	"testing"
)

func TestOrdering(t *testing.T) {
	// From the semver 2.0 spec, section 11, plus a few npm-isms.
	want := []string{
		"not-a-version",
		"0.30.3", "0.30.4",
		"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
		"1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.13.6", "1.14.0", "v1.14.1", "1.14.1+build.9", "2.0.0",
	}
	got := append([]string(nil), want...)
	sort.Slice(got, func(i, j int) bool { return Compare(Parse(got[j]), Parse(got[i])) > 0 })
	for i := range want {
		if Compare(Parse(got[i]), Parse(want[i])) != 0 {
			t.Fatalf("order:\n got %v\nwant %v", got, want)
		}
	}
}

func TestParse(t *testing.T) {
	for _, bad := range []string{"", "1.2", "1.2.3.4", "01.2.3", "1.2.3-", "a.b.c", "1.0.0rc4"} {
		if Parse(bad).Valid() {
			t.Errorf("%q parsed as valid", bad)
		}
	}
	v := Parse("0.0.1-security.0")
	if !v.Valid() || !v.Prerelease() || v.Pre[0] != "security" {
		t.Errorf("%+v", v)
	}
}

func TestLine(t *testing.T) {
	cases := map[string]string{"1.14.1": "1", "1.13.6": "1", "0.30.4": "0.30", "0.29.0": "0.29", "5.6.1": "5"}
	for v, want := range cases {
		if got := Parse(v).Line(); got != want {
			t.Errorf("Line(%s) = %s, want %s", v, got, want)
		}
	}
}

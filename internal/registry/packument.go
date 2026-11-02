// Package registry reads npm registry documents ("packuments") and answers
// the questions graft asks about a package's history: who published each
// version and how, what it depended on, and which versions have since
// vanished.
package registry

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/n4uu/graft/internal/semver"
)

// Packument is the full registry document for one package, reduced to the
// fields graft reads.
type Packument struct {
	Name        string               `json:"name"`
	DistTags    map[string]string    `json:"dist-tags,omitempty"`
	Versions    map[string]*Manifest `json:"versions"`
	Time        map[string]string    `json:"time"`
	Description string               `json:"description,omitempty"`
	Homepage    string               `json:"homepage,omitempty"`
	Repository  Repository           `json:"repository,omitempty"`
	Maintainers []Person             `json:"maintainers,omitempty"`

	// Missing is set when the registry answered 404: the package doesn't
	// exist (never did, or was removed entirely).
	Missing bool `json:"-"`
}

// Manifest is one published version.
type Manifest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Description          string            `json:"description,omitempty"`
	Homepage             string            `json:"homepage,omitempty"`
	Repository           Repository        `json:"repository,omitempty"`
	Dependencies         map[string]string `json:"dependencies,omitempty"`
	OptionalDependencies map[string]string `json:"optionalDependencies,omitempty"`
	Scripts              map[string]string `json:"scripts,omitempty"`
	HasInstallScript     bool              `json:"hasInstallScript,omitempty"`
	GitHead              string            `json:"gitHead,omitempty"`
	Deprecated           string            `json:"deprecated,omitempty"`
	NpmUser              Publisher         `json:"_npmUser,omitempty"`
	Maintainers          []Person          `json:"maintainers,omitempty"`
	Dist                 Dist              `json:"dist"`
}

// Publisher is the account (or CI identity) that ran npm publish.
type Publisher struct {
	Name             string            `json:"name,omitempty"`
	Email            string            `json:"email,omitempty"`
	TrustedPublisher *TrustedPublisher `json:"trustedPublisher,omitempty"`
}

// TrustedPublisher is present when the version was published through npm
// trusted publishing (OIDC from a CI provider) instead of a token.
type TrustedPublisher struct {
	ID           string `json:"id"`
	OIDCConfigID string `json:"oidcConfigId,omitempty"`
}

// Person is a maintainer entry.
type Person struct {
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

// Dist describes the tarball.
type Dist struct {
	Tarball      string        `json:"tarball,omitempty"`
	Integrity    string        `json:"integrity,omitempty"`
	Shasum       string        `json:"shasum,omitempty"`
	FileCount    int           `json:"fileCount,omitempty"`
	UnpackedSize int64         `json:"unpackedSize,omitempty"`
	Attestations *Attestations `json:"attestations,omitempty"`
}

// Attestations is set for versions published with npm provenance (a
// sigstore-signed SLSA statement linking the tarball to a CI run).
type Attestations struct {
	URL        string `json:"url"`
	Provenance *struct {
		PredicateType string `json:"predicateType"`
	} `json:"provenance,omitempty"`
}

// Repository accepts both the string and the {type,url} object forms.
type Repository struct {
	Type string `json:"type,omitempty"`
	URL  string `json:"url,omitempty"`
}

func (r *Repository) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		r.URL = s
		return nil
	}
	type plain Repository
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return nil // malformed repository fields are common; ignore
	}
	*r = Repository(p)
	return nil
}

// Publisher fields are sometimes a bare string in very old documents.
func (p *Publisher) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		p.Name = s
		return nil
	}
	type plain Publisher
	var q plain
	if err := json.Unmarshal(b, &q); err != nil {
		return nil
	}
	*p = Publisher(q)
	return nil
}

// Person entries can also be strings ("Name <email>").
func (p *Person) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		name, email, _ := strings.Cut(s, "<")
		p.Name = strings.TrimSpace(name)
		p.Email = strings.TrimSuffix(strings.TrimSpace(email), ">")
		return nil
	}
	type plain Person
	var q plain
	if err := json.Unmarshal(b, &q); err != nil {
		return nil
	}
	*p = Person(q)
	return nil
}

// Deprecated is a string, or false in some documents.
func (m *Manifest) UnmarshalJSON(b []byte) error {
	type plain Manifest
	var raw struct {
		plain
		Deprecated json.RawMessage `json:"deprecated,omitempty"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*m = Manifest(raw.plain)
	var s string
	if json.Unmarshal(raw.Deprecated, &s) == nil {
		m.Deprecated = s
	}
	return nil
}

// RepoKey normalises a repository URL so that git+https://github.com/a/b.git,
// git://github.com/a/b and github:a/b compare equal.
func (r Repository) RepoKey() string {
	u := strings.ToLower(strings.TrimSpace(r.URL))
	for _, p := range []string{"git+", "https://", "http://", "git://", "ssh://", "git@", "www."} {
		u = strings.TrimPrefix(u, p)
	}
	u = strings.TrimPrefix(u, "github:")
	if !strings.Contains(u, "/") || strings.HasPrefix(u, "npm/security-holder") {
		return u
	}
	u = strings.Replace(u, "github.com:", "github.com/", 1)
	if !strings.Contains(u, ".") {
		u = "github.com/" + u
	}
	u = strings.TrimSuffix(strings.TrimSuffix(u, "/"), ".git")
	return u
}

// Published returns when a version was published, from the time map. It
// also works for versions that have since been unpublished.
func (p *Packument) Published(version string) (time.Time, bool) {
	s, ok := p.Time[version]
	if !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// Created is when the package name was first published.
func (p *Packument) Created() (time.Time, bool) { return p.Published("created") }

// Unpublished reports whether version was published once and is gone now.
// The registry drops the manifest but keeps the timestamp, which is how
// axios@1.14.1 can still be dated to the second months after removal.
func (p *Packument) Unpublished(version string) bool {
	if _, live := p.Versions[version]; live {
		return false
	}
	_, ok := p.Time[version]
	return ok && version != "created" && version != "modified" && version != "unpublished"
}

// SecurityHolding reports whether npm's security team has replaced the
// package with a placeholder, which it does after confirming malware.
func (p *Packument) SecurityHolding() bool {
	if p.Repository.RepoKey() == "npm/security-holder" {
		return true
	}
	if len(p.Versions) == 0 {
		return false
	}
	for v, m := range p.Versions {
		if !strings.Contains(v, "-security") {
			return false
		}
		if m.NpmUser.Name != "npm" && m.NpmUser.Name != "" {
			return false
		}
	}
	return true
}

// History returns live versions ordered by publish time.
func (p *Packument) History() []*Manifest {
	out := make([]*Manifest, 0, len(p.Versions))
	for _, m := range p.Versions {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		ti, _ := p.Published(out[i].Version)
		tj, _ := p.Published(out[j].Version)
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return semver.Compare(semver.Parse(out[i].Version), semver.Parse(out[j].Version)) < 0
	})
	return out
}

// Predecessor is the version a release should be compared against: the
// most recently published earlier version on the same release line; failing
// that (the first release of a new 0.x minor), the same major; failing
// that, any earlier version. Comparing against the previous *publish* on
// the line rather than the previous semver is what catches a compromised
// maintainer pushing 0.30.4 onto an old branch.
func (p *Packument) Predecessor(version string) *Manifest {
	at, ok := p.Published(version)
	if !ok {
		return nil
	}
	v := semver.Parse(version)
	var sameLine, sameMajor, anyLine *Manifest
	for _, m := range p.History() {
		t, _ := p.Published(m.Version)
		if !t.Before(at) || m.Version == version {
			continue
		}
		mv := semver.Parse(m.Version)
		if mv.Prerelease() && !v.Prerelease() {
			continue // nightlies and canaries publish on another pipeline
		}
		anyLine = m
		if mv.Valid() && v.Valid() && mv.Major == v.Major && semver.Compare(mv, v) < 0 {
			sameMajor = m
		}
		if mv.Line() == v.Line() {
			sameLine = m
		}
	}
	switch {
	case sameLine != nil:
		return sameLine
	case sameMajor != nil:
		return sameMajor
	}
	return anyLine
}

// PublishedBy reports whether account ever published a live version before t.
func (p *Packument) PublishedBy(account string, before time.Time) bool {
	for _, m := range p.Versions {
		if t, _ := p.Published(m.Version); t.Before(before) && strings.EqualFold(m.NpmUser.Name, account) {
			return true
		}
	}
	return false
}

// At returns a copy of the packument as the registry would have served it
// at time t: later versions removed, timestamps after t dropped. It can't
// resurrect versions that were unpublished since; those have no manifest.
func (p *Packument) At(t time.Time) *Packument {
	q := *p
	q.Versions = map[string]*Manifest{}
	q.Time = map[string]string{}
	for k, v := range p.Time {
		if ts, err := time.Parse(time.RFC3339Nano, v); err == nil && !ts.After(t) {
			q.Time[k] = v
		}
	}
	for k, m := range p.Versions {
		if _, ok := q.Time[k]; ok {
			q.Versions[k] = m
		}
	}
	return &q
}

// InstallScripts returns the lifecycle scripts npm runs on install.
func (m *Manifest) InstallScripts() map[string]string {
	out := map[string]string{}
	for _, k := range []string{"preinstall", "install", "postinstall"} {
		if s, ok := m.Scripts[k]; ok && s != "" {
			out[k] = s
		}
	}
	// hasInstallScript without an explicit script means a binding.gyp,
	// for which npm synthesises "node-gyp rebuild".
	if len(out) == 0 && m.HasInstallScript {
		out["install"] = "(implicit: node-gyp rebuild)"
	}
	return out
}

// AllDeps merges dependencies and optionalDependencies, which npm installs
// alike.
func (m *Manifest) AllDeps() map[string]string {
	out := map[string]string{}
	for k, v := range m.Dependencies {
		out[k] = v
	}
	for k, v := range m.OptionalDependencies {
		out[k] = v
	}
	return out
}

// Slim returns a copy holding only what evaluation reads, for the disk
// cache. Big packages (prisma, playwright, @typescript-eslint/*) carry
// thousands of versions with full script maps, contributor lists and
// descriptions; none of that is needed twice.
func (p *Packument) Slim() *Packument {
	q := &Packument{
		Name: p.Name, DistTags: p.DistTags, Time: p.Time, Description: p.Description,
		Homepage: p.Homepage, Repository: p.Repository,
		Versions: make(map[string]*Manifest, len(p.Versions)),
	}
	// Maintainer names are evidence (who publishes what); their email
	// addresses aren't, and don't belong in a cache on disk.
	for _, m := range p.Maintainers {
		q.Maintainers = append(q.Maintainers, Person{Name: m.Name})
	}
	for v, m := range p.Versions {
		s := &Manifest{
			Name: m.Name, Version: m.Version, Repository: m.Repository,
			Dependencies: m.Dependencies, OptionalDependencies: m.OptionalDependencies,
			HasInstallScript: m.HasInstallScript, GitHead: m.GitHead, Deprecated: m.Deprecated,
			NpmUser: Publisher{Name: m.NpmUser.Name, TrustedPublisher: m.NpmUser.TrustedPublisher},
			Dist:    Dist{Tarball: m.Dist.Tarball, Integrity: m.Dist.Integrity, Attestations: m.Dist.Attestations},
		}
		for _, k := range []string{"preinstall", "install", "postinstall"} {
			if x, ok := m.Scripts[k]; ok {
				if s.Scripts == nil {
					s.Scripts = map[string]string{}
				}
				s.Scripts[k] = x
			}
		}
		if s.Repository == p.Repository {
			s.Repository = Repository{} // same as the package's; don't repeat it
		}
		q.Versions[v] = s
	}
	return q
}

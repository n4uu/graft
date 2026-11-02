# graft

[![ci](https://github.com/n4uu/graft/actions/workflows/ci.yml/badge.svg)](https://github.com/n4uu/graft/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/n4uu/graft.svg)](https://pkg.go.dev/github.com/n4uu/graft)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Finds compromised releases in npm dependency trees.** The axios compromise
of March 2026 and the Mastra one in June followed the same recipe: steal a
maintainer's publish token, then publish a release of a package everyone
already trusts with one new dependency grafted on, whose install script
does the work. The package's own code isn't touched, so diffing source or
scanning for known-bad hashes on the day sees nothing.

What does change is the release's paper trail on the registry: who
published it and how, what it suddenly depends on, how old that dependency
is, which other release lines went out in the same hour. graft reads that
trail for every package in your lockfiles, scores what it finds, and tells
you why. It also does the after-the-fact part: which of your projects, which
`node_modules`, and which machines' npm caches ever had a bad version, and
when it arrived.

```
graft audit [path...]         package-lock (v1/v2/v3), npm-shrinkwrap, yarn (classic and berry), pnpm (v5/v6/v9)
graft sweep [path...]         audit + node_modules tampering + the npm cache (~/.npm/_cacache)
graft check name@version...   one-off checks before an upgrade
```

Output is text, JSON, or SARIF for GitHub code scanning. There's a GitHub
Action in this repo (`action.yml`) that does the last part for you.

## What the registry remembers

npm deletes the manifest of an unpublished version but keeps its timestamp
in the package's `time` record. When it confirms malware it swaps the
package for a `0.0.1-security` placeholder published by the `npm` account.
Both survive. Here is the axios incident reconstructed from nothing but the
registry documents graft reads, as they stand today
(`testdata/registry/` holds copies):

| UTC | Registry record |
| --- | --- |
| 2026-03-27 19:01:40 | `axios@1.14.0`, published by GitHub Actions through trusted publishing (OIDC), with a provenance attestation, `gitHead` recorded |
| 2026-03-30 05:57:32 | `plain-crypto-js@4.2.0`, the first version of a new package |
| 2026-03-30 23:59:12 | `plain-crypto-js@4.2.1` |
| 2026-03-31 00:21:58 | `axios@1.14.1` (manifest since removed) |
| 2026-03-31 01:00:57 | `axios@0.30.4` on the old 0.x line, 39 minutes later (manifest since removed) |
| 2026-03-31 03:25:11 | `plain-crypto-js@0.0.1-security`, published by `npm` |
| 2026-04-08 16:09:38 | `axios@1.15.0`, back to trusted publishing with provenance |

The Mastra compromise left a different trace. `easy-day-js` appeared on
2026-06-16 with dayjs's description and a `repository` field pointing at
github.com/iamkun/dayjs, the real dayjs repository. Its first version number,
1.11.21, was dayjs's current release that day. Version 1.11.22 followed at
01:01 UTC the next morning and is gone now; 1.11.21 is still live.

The September 2025 phishing of the maintainer `qix` shows a third shape:
the registry still lists the 19 malicious versions (ansi-styles 6.2.2,
debug 4.4.2, chalk 5.6.1, supports-color 10.2.1 and so on) published one
after another between 13:12:10 and 13:20:31 UTC, each a normal-looking patch
release of a different package.

Today, graft sees all three straight away:

```
$ graft check axios@1.14.1 plain-crypto-js@4.2.1 easy-day-js@1.11.21 chalk@5.6.1
  CRITICAL  25.0  axios@1.14.1
                 published 2026-03-31T00:21:58Z
         +20.0   known_malicious            axios maintainer account takeover (UNC1069 / Sapphire Sleet) (2026-03-31)
          +4.0   unpublished                published 2026-03-31T00:21:58Z and removed since; the registry kept only the timestamp
          +1.0   release_burst              other release lines published alongside: 0.30.4 (39m later), since removed
  CRITICAL  34.0  plain-crypto-js@4.2.1
                 published 2026-03-30T23:59:12Z
         +20.0   known_malicious            axios maintainer account takeover (UNC1069 / Sapphire Sleet) (2026-03-31)
         +10.0   security_holding           npm replaced the package with a security placeholder, which it does after confirming malware
          +2.0   unpublished                published 2026-03-30T23:59:12Z and removed since; the registry kept only the timestamp
          +2.0   lookalike_name             name resembles crypto-js ("plain" added to the name)
  CRITICAL  26.0  easy-day-js@1.11.21
                 published 2026-06-16T07:05:42Z by sergey2016
         +20.0   known_malicious            Mastra ecosystem compromise, easy-day-js dependency (UNC1069 / Sapphire Sleet) (2026-06-17)
          +6.0   impersonation              claims dayjs's description and repository (github.com/iamkun/dayjs), but no account that published dayjs has ever published this package
  CRITICAL  24.0  chalk@5.6.1
                 published 2025-09-08T13:13:05Z
         +20.0   known_malicious            qix maintainer phishing (crypto clipper in 18+ packages) (2025-09-08)
          +4.0   unpublished                published 2025-09-08T13:13:05Z and removed since; the registry kept only the timestamp
4 critical, 0 high, 0 medium, 0 low
```

The known-malicious feed (`internal/policy/data/known.yaml`) makes that
easy, but it isn't what's doing the work. With the feed removed, the tests
still put `axios@1.14.1` at high (removed version) and `plain-crypto-js` at
critical (security placeholder), and `easy-day-js@1.11.21`, the live decoy,
at medium on impersonation alone. Every feed entry was checked against the
registry before it went in: the version has to be in `time` and gone from
`versions`, or the package has to be a security placeholder.

## Would it have caught it on the night?

That's the question that matters for a tool like this, and the registry can
almost answer it. `-at` evaluates against the registry as it stood at a
given time: later versions and timestamps disappear. What it can't do is
bring back the manifests npm deleted, so `TestAxiosAtTheTime` rebuilds them
from public reporting: 1.14.1 and 0.30.4 added `plain-crypto-js` (the
reconstruction changes nothing else in the manifest), they came from an existing maintainer
account using a stolen long-lived token (so no trusted publishing, no
provenance), and `plain-crypto-js@4.2.1` ran `node setup.js` on postinstall.
Every timestamp is the registry's own. No feed. Evaluated at 01:05 UTC on
2026-03-31, after both releases and two hours before npm stepped in:

```
axios@1.14.1 at 01:05Z: critical 16.50
  +5.00 trusted_publisher_dropped: 1.14.0 was published by GitHub Actions through trusted publishing (OIDC); this version by the account "maintainer"
  +4.00 young_dependency: plain-crypto-js first appeared on the registry 18h before this release, published by "attacker-account", not by this package's publisher
  +2.00 provenance_dropped: 1.14.0 carried a provenance attestation; this version has none
  +2.00 dependency_install_script: plain-crypto-js@4.2.1, which ^4.2.1 resolved to when published, runs postinstall "node setup.js" on install
  +2.00 lookalike_name: added dependency plain-crypto-js resembles crypto-js ("plain" added to the name)
  +1.00 release_burst: other release lines published alongside: 0.30.4 (39m later)
  +0.25 githead_missing: 1.14.0 recorded the git commit it was built from; this version doesn't
  +0.25 dependency_added: plain-crypto-js@^4.2.1 is new since 1.14.0

axios@0.30.4: high 10.25
  +4.00 young_dependency: plain-crypto-js first appeared on the registry 19h before this release, ...
  +2.00 dependency_install_script: plain-crypto-js@4.2.1, which ^4.2.1 resolved to when published, runs postinstall "node setup.js" on install
  +2.00 lookalike_name: added dependency plain-crypto-js resembles crypto-js ("plain" added to the name)
  +1.00 githead_missing: 0.30.3 recorded the git commit it was built from; this version doesn't
  +1.00 release_burst: other release lines published alongside: 1.14.1 (39m earlier)
  +0.25 dependency_added: plain-crypto-js@^4.2.1 is new since 0.30.3
```

The difference between the two is worth a look. The 1.x line had moved to
trusted publishing, so a release from a personal token stands out on its
own. The 0.x line had always been published by hand, so there was nothing
to lose and the grafted dependency has to carry it. graft compares each
release with the previous publish *on the same release line* for exactly
this reason; comparing 0.30.4 with 1.14.0 would have flagged the publishing
change on the wrong evidence.

`TestPublisherBurst` does the same for the qix phishing, where no single
package looks different from its previous release: the burst across
unrelated projects is the only metadata signal, and `-deep` (below) is what
reads the code.

## Signals

Each signal adds points; signals in the same group are damped (the
strongest counts in full, the next at half, and so on) because they tend to
fire together for one underlying reason. 12 or more is critical, 7 high, 4
medium. `graft policy` prints the full policy with its calibration notes;
any part can be overridden with `-policy file.yaml`.

| Signal | Points | Fires when |
| --- | --- | --- |
| `known_malicious` | 20 | the version is in the feed |
| `security_holding` | 20 | npm has replaced the package with a security placeholder |
| `dependency_malicious` | 14 | the version adds a dependency that is in the feed or now a placeholder |
| `installed_mismatch` | 10 | `node_modules/<pkg>/package.json` disagrees with the lockfile (sweep) |
| `unpublished` | 8 | the version was published and later removed |
| `never_published` | 8 | the registry has no record of the version at all |
| `deprecated_security` | 8 | deprecated with a malware/compromise message |
| `trusted_publisher_dropped` | 5 | previous release came from CI via OIDC, this one from an account token |
| `install_script_added` | 5 | new preinstall/install/postinstall |
| `publisher_burst` | 5 | one account released packages of three or more unrelated projects in your tree within 30 minutes |
| `impersonation` | 6 | a lookalike name whose `repository` claims the original project, with no publisher in common |
| `provenance_dropped` | 4 | previous release had a provenance attestation, this one doesn't |
| `young_dependency` | 4 | an added dependency first appeared under 30 days before the release (half weight past 7 days) and isn't from the same publishers or repository |
| `dependency_install_script` | 4 | an added dependency, at the version its range resolved to at publish time, runs an install script |
| `package_missing` | 4 | the package doesn't exist on the registry |
| `publisher_new` | 2 | first release ever by this account |
| `lookalike_name` | 2 | name resembles a widely used package (and the package is under a year old or has few releases) |
| `githead_missing` | 1 | previous release recorded its git commit, this one doesn't |
| `dependency_added` | 1 | a new dependency |
| `release_burst` | 1 | another release line of the package went out within two hours |
| `obfuscated_code`, `install_script_behaviour`, `self_tampering` | 6, 5, 6 | `-deep` tarball findings, below |

## Calibration on real trees

A detector that cries wolf on a normal lockfile gets switched off, so the
weights were tuned against two real dependency trees, live against
registry.npmjs.org, until neither produced a single medium:

| Lockfile | Packages checked | critical | high | medium | low | Time (cold / cached) |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| An Astro site (npm, lockfile v3) | 384 | 0 | 0 | 0 | 24 | 5 s / 1.5 s |
| Apache Superset frontend (npm, lockfile v3) | 3,146 | 0 | 0 | 0 | 326 | 29 s / 18 s |

Getting there meant fixing real false positives, each of which says
something about how npm behaves:

- **Coordinated releases.** The first version of `publisher_burst` counted
  repositories. It fired on sindresorhus shipping chalk, ansi-styles,
  ansi-regex and wrap-ansi within 23 minutes on 2025-09-08, which were the
  *clean* releases that superseded the qix ones, and on wooorm releasing
  several `unist-util-*` packages together. All of those live under one
  GitHub organisation each. The qix burst spanned chalk/, debug-js/ and
  Qix-/. The signal now counts distinct owners.
- **Projects splitting themselves up.** `sharp@0.34.5` added
  `@img/sharp-linux-riscv64`, a day old; several `mdast-util-*` releases
  added wooorm's own `devlop`. Young, but from the same people or the same
  repository. `young_dependency` skips those, and halves its weight past a
  week: plain-crypto-js was 18 hours old.
- **Forks.** `source-map-js` copies source-map's description;
  `@zkochan/js-yaml` even keeps js-yaml's repository field. A fork under the
  author's own scope is how forks are supposed to be named and isn't
  flagged; a copied description alone is a low-level note. Impersonation
  requires the `repository` field to claim the original, which is what
  easy-day-js did and source-map-js didn't.
- **Scoped names.** Comparing scoped packages by their bare name made
  `@emnapi/core` look like `@babel/core`. The scope is part of the name now.
- **Established lookalikes.** `preact` is one edit from `react` and has been
  for a decade. Lookalike names only count for packages under a year old or
  with fewer than a dozen releases.
- **Maintenance deprecations.** glob's deprecation message mentions
  "security vulnerabilities"; inflight's says "Do not use it". Neither is
  what `deprecated_security` is for, so it only matches malware and
  compromise wording.
- **Ranges.** `send@0.19.0` adds `mime`, and `mime@1.3.2` has an install
  script, but `^1.6.0` would never install it. graft now resolves each
  added dependency's range to the version it would have picked at publish
  time.
- **0.x minors.** Under 1.0 every minor is its own line, so the first
  `send@0.19.x` had no same-line predecessor and got compared with 1.0.0.
  The fallback is now the same major first.

What's left at low (on Superset: 161 `dependency_added`, 144
`release_burst`, 93 `publisher_new`, 35 `githead_missing`, 5
`lookalike_name`, 1 `young_dependency`) is what those signals look like in
ordinary use, and is why each is worth a point or two: they're corroboration,
not verdicts. `-min low` shows them.

## Incident response

```
$ graft sweep -npm-cache testdata/npm-cache/_cacache testdata/sweep
testdata/sweep/project/package-lock.json  (npm, 2 packages, 2 checked against the registry)
  CRITICAL  35.5  plain-crypto-js@4.2.1  (transitive  line 22)
         +20.0   known_malicious            axios maintainer account takeover (UNC1069 / Sapphire Sleet) (2026-03-31)
         +10.0   security_holding           npm replaced the package with a security placeholder, which it does after confirming malware
          +2.5   installed_mismatch         the lockfile installed 4.2.1 but node_modules/plain-crypto-js/package.json now says 4.2.0: something rewrote the package's manifest after install
          ...

npm cache testdata/npm-cache/_cacache  (4 tarballs)
  CRITICAL  25.0  axios@1.14.1  (downloaded 2026-03-31 00:48:12 UTC)
  CRITICAL  34.0  plain-crypto-js@4.2.1  (downloaded 2026-03-31 00:48:13 UTC)
  ...
```

(The sweep fixtures are synthetic; see `testdata/README.md`.)

Two things here are hard to get any other way:

- **The installed copy lies.** Reporting on the axios dropper noted that
  after it ran, `npm list` showed plain-crypto-js 4.2.0 rather than the
  4.2.1 that executed: the package's own `package.json` had been replaced.
  `sweep` compares every installed `package.json` under `node_modules` with
  the lockfile, so that trick becomes a finding of its own.
- **The cache remembers.** npm's cache index (`~/.npm/_cacache/index-v5`)
  is append-only and keeps a millisecond timestamp per fetched tarball.
  After the lockfile is fixed and `node_modules` rebuilt, the cache still
  says whether a machine ever pulled `axios-1.14.1.tgz`, and exactly when,
  which is the start of the timeline an investigation needs.

## Deep inspection

`-deep` downloads the tarballs of versions that already look suspicious, or
that run install scripts, plus their predecessor's, and reads them in
memory (nothing is extracted or executed). For every publisher burst, all
members get this treatment, since a phished maintainer's releases are only
different in their code. It looks at:

- what the install scripts actually run (`node setup.js`, `sh x.sh`), and
  whether that code starts processes, makes requests, reads `.npmrc` or CI
  tokens, branches on the OS, or pipes a download into a shell;
- whether it deletes itself or rewrites the package's `package.json`;
- whether install-time code, new files, or files that more than tripled in
  size are machine-obfuscated (javascript-obfuscator's rotated string
  array, `_0x` identifier density, escape density, long high-entropy blobs).

## In CI

```yaml
# .github/workflows/graft.yml
permissions:
  contents: read
  security-events: write
jobs:
  graft:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: n4uu/graft@main
        with:
          fail-on: high
```

Findings show up as code scanning alerts on the exact lockfile line.
`examples/workflow.yml` adds a daily schedule, which matters: a version that
was fine yesterday can be pulled today, and `unpublished` only fires once it
has been.

Exit status is 0 when clean, 1 when something reaches `-fail-on` (high by
default), 2 on errors. Registry documents are cached under the user cache
directory (slimmed and gzipped: 39 MB for the whole Superset tree) for six
hours; `-offline` uses only the cache, `-registry` and `NPM_TOKEN` point it
at a private registry.

## Install

Prebuilt binaries for Linux, macOS and Windows (amd64 and arm64) are on the
[releases page](https://github.com/n4uu/graft/releases/latest). They're built
by GitHub Actions from the tagged commit, never on a workstation, and every
archive carries a signed build provenance attestation (the same kind of
evidence graft looks for on npm releases):

```sh
gh attestation verify graft_*_linux_amd64.tar.gz -R n4uu/graft
```

To build from source instead:

```sh
git clone https://github.com/n4uu/graft
cd graft
make build         # Go 1.24+
make test
```

## Testing

- `testdata/registry/` holds real registry documents (reduced) for axios,
  plain-crypto-js, easy-day-js, chalk, debug and five ordinary packages.
  The incident tests run against them, and so does a negative test that
  checks ordinary releases of axios, express, lodash, dayjs, crypto-js,
  chalk, debug and ms stay at low or below.
- `TestAxiosAtTheTime` and `TestPublisherBurst` are the reconstructions
  described above.
- Every lockfile format has a parser test, including aliases, git
  dependencies, workspace entries and pnpm peer suffixes in three key styles.
- The SARIF output is validated against the OASIS SARIF 2.1.0 schema in
  CI, and a live job checks that the incident versions fail and current
  releases pass against registry.npmjs.org.

## Limitations

- **Metadata can't see everything.** A compromise that only edits code,
  from the usual publisher, through the usual channel, with no new
  dependency, is invisible to every metadata signal. That was the qix case:
  `publisher_burst` is the one hint, and `-deep` the confirmation. On a
  single package with no burst, only `-deep` has a chance.
- **The signals get better as npm does.** `trusted_publisher_dropped` and
  `provenance_dropped` only exist for projects that adopted trusted
  publishing or provenance. For a project published by hand from a laptop,
  a stolen token looks like any other release.
- **Removed versions lose their manifests.** After npm deletes a version,
  only its timestamp is left, so graft can say it existed and was removed,
  not what it contained. Run graft before installing, not only after.
- **Private registries.** Packages graft can't find get `package_missing`
  (4 points). Point `-registry` at your registry, or list internal packages
  under `allow.packages` in a policy file.
- **The lookalike list is curated** (`internal/policy/data/popular.txt`,
  about 180 names). It catches typosquats of those; it won't catch a squat
  of something it doesn't list.
- **Lockfiles only.** `bun.lock` and projects without a lockfile aren't
  read; `graft check` works for anything with a name and a version.

## References

- Tenable, [FAQ about the axios npm supply chain attack by UNC1069](https://www.tenable.com/blog/faq-about-the-axios-npm-supply-chain-attack-by-north-korea-nexus-threat-actor-unc1069)
- Microsoft, [Mitigating the axios npm supply chain compromise](https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/)
- SecurityWeek, [North Korean hackers blamed for Mastra npm supply chain attack](https://www.securityweek.com/north-korean-hackers-blamed-for-mastra-npm-supply-chain-attack/)
- The Register, [the qix phishing (2025-09-08)](https://www.theregister.com/2025/09/08/dev_falls_for_phishing_email) and Check Point, [The great npm heist](https://blog.checkpoint.com/crypto/the-great-npm-heist-september-2025/)
- GitLab advisory [MAL-2025-47141](https://advisories.gitlab.com/pkg/npm/@ctrl/tinycolor/MAL-2025-47141/) (Shai-Hulud, @ctrl/tinycolor)
- npm docs: [trusted publishing](https://docs.npmjs.com/trusted-publishers), [provenance](https://docs.npmjs.com/generating-provenance-statements), [unpublish policy](https://docs.npmjs.com/policies/unpublish)
- [OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

See also [crumble](https://github.com/n4uu/crumble) and
[prowl](https://github.com/n4uu/prowl), which cover the malware and the
infrastructure side of the same North Korean operations against developers.

## License

MIT, see [LICENSE](LICENSE).

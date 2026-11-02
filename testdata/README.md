# testdata

`registry/` holds real npm registry documents, fetched from
registry.npmjs.org on 2026-11-02 and reduced to the fields graft reads
(README text and the like dropped). They are what the case-study tests run
against: the axios / plain-crypto-js compromise of 2026-03-31, the
easy-day-js package from the Mastra compromise of 2026-06-17, chalk and
debug from the 2025-09-08 maintainer phishing, and a handful of ordinary
packages (express, lodash, dayjs, crypto-js, ms) as negatives.

`lockfiles/` are synthetic. They describe the dependency trees affected
projects would have locked, in every lockfile format graft reads. Integrity
hashes are fake (sha512 of a fixture string), the git commit is made up, and
no tarball referenced here is downloaded by the tests.

`npm-cache/` is a synthetic `~/.npm/_cacache` index in the on-disk format
npm (cacache v5) writes.

`sweep/` is a synthetic project whose installed `plain-crypto-js` claims
version 4.2.0 while its lockfile says 4.2.1, the state reporting describes
on hosts where the axios dropper ran.

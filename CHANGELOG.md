# Changelog

## [0.1.8](https://github.com/periphery-security/edgewalker/compare/edgewalker-v0.1.7...edgewalker-v0.1.8) (2026-06-16)


### New Features

* **cli:** `history --list` and a `compare` command for reports ([e582cfe](https://github.com/periphery-security/edgewalker/commit/e582cfea4e81e58b4a06143828f8d66f22ec4113))
* **cli:** add `history` command for changes and score trend (Phase 3, step 7) ([be9b741](https://github.com/periphery-security/edgewalker/commit/be9b7413f6eb942c62d52ed73fafa3d5806bbf9d))
* **core:** add SQL and web change signals to the diff engine ([af16d03](https://github.com/periphery-security/edgewalker/commit/af16d03e907c1e01e97c0deb53a9eb360ae14d57))
* **core:** compute and persist change events in the SQLite store (Phase 3, step 3) ([6f4df72](https://github.com/periphery-security/edgewalker/commit/6f4df72b1db77f462fab8e7026925101964cb9e3))
* **core:** emit device_appeared on the first-ever port scan ([6535c1e](https://github.com/periphery-security/edgewalker/commit/6535c1e8db3780c4040f3934802298ada66c5427))
* **core:** engine records assessment score/grade on completion (Phase 3, step 9) ([c1de747](https://github.com/periphery-security/edgewalker/commit/c1de74769cfbdedb993e9cee07a5ce4a93e725be))
* **core:** history query methods on the SQLite store (Phase 3, step 6) ([2dd9e30](https://github.com/periphery-security/edgewalker/commit/2dd9e302ef41ccfcb12bcac95ed8fb71ff0801ef))
* **core:** introduce ResultStore abstraction (Phase 1 keystone) ([c68958f](https://github.com/periphery-security/edgewalker/commit/c68958f9cde70a797b38671b67a92d80dd0485c1))
* **core:** persist SQL and web findings + change events in the store ([bf26f9d](https://github.com/periphery-security/edgewalker/commit/bf26f9dbd65a559f1bf16b52937cd91db06bf707))
* **core:** pure diff engine for change tracking (Phase 3, step 2) ([617c624](https://github.com/periphery-security/edgewalker/commit/617c624fbe825c870a9a1675113b6594b4ee0ca9))
* **core:** SQLite result store — schema + structured persistence (Phase 3, step 1) ([3e2ad9a](https://github.com/periphery-security/edgewalker/commit/3e2ad9ace9ab87d6f26c37cf673481948076dde7))
* **core:** store queries to list and compare assessment reports ([10cc5ac](https://github.com/periphery-security/edgewalker/commit/10cc5acff15d5822e81b8e4d64d66a511ca51c25))
* **cve_scan:** add local NVD cache with TTL ([361507d](https://github.com/periphery-security/edgewalker/commit/361507d2c488059255672abb8b9a3629f367e921))
* **cve_scan:** back the CVE cache with the cve_cache table (Phase 3, step 5) ([6e7f19b](https://github.com/periphery-security/edgewalker/commit/6e7f19bdf9aa5ea38344b14358174ab830b34445))
* **models:** add stable per-host key (Phase 2) ([fa46e1e](https://github.com/periphery-security/edgewalker/commit/fa46e1ea372190b83b7130c928d1cfb7bf75d64d))
* shared engine + SQLite store with change tracking and history/compare ([67803b1](https://github.com/periphery-security/edgewalker/commit/67803b16b03edf25b384124e147047b82331612e))
* **tui:** interactive report selection + compare in the HISTORY view ([6a8d74f](https://github.com/periphery-security/edgewalker/commit/6a8d74f52a7d62e1ee6a6353fd4d25d522c2c3ae))
* **tui:** RECENT CHANGES / history view on the dashboard (Phase 3, step 8) ([04ddac2](https://github.com/periphery-security/edgewalker/commit/04ddac25b92b4ccea6046e197d49e2c2e568022e))
* **tui:** render web issue change events in the history view ([fe08f3c](https://github.com/periphery-security/edgewalker/commit/fe08f3ccbcf22f9edf4c252a3d01a50a35fae22d))
* **tui:** renderers for the report list and report comparison ([645960e](https://github.com/periphery-security/edgewalker/commit/645960ed069027d4d1c6490d55e2ede71c28ae52))
* **tui:** report list + latest comparison in the HISTORY view ([8625aa3](https://github.com/periphery-security/edgewalker/commit/8625aa37c4da0db2a9f308584c4e36d6edac1140))


### Bug Fixes

* **core:** record assessment score on the TUI run-all and report paths ([f245dde](https://github.com/periphery-security/edgewalker/commit/f245dded8f42f39865afe45b6bc9b698bcbd9cae))
* **core:** store credential finding service as the enum value, not its repr ([3a896a7](https://github.com/periphery-security/edgewalker/commit/3a896a77eef17d980e896db0439a5feb30298be1))


### Documentation

* document history/compare; add demo seed + VHS tapes ([dca44f8](https://github.com/periphery-security/edgewalker/commit/dca44f8eba9b9129ce4ae7b0a06fd037ced790dc))
* embed history/compare CLI + TUI demo GIFs in the README ([f519a15](https://github.com/periphery-security/edgewalker/commit/f519a1563238f5ce8641484cde10e390bfc90606))
* render history/compare demo GIFs (CLI + TUI) ([9fc75d4](https://github.com/periphery-security/edgewalker/commit/9fc75d404623a44683c21c3be1012daa831dfb33))
* rework CLI + TUI demo tapes into full guided tours ([f16cf29](https://github.com/periphery-security/edgewalker/commit/f16cf292ac39f26e03b392bd843b5baa16a6fbe5))

## [0.1.7](https://github.com/periphery-security/edgewalker/compare/edgewalker-v0.1.6...edgewalker-v0.1.7) (2026-04-22)


### New Features

* add correlation id to telemetry. ([de9c7e4](https://github.com/periphery-security/edgewalker/commit/de9c7e4d7302bd27fcece4698e8c38ea853ee02b))
* add web & sql modules ([83533fc](https://github.com/periphery-security/edgewalker/commit/83533fc9ee42b9935f678a612bc33064897b0313))
* **modules:** add web and sql scanning modules ([9c3e31a](https://github.com/periphery-security/edgewalker/commit/9c3e31ad9a24ba19db3974fc6d8c5989f3cd46b1))


### Bug Fixes

* **modules:** resolve CI issues and improve test coverage ([9db640a](https://github.com/periphery-security/edgewalker/commit/9db640aadc20b6e9e2ff9ec52d4ed69334fa6dce))

## [0.1.6](https://github.com/periphery-security/edgewalker/compare/edgewalker-v0.1.5...edgewalker-v0.1.6) (2026-04-04)


### Bug Fixes

* amend compatibility to support lower python version ([0a9e497](https://github.com/periphery-security/edgewalker/commit/0a9e4978f4d1e7b93323bb8a6d2ab3571d96ed5a))


### Documentation

* replace IoT with edge ([#25](https://github.com/periphery-security/edgewalker/issues/25)) ([d2e2834](https://github.com/periphery-security/edgewalker/commit/d2e283462d3b01c4a85d2dbb61d7241418ec60dc))

## [0.1.5](https://github.com/periphery-security/edgewalker/compare/edgewalker-v0.1.4...edgewalker-v0.1.5) (2026-03-30)


### New Features

* add topology view ([6c7541d](https://github.com/periphery-security/edgewalker/commit/6c7541d0a10fe7b1e7beba167b450f9096376094))
* add upnp and mdns discovery for devices ([c57eab4](https://github.com/periphery-security/edgewalker/commit/c57eab4ea9ff1056caf1c88c7bb54168c7e36e67))


### Bug Fixes

* security vulnerabilities in dependent packages resolved ([56a9e26](https://github.com/periphery-security/edgewalker/commit/56a9e26755f6282616876a18d10003fa8a3d3187))

## [0.1.4](https://github.com/periphery-security/edgewalker/compare/edgewalker-v0.1.3...edgewalker-v0.1.4) (2026-03-09)


### New Features

* add --colorblind flag with Okabe-Ito safe palette ([014ba94](https://github.com/periphery-security/edgewalker/commit/014ba94c3a330f38116694d63e0fb16c2b64160c))
* add --unprivileged and --verbose flags to scan command ([80f1355](https://github.com/periphery-security/edgewalker/commit/80f135532d659fdfe7bdba80660b626f0d1762ff))
* add silent mode and detailed logging for CI/CD automation ([#14](https://github.com/periphery-security/edgewalker/issues/14)) ([db95d39](https://github.com/periphery-security/edgewalker/commit/db95d3989f27085c009b5071f8a2ad2bd023696a))
* add unprivileged support to the TUI ([bf91e12](https://github.com/periphery-security/edgewalker/commit/bf91e124be49ea4ca36f6eb93e4f6677f7cc38ab))
* colorblind mode updates config theme ([23afc5b](https://github.com/periphery-security/edgewalker/commit/23afc5b7b4d1e2fb98f6239b77e0d458b8ce70cb))
* colorblind mode updates config theme ([a1fcb53](https://github.com/periphery-security/edgewalker/commit/a1fcb53b5fc6bac23918fd8217d745db557d4579))
* implement unprivileged mode for CLI and TUI ([12b5d30](https://github.com/periphery-security/edgewalker/commit/12b5d300fbbe478a8027c2a4ffd64b772361eede))


### Bug Fixes

* four bugs in cve_scan and password_scan modules ([2494c05](https://github.com/periphery-security/edgewalker/commit/2494c05018d7c8f7264d5c7d7b9a5d4dc3b6ad90))
* four bugs in cve_scan and password_scan modules ([0949486](https://github.com/periphery-security/edgewalker/commit/0949486103b6c421e7e51301c64620bcb962a53b))
* report save location ([a4d7d75](https://github.com/periphery-security/edgewalker/commit/a4d7d75fe7033add7bdb1648b981886c2c663d67))
* save scan results to ~/.edgewalker/scans not Application Support ([a73dfc4](https://github.com/periphery-security/edgewalker/commit/a73dfc4b7290cf1a66c8f8094da65ca9b7dfcb48))
* verbose logging showing without -vv being specified ([cd6c8e9](https://github.com/periphery-security/edgewalker/commit/cd6c8e9bb8660c93bab7ed8baff32dbfa59107b8))

## [0.1.3](https://github.com/periphery-security/edgewalker/compare/edgewalker-v0.1.2...edgewalker-v0.1.3) (2026-03-05)


### New Features

* add warnings if API URLs are modified ([8117665](https://github.com/periphery-security/edgewalker/commit/8117665a73917bfbd9c5f5e9e8d733fe0ac5bb2a))
* security enhancements and demo mode ([1ae22d3](https://github.com/periphery-security/edgewalker/commit/1ae22d3082f789f3587f655d7ed4906c0383b847))


### Bug Fixes

* .env overrides not clear to users ([ae9cbcf](https://github.com/periphery-security/edgewalker/commit/ae9cbcf0b8bcada7e0fc363c95ac0616c6768e47))
* demo now saves to different file ([eaa2d40](https://github.com/periphery-security/edgewalker/commit/eaa2d401c1cd71191e5a0e6501475725b3226d6d))
* install script vulnerable to malicious values for sudo ([adee940](https://github.com/periphery-security/edgewalker/commit/adee94017715c0b9f983e4e3156f17956a216227))
* scan files now saved with specific users permissions ([e695c86](https://github.com/periphery-security/edgewalker/commit/e695c86ada4ac98e44881771c8b689114a30e62e))
* **scanner:** ping_sweep arguments not validated ([ef5bb31](https://github.com/periphery-security/edgewalker/commit/ef5bb31261c11b0df93604b6de1775c2f147ac34))


### Documentation

* update docs to match changes ([e156a16](https://github.com/periphery-security/edgewalker/commit/e156a168d165acca85923d7bdc2953f6f335552c))

## [0.1.2](https://github.com/periphery-security/edgewalker/compare/edgewalker-v0.1.1...edgewalker-v0.1.2) (2026-03-05)


### Documentation

* add agents file ([f1f10a8](https://github.com/periphery-security/edgewalker/commit/f1f10a802a11427a05fb8056eaf656fe944948d4))
* fix contributing link and code of conduct wording ([6bb26c3](https://github.com/periphery-security/edgewalker/commit/6bb26c364b57de950afa0344b8e041f19716c2a0))
* fix contributing link and code of conduct wording ([68d5f59](https://github.com/periphery-security/edgewalker/commit/68d5f5967b6b34b169a6c254e03bfd35d2feb158))

## [0.1.1](https://github.com/periphery-security/edgewalker/compare/edgewalker-v0.1.0...edgewalker-v0.1.1) (2026-03-04)


### New Features

* initial commit ([df638c2](https://github.com/periphery-security/edgewalker/commit/df638c2b4cdb33313f50f1d68490c3003d90cd91))

## Changelog

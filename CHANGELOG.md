# Changelog

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

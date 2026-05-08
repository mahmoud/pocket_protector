PocketProtector's CHANGELOG
============================

PocketProtector is a growing utility! This document records its growth.

PocketProtector uses the [CalVer](https://calver.org) versioning
scheme (`YY.MINOR.MICRO`).

Check this page when upgrading, we strive to keep the updates
summarized and readable.

26.0.0
------
*(May 8, 2026)*

* Add exec subcommand for injecting secrets into subprocess environments
* Add output format options (env, shell, json, raw) for decrypt-domain
* Add --env-prefix flag for configurable credential environment variable prefix
* Add secret name filter for decrypt-domain
* Add v2 raw-key custodians with hex passphrase support
* Add per-custodian KDF parameters (sensitive, interactive)
* Add rekey-custodian command
* Add migrate-owner command
* Add list-user-secrets command
* Replace --fast-crypto with --key-type (hard, fast, raw)
* Fix list-all-secrets command
* Switch to flit build backend with pyproject.toml
* Add GitHub Actions CI (Python 3.9-3.14, Linux/Mac/Windows) and OIDC publishing
* Fix datetime.utcnow() deprecation warning
* Drop Python 2 support


20.0.1
------
*(January 22, 2020)*

* Fix new user prompt formatting

20.0.0
------
*(January 21, 2020)*

* Python 3 support by way of refactor to use the [face](https://github.com/mahmoud/face) framework
* Extensive testing

18.0.1
------
*(August 22, 2018)*

Fix a schema validation error that occurred when loading a protected
file, due to a breaking change in `ruamel.yaml` version
0.15.55. That's [0ver](https://0ver.org/), folks.

18.0.0
------
*(February 5, 2018)*

Initial release with complete featureset.

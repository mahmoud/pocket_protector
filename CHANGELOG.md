PocketProtector's CHANGELOG
============================

PocketProtector is a growing utility! This document records its growth.

PocketProtector uses the [CalVer](https://calver.org) versioning
scheme (`YY.MINOR.MICRO`).

Check this page when upgrading, we strive to keep the updates
summarized and readable.

26.4.2
------
*(Unreleased)*

* Quote shell command substitution in the eval recipes to prevent word
  splitting and pathname expansion (PP-002); place options before the domain.
* Reject stored v1 KDF costs above 4 operations or 1 GiB before derivation;
  allow explicit trusted-file loading with PPROTECT_TRUST_KDF_PARAMS=1 (PP-003).
* Reject truncated or overlong custodian key material in all wire versions
  instead of accepting trailing bytes or leaking low-level errors (HO-001).
* Clarify that raw-key format validation does not establish entropy; use the
  built-in randomness-backed generator rather than hand-crafted hex (HO-002).

26.4.1
------
*(July 23, 2026)*

* Promote --ignore-env to a visible, documented flag (was hidden with display=False)
* Fix --ignore-env to actually skip credential env var reads (previously only gated the error check)
* Allow --non-interactive --ignore-env when --passphrase-file supplies credentials
* Improve error message for --non-interactive + --ignore-env to reference CLI flags

26.4.0
------
*(July 21, 2026)*

* Add --domain, --secret-name, and --from-file flags to add-secret and
  update-secret, so secret values (multi-line PEMs, values >1024 bytes)
  can be loaded from a file or stdin instead of an interactive prompt
* CI: pin GitHub Actions to commit SHAs and restrict workflow token permissions

26.3.0
------
*(June 18, 2026)*

* Add Creds.from_env() classmethod for reading credentials from environment
* Organize CLI subcommands into groups (Access Management, Domain Management,
  Secret Management, Secret Access) for clearer ``--help`` output
* Drop Python 3.9 support (face 26.0.1 requires Python 3.10+)

26.1.0
------
*(June 3, 2026)*

* Add PPROTECT_ENV_PREFIX env var for setting --env-prefix default
* Tighten shell escaping and secret name validation
* Documentation improvements: new 'Why PocketProtector' page, ReadTheDocs setup

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

Changelog
=========

PocketProtector uses the `CalVer <https://calver.org>`_ versioning
scheme (``YY.MINOR.MICRO``).

The full changelog is maintained on GitHub:

`View Changelog on GitHub <https://github.com/mahmoud/pocket_protector/blob/master/CHANGELOG.md>`_


Recent highlights
-----------------

**26.0.0** *(May 2026)*

* ``exec`` subcommand for injecting secrets into subprocess environments
* Output format options (env, shell, json) for ``decrypt-domain``
* ``--env-prefix`` flag for configurable credential environment variable prefix
* Single secret extraction with ``--secret``
* Raw-key custodians (``--key-type raw``) with hex passphrase support
* Per-custodian KDF parameters (sensitive, interactive)
* ``rekey-custodian`` command
* ``migrate-owner`` command
* ``list-user-secrets`` command
* Replace ``--fast-crypto`` with ``--key-type`` (hard, fast, raw)
* GitHub Actions CI (Python 3.9--3.14, Linux/Mac/Windows)
* Drop Python 2 support

**20.0.1** *(January 2020)*

* Fix new user prompt formatting

**20.0.0** *(January 2020)*

* Python 3 support via refactor to `face <https://github.com/mahmoud/face>`_ framework
* Extensive testing

**18.0.0** *(February 2018)*

* Initial release with complete featureset

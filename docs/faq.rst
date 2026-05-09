FAQ
===


What is PocketProtector?
------------------------

PocketProtector is a serverless, in-repo secret management system. It
encrypts secrets and stores them in a ``protected.yaml`` file alongside
your code. Secrets are organized into domains with cryptographic access
control -- only authorized key custodians can decrypt a domain's secrets.


What is PocketProtector *not*?
------------------------------

* **Not a runtime credential manager.** PocketProtector manages static
  deploy-time secrets (database passwords, API keys, TLS certificates).
  For dynamic credentials (OAuth tokens, short-lived sessions), use a
  runtime credential manager alongside PocketProtector.
* **Not a network daemon or SaaS product.** Serverless is the value
  proposition. There is no server to run.
* **Not an MCP server.** Use ``pprotect exec`` to inject secrets into
  MCP server processes at startup.
* **Not a per-secret access control system.** Domains are the access
  boundary. All secrets in a domain are accessible to all domain owners.


Is it safe to commit protected.yaml?
-------------------------------------

Yes. That's the intended usage. All secret values are encrypted using
NaCl's ``SealedBox`` (Curve25519 + XSalsa20-Poly1305). An attacker with
read access to the file gets environment and secret *names*, but cannot
decrypt any values without the correct custodian passphrase.


What happens if someone leaves the team?
----------------------------------------

1. Remove their ownership from each domain with ``pprotect rm-owner``.
2. Rotate the domain keys with ``pprotect rotate-domain-keys`` so their
   old keys can no longer decrypt secrets from new commits.
3. Optionally, remove them as a key custodian with
   ``pprotect rm-key-custodian`` (the CLI does not expose this directly;
   use the Python API).

Note that secrets in *old* git history remain encrypted with the old
keys. If the departing person knew the secret *values* (not just the
passphrase), you should also rotate the actual secret values with the
upstream providers.


Can I use multiple protected files?
------------------------------------

Yes. Use the ``--file`` flag to specify a different file path::

   pprotect --file secrets/backend.yaml decrypt-domain prod
   pprotect --file secrets/frontend.yaml decrypt-domain prod

Each file is fully independent with its own custodians, domains, and
secrets.


How does this compare to .env files?
--------------------------------------

``.env`` files store secrets in plaintext. They rely on ``.gitignore``
to stay out of version control, which means:

* No versioning or audit trail for secret changes
* No way to share secrets between team members without a side channel
* A single ``git add .`` accident leaks everything

PocketProtector encrypts everything. The file *should* be committed.
Secret changes are git commits with timestamps and authorship.


Why not just use environment variables?
--------------------------------------------

Environment variables are the twelve-factor app recommendation, and they
work. But they have scaling problems:

* Each secret is a separate variable to configure per environment.
  Across dozens of secrets and dozens of environments, you lose track.
* Each variable is a separate thing that can leak. A stack trace, an
  ``os.environ`` dump in a debug log, a ``docker inspect`` call: any
  one can expose a secret.
* Environment variables offer no audit trail. You cannot see who set
  what, when, or why.
* You still need a way to get the variables there. Someone has to paste
  them into the CI config, the Heroku dashboard, the docker-compose file.
  That process is the real secret management problem, and environment
  variables do not solve it.

PocketProtector reduces the bootstrap to a single passphrase per domain.
That passphrase unlocks all secrets in the domain. The secrets themselves
are versioned in the repo, with a built-in audit log. You manage one
credential instead of dozens.


How does this compare to HashiCorp Vault?
------------------------------------------

HashiCorp Vault is a full-featured secret management server with dynamic
credentials, leasing, and access policies. It requires infrastructure
to run (server process, storage backend, unsealing).

PocketProtector is serverless -- there is nothing to deploy, manage, or
keep running. It's a file in your repo. The tradeoff: PocketProtector
handles static secrets only, with no dynamic credential generation or
network API.

Choose Vault when you need a runtime credential manager with dynamic
secrets. Choose PocketProtector when you want simple, git-native secret
storage with no infrastructure.


Can AI agents use PocketProtector?
-----------------------------------

Yes, with caveats. PocketProtector works in agent workflows through
``pprotect exec``, which injects secrets as environment variables into
a child process. The passphrase is scrubbed from the child environment.

However, a coding agent running inside the child process (or any process
with shell access) can still read environment variables. ``exec`` reduces
*accidental* exposure, not adversarial exfiltration. See
:doc:`security` for the full threat model and recommended practices.

For agent workflows that require secret values to be truly invisible to
the agent, consider pairing PocketProtector with a Layer 2 broker tool.
See :doc:`comparison` for options.


How do I pass credentials in CI/CD?
-------------------------------------

Use environment variables with ``--non-interactive``:

.. code-block:: bash

   export PPROTECT_USER=ci@example.com
   export PPROTECT_PASSPHRASE=<passphrase>
   pprotect exec --domain prod --non-interactive -- ./deploy.sh

For stronger isolation, use ``--passphrase-file`` with a mounted secret:

.. code-block:: bash

   pprotect exec --domain prod --passphrase-file /run/secrets/pp_pass -- ./deploy.sh

For automation without human passphrases, create a ``raw`` key type
custodian (``--key-type raw``) and store the generated hex key in your
CI system's secret store.

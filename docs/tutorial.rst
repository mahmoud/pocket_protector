Tutorial
========

PocketProtector is a streamlined, people-centric secret management
system, built to work with modern distributed version control systems.

This tutorial walks through security scenarios commonly faced by
teams, showcasing how PocketProtector's no-nonsense workflow offers
a practical alternative to more complicated solutions.

Starting out
------------

Let's say we have a small engineering team building a software service
whose source code is versioned in git, and they're looking to improve
their secret management. Our team consists of Engineer Alice, Engineer
Bob, CEO Claire, and CTO Tom.

The service interacts with other services, including an email
service. The email service provides an API key, which Claire checked
into the code on day 1, despite Tom's protests.

Let's migrate to a better way, the PocketProtector way!

Creating a new protected
------------------------

With PocketProtector, secrets are encrypted and stored in a file which
is versioned alongside your code. Create this file like so::

   $ pprotect init

You'll be prompted to add a *key custodian*, an administrator for the
secrets we're trying to protect. In our scenario, CTO Tom would be the
natural choice for our first key custodian::

   tom@tomtop $ pprotect init
   Adding new key custodian.
   User email: tom@example.com
   Passphrase:
   Retype passphrase:

After successfully creating his credentials, Tom would see a
``protected.yaml`` now exists in his current directory::

   tom@tomtop $ ls -l protected.yaml
   -rw-rw-r-- 1 tom tom 275 Nov 13 16:25 protected.yaml

PocketProtector will store all secrets encrypted in this YAML file,
which is always safe to check in to the project's repository. It's
commonly put at the root of the repository for discoverability, but
the ``protected.yaml`` is self-contained and can exist anywhere in the
project tree.

.. note::

   **Key types:** When creating a custodian, you can choose a key type
   with ``--key-type``: ``hard`` (default) uses a slow, memory-intensive
   KDF suitable for production passphrases; ``fast`` uses a quicker KDF
   for development and testing; ``raw`` generates a random hex key
   (format ``P<64hex>P``) with no KDF, intended for CI/CD automation.
   If you don't specify ``--key-type``, ``hard`` is used.

Adding a domain
---------------

Right now, the protected only contains credentials for our sole key
custodian, CTO Tom. Before anyone can add any secrets, Tom needs to
create one or more *domains*.

A domain can represent any set of keys accessible to the same actors,
and in our scenario we're going to have one domain per environment,
which means one domain for ``prod`` (our production datacenter) and one
for ``dev`` (our development laptops)::

   tom@tomtop $ pprotect add-domain
   Verify credentials for /home/tom/work/project/protected.yaml
   User email: tom@example.com
   Passphrase:
   Adding new domain.
   Domain name: dev

Tom verifies his credentials and creates the "dev" domain, then does
the same for the "prod" domain.

.. tip::

   Almost all ``pprotect`` subcommands accept a ``--confirm`` option,
   which enables you to see the actual changes being made to the
   protected file, with a prompt to accept or reject. Use this to do
   dry runs of changes, and don't forget that you can and should commit
   the file regularly so you can revert any changes you don't want.

Adding secrets
--------------

So far CTO Tom has done all the work. Now it's time for our Engineers
to pick up the slack. CTO Tom asks Engineer Alice to start
investigating chat integration. Since the chat service requires an API
key, Alice is going to have a secret on her hands.

Alice installs ``pprotect``, pulls the repo with ``protected.yaml``
created by Tom. She adds the ``chat-api-key`` to the protected's ``dev``
domain::

   alice@alicetop $ pprotect add-secret
   Adding secret value.
   Domain name: dev
   Secret name: chat-api-key
   Secret value: abc5ca1ab1e

Notice that PocketProtector did not prompt Alice for any
credentials. Because they were added to the "dev" domain, they were
safely added by encrypting them with a key accessible only to Tom
right now.

**How did the secret get secured without requiring an authenticated
user?**

The best analogy comes from the NaCl project, on top of which
PocketProtector is implemented. Imagine you're a security-conscious
community member, holding a letter you'd like a select few of your
neighbors to read. One elegant solution is to put the letter in your own
mailbox, and make copies of your mailbox key. Then, put a copy of the
key (with instructions) into each of the neighbors' mailboxes.

PocketProtector uses a cryptographic approach known as two-key
encryption to implement this scheme. Every domain is a mailbox, and
only key custodians assigned to that domain are neighbors with a key
to that mailbox. Anyone can *add* a letter (encrypt a secret), but only
custodians who own the domain can *read* it.

Reading a protected
-------------------

The ``protected.yaml`` file is plaintext YAML, designed for some degree
of human readability. But there are more convenient ways to inspect it.

Listing available domains
~~~~~~~~~~~~~~~~~~~~~~~~~

::

   $ pprotect list-domains
   dev
   prod

Listing secrets within a domain
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   $ pprotect list-domain-secrets dev
   chat-api-key
   mail-api-key

Listing all secrets
~~~~~~~~~~~~~~~~~~~

The ``list-all-secrets`` subcommand gives a sorted list of all secrets
with the domains that contain them::

   $ pprotect list-all-secrets
   chat-api-key: dev
   mail-api-key: dev, prod

Listing the audit log
~~~~~~~~~~~~~~~~~~~~~

PocketProtector maintains a human-readable audit log of all operations
performed on the protected::

   $ pprotect list-audit-log
   2020-01-22T18:06:40Z -- created key custodian tom@example.com
   2020-01-22T19:46:15Z -- created domain dev with owner tom@example.com
   2020-01-22T19:46:38Z -- added secret chat-api-key in dev
   2020-01-23T05:12:28Z -- created domain prod with owner tom@example.com
   2020-01-23T05:13:22Z -- added secret mail-api-key in dev
   2020-01-23T05:13:50Z -- added secret mail-api-key in prod

The audit log is supplementary. It can safely be truncated without
affecting any other PocketProtector functionality.

Granting domain access
----------------------

One of PocketProtector's biggest features is its distributed
design. Any action performed with PocketProtector only requires one
set of credentials, if it requires credentials at all.

Back in our scenario, Engineer Alice needs to decrypt secrets from the
``dev`` domain. Right now, only CTO Tom owns that domain. Tom can grant
Alice access by adding her as an owner::

   tom@tomtop $ pprotect add-owner
   Verify credentials for /home/tom/work/project/protected.yaml
   User email: tom@example.com
   Passphrase:
   Adding domain owner.
   Domain name: dev
   New owner email: alice@example.com

Alice must already be a key custodian in the protected (added via
``pprotect add-key-custodian``) before she can be made an owner. Once
added, Alice can decrypt any secret in the ``dev`` domain using her own
credentials.

Alice can check which domains and secrets she has access to::

   alice@alicetop $ pprotect list-user-secrets -u alice@example.com
   dev: chat-api-key, mail-api-key

Decrypting secrets
------------------

Now that Alice owns the ``dev`` domain, she can decrypt its secrets.
By default, ``decrypt-domain`` outputs JSON::

   alice@alicetop $ pprotect decrypt-domain dev
   User email: alice@example.com
   Passphrase:
   {"chat-api-key": "abc5ca1ab1e", "mail-api-key": "m41l-k3y-v4lu3"}

Output formats
~~~~~~~~~~~~~~

The ``--output-format`` flag controls how secrets are printed:

.. code-block:: bash

   # JSON (default)
   pprotect decrypt-domain dev

   # dotenv format: KEY="value"
   pprotect decrypt-domain dev --output-format env

   # Shell export format: export KEY="value"
   eval $(pprotect decrypt-domain dev --output-format shell)

Single secret extraction
~~~~~~~~~~~~~~~~~~~~~~~~

Use ``--secret`` to extract one secret. Without ``--output-format``, the
raw value is printed (no quotes, no key name) for easy use in scripts:

.. code-block:: bash

   db_pass=$(pprotect decrypt-domain prod --secret db-pass)

Running applications with secrets
----------------------------------

The ``exec`` subcommand is the recommended way to pass secrets to an
application. It decrypts a domain and injects the secrets as environment
variables into a child process, without ever writing them to disk:

.. code-block:: bash

   pprotect exec --domain prod -- ./myapp --flag arg

Example::

   tom@tomtop $ pprotect exec --domain prod -- python run_service.py
   User email: tom@example.com
   Passphrase:
   # The service starts with secrets injected as environment variables

``exec`` options:

* ``--domain DOMAIN`` -- the domain to decrypt (required)
* ``--prefix PREFIX`` -- prepend ``PREFIX_`` to each secret's env var name
* ``--uppercase`` -- convert secret names to ``UPPER_CASE``
* ``--no-passthrough`` -- start the child with a minimal environment
  (``PATH``, ``HOME``, ``TERM``, ``LANG``, ``USER``, ``SHELL``,
  ``LOGNAME``) plus the decrypted secrets

``exec`` scrubs ``PPROTECT_USER``, ``PPROTECT_PASSPHRASE``, and any
custom ``--env-prefix`` variables from the child process environment.
On Unix, ``exec`` replaces the current process entirely
(``os.execvpe``), so the passphrase never lingers in a parent shell.

Managing credentials
--------------------

Changing your passphrase
~~~~~~~~~~~~~~~~~~~~~~~~

Key custodians can change their passphrase at any time::

   alice@alicetop $ pprotect set-key-custodian-passphrase
   Verify credentials for /home/alice/work/project/protected.yaml
   User email: alice@example.com
   Current passphrase:
   New passphrase:
   Retype new passphrase:

This re-encrypts Alice's key material with the new passphrase. Her
access to all domains remains unchanged.

Key types
~~~~~~~~~

PocketProtector supports three key derivation modes, selectable with
``--key-type`` when creating a custodian or rekeying:

* **hard** (default) -- slow, memory-intensive KDF (~0.8s, 256 MB). Best
  for human passphrases in production.
* **fast** -- lighter KDF (~0.1s, 64 MB). Suitable for development and
  testing where you unlock frequently.
* **raw** -- no KDF at all. PocketProtector generates a 256-bit random
  key displayed in the format ``P<64 hex chars>P``. You must store this
  key securely (e.g., in a CI secret or vault).

Rekeying a custodian
~~~~~~~~~~~~~~~~~~~~

The ``rekey-custodian`` command re-encrypts a custodian's key material
with a new passphrase and optionally a different key type:

.. code-block:: bash

   # Switch from hard (human passphrase) to raw (automation key)
   pprotect rekey-custodian -u ci@example.com --key-type raw

Multi-project and automation
----------------------------

Custom environment variable prefix
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In environments where multiple PocketProtector-managed projects coexist,
use ``--env-prefix`` to namespace credential environment variables:

.. code-block:: bash

   # Project A
   export PROJECTA_USER=alice@example.com
   export PROJECTA_PASSPHRASE=secret_a
   pprotect decrypt-domain prod --env-prefix PROJECTA

   # Project B (simultaneously)
   export PROJECTB_USER=bob@example.com
   export PROJECTB_PASSPHRASE=secret_b
   pprotect decrypt-domain staging --env-prefix PROJECTB

Credential resolution order
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PocketProtector resolves credentials in this order:

1. **Command-line flags**: ``-u / --user``, ``--passphrase-file``
2. **Environment variables**: ``PPROTECT_USER``, ``PPROTECT_PASSPHRASE``
   (or custom prefix equivalents)
3. **Interactive prompt** (unless ``--non-interactive`` is set)

Flags take precedence over environment variables, and both bypass
interactive prompts.

Non-interactive mode
~~~~~~~~~~~~~~~~~~~~

For CI/CD pipelines, pass ``--non-interactive`` to fail immediately if
credentials cannot be resolved from flags or environment variables:

.. code-block:: bash

   pprotect exec --domain prod --non-interactive -- ./deploy.sh

Team changes and key rotation
------------------------------

Onboarding a new team member
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When Engineer Bob joins the team, he needs to be set up as a key
custodian and granted access to the domains he'll work with:

.. code-block:: bash

   # Bob creates his custodian identity
   pprotect add-key-custodian

   # Tom grants Bob ownership of the dev domain
   pprotect add-owner --domain dev -u tom@example.com

Migrating ownership
~~~~~~~~~~~~~~~~~~~~

When CTO Tom goes on sabbatical, he can transfer all of his domain
ownerships to CEO Claire in one step::

   tom@tomtop $ pprotect migrate-owner
   User email: tom@example.com
   Passphrase:
   New owner email: claire@example.com
   Migrating ownership of 2 domain(s): dev, prod
   Confirm? [y/N]: y

``migrate-owner`` adds the new owner to every domain currently owned by
the authenticated custodian. It does not remove the original owner --
that is a separate step.

Offboarding a team member
~~~~~~~~~~~~~~~~~~~~~~~~~~

When someone leaves the team, remove their ownership from each domain
and then rotate the domain keys:

.. code-block:: bash

   # Remove Tom's ownership of dev and prod
   pprotect rm-owner --domain dev -u alice@example.com
   pprotect rm-owner --domain prod -u alice@example.com

   # Rotate domain keys so Tom's old keys can no longer decrypt
   pprotect rotate-domain-keys --domain dev -u claire@example.com
   pprotect rotate-domain-keys --domain prod -u claire@example.com

``rotate-domain-keys`` generates a new keypair for the domain and
re-encrypts all secrets and owner key shares. Only current owners
retain access after rotation.

Updating and removing secrets
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When a secret changes:

.. code-block:: bash

   pprotect update-secret
   # prompts for domain, secret name, new value

To remove a secret:

.. code-block:: bash

   pprotect rm-secret
   # prompts for domain and secret name

Removing a domain
~~~~~~~~~~~~~~~~~

When an environment is decommissioned:

.. code-block:: bash

   pprotect rm-domain --domain staging -u tom@example.com

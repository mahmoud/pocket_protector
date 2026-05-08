CLI Reference
=============

PocketProtector's CLI is its primary interface. The main command is
``pprotect`` (or equivalently, ``pocket_protector``).

.. program:: pprotect

Global flags
------------

These flags are available on all subcommands:

.. option:: --file PATH

   Path to the PocketProtector-managed file. Defaults to
   ``protected.yaml`` in the working directory.

.. option:: --confirm

   Show a diff and prompt for confirmation before modifying the file.

.. option:: --non-interactive

   Disable interactive prompts. The command fails if credentials cannot
   be resolved from flags or environment variables.

.. option:: --user EMAIL, -u EMAIL

   The acting user's email credential.

.. option:: --passphrase-file PATH

   Path to a file containing only the passphrase, typically provided
   by a deployment system (Docker secrets, Kubernetes mounts).

.. option:: --key-type TYPE

   Custodian key type: ``hard`` (default, slow KDF), ``fast`` (quick
   KDF), or ``raw`` (no KDF, generated hex key).

.. option:: --env-prefix PREFIX

   Environment variable prefix for credential lookup. Default:
   ``PPROTECT``. When set, credentials are read from
   ``PREFIX_USER`` and ``PREFIX_PASSPHRASE``.

.. option:: --output-format FORMAT

   Output format for ``decrypt-domain``: ``json`` (default), ``env``
   (dotenv), or ``shell`` (export statements).

.. option:: --secret NAME

   Decrypt a single secret by name (``decrypt-domain`` only).

.. option:: --domain DOMAIN

   Domain name (used by ``exec`` and other subcommands).

.. option:: --prefix PREFIX

   Prefix to prepend to secret env var names (``exec`` only).

.. option:: --uppercase

   Convert secret names to ``UPPER_CASE`` env var names (``exec`` only).

.. option:: --no-passthrough

   Start the child with a minimal environment (``exec`` only).


Commands
--------

init
~~~~

.. code-block:: bash

   pprotect init [--key-type TYPE]

Create a new ``protected.yaml`` file in the current directory and add
the first key custodian. Prompts for the custodian's email and
passphrase.

This is equivalent to ``add-key-custodian`` but also creates the file.

add-key-custodian
~~~~~~~~~~~~~~~~~

.. code-block:: bash

   pprotect add-key-custodian [--key-type TYPE]

Add a new key custodian to an existing protected file. Prompts for the
custodian's email and passphrase.

With ``--key-type raw``, a 256-bit hex key is generated and displayed.
You must type ``YES`` to confirm you have saved it.

add-domain
~~~~~~~~~~

.. code-block:: bash

   pprotect add-domain [-u EMAIL]

Add a new domain to the protected. Requires authentication as an
existing key custodian, who becomes the initial owner of the domain.
Prompts for the domain name.

rm-domain
~~~~~~~~~

.. code-block:: bash

   pprotect rm-domain [-u EMAIL]

Remove a domain and all of its secrets from the protected. Prompts for
the domain name. This operation is irreversible (use VCS to undo).

add-owner
~~~~~~~~~

.. code-block:: bash

   pprotect add-owner [-u EMAIL]

Add a key custodian as an owner of a domain. The new owner must already
be a key custodian. The authenticated user must already own the domain.

Prompts for the domain name and new owner email.

rm-owner
~~~~~~~~

.. code-block:: bash

   pprotect rm-owner [-u EMAIL]

Remove an owner from a domain. The domain must retain at least one
owner. Prompts for the domain name and owner email to remove.

.. note::

   After removing an owner, you should ``rotate-domain-keys`` to
   ensure the removed owner's old keys can no longer decrypt secrets.

add-secret
~~~~~~~~~~

.. code-block:: bash

   pprotect add-secret

Add a new secret to a domain. Does not require authentication --
secrets are encrypted using the domain's public key. Prompts for domain
name, secret name, and secret value.

Fails if the secret name already exists in the domain. Use
``update-secret`` to change an existing secret's value.

update-secret
~~~~~~~~~~~~~

.. code-block:: bash

   pprotect update-secret

Update the value of an existing secret in a domain. Does not require
authentication. Prompts for domain name, secret name, and new value.

Fails if the secret does not exist. Use ``add-secret`` for new secrets.

rm-secret
~~~~~~~~~

.. code-block:: bash

   pprotect rm-secret

Remove a secret from a domain. Does not require authentication. Prompts
for domain name and secret name.

decrypt-domain
~~~~~~~~~~~~~~

.. code-block:: bash

   pprotect decrypt-domain [DOMAIN] [-u EMAIL] [--output-format FORMAT] [--secret NAME]

Decrypt and display the secrets for a domain. Requires authentication
as a domain owner.

The domain name can be provided as a positional argument or via prompt.

Output format options:

* ``json`` (default) -- JSON object of all secrets
* ``env`` -- dotenv format (``KEY="value"``)
* ``shell`` -- shell export format (``export KEY="value"``)

With ``--secret NAME``, only the named secret is printed. Without
``--output-format``, the raw value is printed (no quoting).

exec
~~~~

.. code-block:: bash

   pprotect exec --domain DOMAIN [--prefix PREFIX] [--uppercase] [--no-passthrough] -- COMMAND [ARGS...]

Decrypt a domain and inject secrets as environment variables into a
child process. This is the recommended way to pass secrets to
applications.

The ``--`` separator is required before the command to execute.

Flags:

* ``--domain DOMAIN`` -- required, the domain to decrypt
* ``--prefix PREFIX`` -- prepend ``PREFIX_`` to each secret env var name
* ``--uppercase`` -- convert secret names to ``UPPER_CASE``, replacing
  non-alphanumeric characters with underscores
* ``--no-passthrough`` -- start the child with a minimal environment
  (``PATH``, ``HOME``, ``TERM``, ``LANG``, ``USER``, ``SHELL``,
  ``LOGNAME``) plus decrypted secrets

Security properties:

* Credential env vars (``PPROTECT_USER``, ``PPROTECT_PASSPHRASE``, and
  any custom ``--env-prefix`` vars) are scrubbed from the child
* On Unix, ``exec`` replaces the current process via ``os.execvpe`` --
  the passphrase never lingers in a parent shell
* On Windows, ``subprocess.run`` is used instead

Example:

.. code-block:: bash

   pprotect exec --domain prod --uppercase -- python run_service.py

set-key-custodian-passphrase
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   pprotect set-key-custodian-passphrase [--key-type TYPE]

Change a key custodian's passphrase. Prompts for the custodian's email,
current passphrase, and new passphrase.

The custodian's domain ownerships are preserved. Only the passphrase
encryption changes.

rekey-custodian
~~~~~~~~~~~~~~~

.. code-block:: bash

   pprotect rekey-custodian [-u EMAIL] [--key-type TYPE]

Re-encrypt a custodian's key material with a new passphrase and
optionally a different key type. This is useful when migrating from a
human passphrase to an automated raw key for CI/CD.

All domain ownerships are preserved and re-encrypted with the new key
material.

rotate-domain-keys
~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   pprotect rotate-domain-keys [-u EMAIL]

Rotate the internal encryption keys for a domain. Generates a new
keypair, re-encrypts all secrets and owner key shares. Only current
owners retain access after rotation.

Requires authentication as a domain owner. Prompts for the domain name.

This should be done after any personnel change involving someone who
had domain access.

migrate-owner
~~~~~~~~~~~~~

.. code-block:: bash

   pprotect migrate-owner [-u EMAIL]

Grant a custodian ownership of all domains currently owned by the
authenticated user. Prompts for the new owner email and confirmation.

Does not remove the original owner -- that is a separate step.

list-domains
~~~~~~~~~~~~

.. code-block:: bash

   pprotect list-domains

Display all domain names in the protected, one per line.

list-domain-secrets
~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   pprotect list-domain-secrets [DOMAIN]

Display all secret names within a domain, one per line. The domain name
can be provided as a positional argument or via prompt.

list-all-secrets
~~~~~~~~~~~~~~~~

.. code-block:: bash

   pprotect list-all-secrets

Display all secrets across all domains. Each line shows a secret name
followed by a colon and the domains that contain it::

   chat-api-key: dev
   mail-api-key: dev, prod

list-audit-log
~~~~~~~~~~~~~~

.. code-block:: bash

   pprotect list-audit-log

Display the audit log, one entry per line. Each entry includes a
timestamp and a description of the operation performed.

list-user-secrets
~~~~~~~~~~~~~~~~~

.. code-block:: bash

   pprotect list-user-secrets [-u EMAIL]

Display the domains and secrets accessible to the authenticated user.
Requires authentication.

version
~~~~~~~

.. code-block:: bash

   pprotect version

Display the current PocketProtector version and exit.

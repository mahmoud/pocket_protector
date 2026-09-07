Security Design
===============

This document describes PocketProtector's security architecture, threat
model, and considerations for agent and automation use.


Theory of operation
-------------------

PocketProtector's ``protected.yaml`` file consists of *key domains* at
the root level. Each domain stores data encrypted by a keypair:

* The **public key** is stored in plaintext, so that anyone may encrypt
  and add a new secret.
* The **private key** is encrypted with each owner's passphrase. The
  owners are known as *key custodians*, and their private keys are
  protected by passphrases.

This is a two-key encryption scheme built on NaCl's ``SealedBox``
(Curve25519 + XSalsa20-Poly1305). Passphrases are processed through
Argon2id key derivation.


File structure
--------------

The ``protected.yaml`` file is a self-contained YAML document:

.. code-block:: yaml

   dev:
     meta:
       public-key: <base64>
       owners:
         alice@example.com: <encrypted-private-key>
         tom@example.com: <encrypted-private-key>
     secret-db-password: <encrypted-value>
     secret-api-key: <encrypted-value>
   prod:
     meta:
       public-key: <base64>
       owners:
         tom@example.com: <encrypted-private-key>
     secret-db-password: <encrypted-value>
   key-custodians:
     alice@example.com:
       pwdkm: <base64>
     tom@example.com:
       pwdkm: <base64>
   audit-log:
   - "2026-01-01T00:00:00Z -- created key custodian tom@example.com"
   - "2026-01-01T00:00:01Z -- created domain dev with owner tom@example.com"

All state PocketProtector needs to operate is included in this file. The
file is designed for ``git diff``, ``git blame``, and ``git log``.


Cryptographic details
---------------------

* **Key derivation**: Argon2id via PyNaCl. Three modes:

  * ``hard`` (default): ``OPSLIMIT_SENSITIVE``, ``MEMLIMIT_MODERATE`` --
    ~0.8s, 256 MB
  * ``fast``: ``OPSLIMIT_INTERACTIVE``, ``MEMLIMIT_INTERACTIVE`` --
    ~0.1s, 64 MB
  * ``raw``: No KDF. A 256-bit random key is used directly. Format:
    ``P<64 hex chars>P``. Format validation checks shape, not entropy; key
    strength depends on its randomness source, so use the built-in
    ``os.urandom``-backed generator rather than hand-crafted hex.

  Stored v1 KDF costs are checked when the file is loaded, before any key
  derivation. The maximum ``opslimit`` is **4** and the maximum ``memlimit``
  is **1,073,741,824 bytes (1 GiB)**, matching PyNaCl's
  ``argon2id.OPSLIMIT_SENSITIVE`` and ``argon2id.MEMLIMIT_SENSITIVE``.
  Exceeding either ceiling raises ``PPError``; costs are never silently
  clamped because that would change the derived key.

  For a trusted file that intentionally uses higher costs, set
  ``PPROTECT_TRUST_KDF_PARAMS=1`` before loading it. Any nonempty value
  disables these load-time ceilings for both CLI and library callers.
  Leave it unset for untrusted files, and ensure sufficient memory and CPU
  are available before deriving a key with trusted higher costs.

* **Encryption**: NaCl ``SealedBox`` (Curve25519 public key encryption)
* **Secret storage**: Each secret is encrypted with the domain's public
  key. Only domain owners (who hold the private key, encrypted under
  their passphrase) can decrypt.
* **Versioned binary format**: Key material is prefixed with a version
  byte (v0, v1, v2) for forward compatibility. Custodian ``pwdkm`` payloads
  must be exactly 41 bytes for v0/v2 or 49 bytes for v1 after Base64
  decoding; both truncated payloads and trailing bytes raise ``PPError``.


Threat model
------------

**Assumed attacker capability**: Read access to ``protected.yaml``. This
could happen because a developer's laptop is compromised, GitHub
credentials are compromised, or git history is accidentally pushed to a
public repo.

**What the attacker gets**: Environment and secret names, and which
secrets are used in which environments. The names and structure are
visible; values are not.

**What the attacker cannot do**: Decrypt any secret values without the
correct custodian passphrase.

**Write access**: PocketProtector does not provide write protection.
Write access control is delegated to the VCS (git permissions, signed
commits, branch protection). Neither the file nor individual entries are
signed, since the security model assumes an attacker does not have write
access.

The file is designed for use alongside VCS tools:

* ``git log protected.yaml`` -- view change history
* ``git blame protected.yaml`` -- see who changed what
* Signed commits are a particularly good complement


Passphrase security by domain
------------------------------

Passphrase security will depend on the domain:

* A **development** domain may set the passphrase as an environment
  variable or hardcode it in a configuration file such as a ``.env``
  next to ``protected.yaml``. The risk is low -- dev secrets are
  typically non-sensitive.
* A **production** domain would likely require manual entry of an
  authorized release engineer, or use AWS/GCP/Heroku key management
  solutions to inject the passphrase.

This layered approach lets teams balance security with convenience for
each environment.


Agent and automation security
------------------------------

PocketProtector is commonly used in CI/CD pipelines and increasingly
alongside AI coding agents. In these contexts, secret hygiene matters
more than usual.

Credential injection: safest to weakest
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. **pprotect exec** (safest): Decrypts a domain and injects secrets as
   env vars into a child process. The custodian passphrase is scrubbed
   from the child environment. Secrets exist only in the child process
   memory, never on disk or in the parent env.

   .. code-block:: bash

      pprotect exec --domain prod -- ./myapp --flag arg

2. **--passphrase-file from a restricted mount**: Store the passphrase
   on a tmpfs or Docker secret mount with ``0400`` permissions. Keeps
   the passphrase off the command line and out of the process
   environment.

   .. code-block:: bash

      pprotect decrypt-domain prod --passphrase-file /run/secrets/pp_pass

3. **PPROTECT_PASSPHRASE env var** (simplest): The classic option but
   not the safest. Readable by any subprocess, including AI agents,
   build scripts, and debug tooling.

4. **.env file** (weakest): ``PPROTECT_USER`` and ``PPROTECT_PASSPHRASE``
   are read from a ``.env`` in the same directory as ``protected.yaml``
   (or the path given to ``--env-file``) whenever flags and the process
   environment leave a credential unresolved. This puts the passphrase in
   plaintext beside the file it unlocks, so read access to the directory
   is enough to decrypt every domain that custodian owns. The threat model
   above assumes the attacker can read ``protected.yaml``; a ``.env``
   beside it voids that assumption. Coding agents and build tooling read
   ``.env`` files as a matter of course.

   Use it for development domains only. Keep it out of version control
   (``git check-ignore -q .env`` should succeed), restrict it to ``0600``,
   and pass ``--no-env-file`` or ``--ignore-env`` when a stray ``.env``
   must not be consulted. The file is never loaded into the process
   environment, so ``pprotect exec`` children do not inherit it.

Security note on pprotect exec
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An agent or process that can run arbitrary commands could call
``pprotect decrypt-domain`` directly. ``exec`` reduces *accidental*
exposure (logged output, env dumps, process listings), not adversarial
exfiltration by a fully compromised agent. Defense in depth still
applies: restrict filesystem access, use scoped custodians, and audit
the ``protected.yaml`` change log.


What PocketProtector is not
----------------------------

PocketProtector manages **static deploy-time secrets** -- database
passwords, API keys, TLS certificates. It is not a runtime credential
manager.

Explicit non-goals:

* **Network daemon / SaaS mode** -- serverless is the value prop
* **Time-limited credentials** -- no clock-based expiry; use
  ``pprotect exec`` to limit secret lifetime to a process
* **Per-secret access control** -- domains are the access boundary
* **MCP server mode** -- use ``pprotect exec`` to inject secrets into
  MCP server processes at startup
* **Output redaction** -- PocketProtector does not scan subprocess
  output for leaked secret values
* **Repo leak scanning** -- PocketProtector does not scan source files
  for accidentally committed secrets

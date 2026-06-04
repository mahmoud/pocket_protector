Programmatic Usage
==================

While PocketProtector's CLI is its primary interface, the Python API
enables direct integration into applications and scripts. This guide
covers real-world usage patterns.


Basic decryption
----------------

The most common pattern: load a protected file, authenticate, and
decrypt a domain.

.. code-block:: python

   from pocket_protector import KeyFile, Creds

   kf = KeyFile.from_file('protected.yaml')
   creds = Creds(name='alice@example.com', passphrase='my-passphrase')
   secrets = kf.decrypt_domain('prod', creds)

   # secrets is a dict-like object
   db_password = secrets['db-password']
   api_key = secrets['api-key']

The returned object raises :class:`~pocket_protector.PPError` (specifically
``PPKeyError``) if you access a secret that doesn't exist, with a
helpful error message listing known secrets.


CRUD operations
---------------

All mutating operations return a new ``KeyFile`` instance (the class is
immutable). You must call ``.write()`` to persist changes.

.. code-block:: python

   from pocket_protector import KeyFile, Creds

   kf = KeyFile.from_file('protected.yaml')

   # Add a secret (fails if it already exists)
   kf = kf.add_secret('dev', 'new-api-key', 'secret-value')

   # Update a secret (fails if it doesn't exist)
   kf = kf.update_secret('dev', 'new-api-key', 'updated-value')

   # Set a secret (add or update, no error either way)
   kf = kf.set_secret('dev', 'new-api-key', 'another-value')

   # Remove a secret
   kf = kf.rm_secret('dev', 'new-api-key')

   # Persist all changes
   kf.write()

.. important::

   Each method returns a **new** ``KeyFile``. Forgetting to capture the
   return value means your changes are lost::

      # WRONG: result is discarded
      kf.add_secret('dev', 'key', 'value')

      # RIGHT: capture the new instance
      kf = kf.add_secret('dev', 'key', 'value')


Bootstrapping a new protected
------------------------------

Creating a protected file from scratch, programmatically:

.. code-block:: python

   from pocket_protector import KeyFile, Creds, KDF_INTERACTIVE

   # Create the file
   kf = KeyFile.create('protected.yaml')

   # Add a key custodian
   creds = Creds(name='admin@example.com', passphrase='admin-pass')
   kf = kf.add_key_custodian(creds, *KDF_INTERACTIVE)

   # Create a domain with the custodian as owner
   kf = kf.add_domain('dev', 'admin@example.com')

   # Add secrets
   kf = kf.add_secret('dev', 'db-password', 'p4ssw0rd')
   kf = kf.add_secret('dev', 'api-key', 'ak_12345')

   # Write to disk
   kf.write()


Introspection
-------------

Inspect a protected file without decrypting anything:

.. code-block:: python

   kf = KeyFile.from_file('protected.yaml')

   # List domains
   kf.get_domain_names()
   # ['dev', 'prod']

   # List secrets in a domain
   kf.get_domain_secret_names('dev')
   # ['api-key', 'db-password']

   # Map of secret names to domains that contain them
   kf.get_all_secret_names()
   # {'api-key': ['dev', 'prod'], 'db-password': ['dev']}

   # Audit log
   kf.get_audit_log()
   # ['2026-01-01T00:00:00Z -- created key custodian admin@example.com', ...]

   # Domains a custodian owns
   kf.get_custodian_domains('admin@example.com')
   # ['dev', 'prod']


Key management
--------------

.. code-block:: python

   from pocket_protector import KeyFile, Creds, KDF_INTERACTIVE

   kf = KeyFile.from_file('protected.yaml')

   # Add a new custodian
   new_creds = Creds(name='bob@example.com', passphrase='bob-pass')
   kf = kf.add_key_custodian(new_creds, *KDF_INTERACTIVE)

   # Grant domain access (requires existing owner credentials)
   admin_creds = Creds(name='admin@example.com', passphrase='admin-pass')
   kf = kf.add_owner('dev', 'bob@example.com', admin_creds)

   # Migrate all ownerships to another custodian
   kf = kf.migrate_owner('bob@example.com', admin_creds)

   # Rotate domain keys (after removing an owner)
   kf = kf.rm_owner('dev', 'old-user@example.com')
   kf = kf.rotate_domain_key('dev', admin_creds)

   kf.write()


Config integration pattern
--------------------------

A pattern used in real-world applications: TOML or INI config values
prefixed with ``protected:`` are resolved from a decrypted domain.

.. code-block:: python

   import tomllib
   from pocket_protector import KeyFile, Creds

   PROTECTED_PREFIX = 'protected:'

   def load_config(config_path, protected_path, domain, creds):
       """Load config, resolving protected: prefixed values from a domain."""
       with open(config_path, 'rb') as f:
           config = tomllib.load(f)

       kf = KeyFile.from_file(protected_path)
       secrets = kf.decrypt_domain(domain, creds)

       def resolve(obj):
           if isinstance(obj, str) and obj.startswith(PROTECTED_PREFIX):
               secret_name = obj[len(PROTECTED_PREFIX):]
               return secrets[secret_name]
           if isinstance(obj, dict):
               return {k: resolve(v) for k, v in obj.items()}
           return obj

       return resolve(config)

Example config (``config.toml``):

.. code-block:: toml

   [database]
   host = "db.example.com"
   password = "protected:db-password"

   [email]
   api_key = "protected:mail-api-key"


Subprocess integration
----------------------

When PocketProtector is used from non-Python applications, or when
process isolation is desired, shell out to ``pprotect``:

.. code-block:: python

   import subprocess
   import json
   import os

   def decrypt_via_cli(domain, user, passphrase):
       """Decrypt a domain using the pprotect CLI."""
       env = {
           'PATH': os.environ['PATH'],
           'PPROTECT_USER': user,
           'PPROTECT_PASSPHRASE': passphrase,
       }
       result = subprocess.run(
           ['pprotect', 'decrypt-domain', '--non-interactive', domain],
           capture_output=True, text=True, env=env,
       )
       result.check_returncode()
       return json.loads(result.stdout)

When to use the CLI vs. the API:

* **Use the API** when your application is Python and you want to avoid
  subprocess overhead, or when you need fine-grained control (CRUD
  operations, key management).
* **Use the CLI** when calling from a non-Python language, when you want
  process isolation (``exec``), or when working in shell scripts.


Passphrase management
---------------------

In automation, passphrases typically come from environment variables.
The ``Creds.from_env()`` classmethod handles this:

.. code-block:: python

   from pocket_protector import Creds

   # Reads PPROTECT_USER and PPROTECT_PASSPHRASE
   creds = Creds.from_env()

   # Or with a custom prefix (reads MYAPP_USER and MYAPP_PASSPHRASE)
   creds = Creds.from_env(prefix='MYAPP')

When ``prefix`` is not passed, ``from_env()`` checks the
``PPROTECT_ENV_PREFIX`` environment variable before falling back to
``PPROTECT``.

The resulting ``Creds`` object has ``name_source`` and
``passphrase_source`` set automatically, so error messages will
reference the correct env var names.
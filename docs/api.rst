API Reference
=============

PocketProtector's Python API provides programmatic access to the same
operations available through the CLI. All public symbols are importable
from the top-level ``pocket_protector`` package.

.. code-block:: python

   from pocket_protector import KeyFile, Creds, PPError, KDF_SENSITIVE, KDF_INTERACTIVE


KeyFile
-------

.. autoclass:: pocket_protector.file_keys.KeyFile
   :members: create, from_file, from_contents_and_path, write, get_contents,
             add_domain, rm_domain, add_secret, set_secret, update_secret,
             rm_secret, add_owner, rm_owner, add_key_custodian,
             add_raw_key_custodian, rm_key_custodian, decrypt_domain,
             set_key_custodian_passphrase, rekey_custodian, migrate_owner,
             rotate_domain_key, get_domain_names, get_domain_secret_names,
             get_all_secret_names, get_audit_log, get_custodian_domains,
             check_creds, truncate_audit_log
   :undoc-members:

.. note::

   ``KeyFile`` is a frozen (immutable) ``attrs`` class. All mutating
   methods return a *new* ``KeyFile`` instance. You must call
   :meth:`~pocket_protector.file_keys.KeyFile.write` on the result to
   persist changes to disk.


Creds
-----

.. autoclass:: pocket_protector.file_keys.Creds
   :members:
   :undoc-members:

``Creds`` is a frozen ``attrs`` class with four fields:

* ``name`` (str) -- the custodian's email address
* ``passphrase`` (str) -- the custodian's passphrase
* ``name_source`` (str or None) -- how the name was obtained (e.g., ``"stdin"``, ``"env var: PPROTECT_USER"``)
* ``passphrase_source`` (str or None) -- how the passphrase was obtained

.. classmethod:: Creds.from_env(prefix=None)

   Create ``Creds`` from environment variables. If *prefix* is ``None``,
   reads ``PPROTECT_ENV_PREFIX`` to determine the prefix, defaulting to
   ``PPROTECT``. Returns ``Creds`` with ``name`` from ``{prefix}_USER``
   and ``passphrase`` from ``{prefix}_PASSPHRASE`` (empty string if unset).


PPError
-------

.. autoexception:: pocket_protector.file_keys.PPError
   :show-inheritance:

Base exception for PocketProtector errors. Inherits from :class:`Exception`.


Constants
---------

.. data:: pocket_protector.KDF_SENSITIVE

   KDF parameters for production use: ``(OPSLIMIT_SENSITIVE, MEMLIMIT_MODERATE)``.
   Approximately 0.8 seconds and 256 MB of memory. This is the default when
   creating custodians with ``--key-type hard``.

.. data:: pocket_protector.KDF_INTERACTIVE

   KDF parameters for development and testing: ``(OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE)``.
   Approximately 0.1 seconds and 64 MB of memory. Used with ``--key-type fast``.

Installation
============

Requirements
------------

PocketProtector requires **Python 3.9 or newer**.

Dependencies are installed automatically:

* `PyNaCl <https://pynacl.readthedocs.io/>`_ -- cryptographic operations (Curve25519, Argon2id)
* `ruamel.yaml <https://yaml.readthedocs.io/>`_ -- YAML parsing and serialization
* `attrs <https://www.attrs.org/>`_ -- data classes
* `boltons <https://boltons.readthedocs.io/>`_ -- utility functions
* `schema <https://github.com/keleshev/schema>`_ -- data validation
* `face <https://github.com/mahmoud/face>`_ -- CLI framework

Install from PyPI
-----------------

.. code-block:: bash

   pip install pocket_protector

Verify the installation:

.. code-block:: bash

   $ pprotect version
   pocket_protector version 26.0.0

The package installs two equivalent console scripts: ``pprotect`` (short
form) and ``pocket_protector``.

Development install
-------------------

To work on PocketProtector itself:

.. code-block:: bash

   git clone https://github.com/mahmoud/pocket_protector.git
   cd pocket_protector
   pip install -e ".[dev]"

Run tests with:

.. code-block:: bash

   pytest

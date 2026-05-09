PocketProtector
===============

.. image:: https://img.shields.io/pypi/v/pocket-protector.svg
   :target: https://pypi.org/project/pocket-protector/
   :alt: PyPI

.. image:: https://img.shields.io/badge/calver-YY.MINOR.MICRO-blue.svg
   :target: https://calver.org
   :alt: CalVer

.. image:: https://img.shields.io/badge/changelog-latest-green.svg
   :target: https://github.com/mahmoud/pocket_protector/blob/master/CHANGELOG.md
   :alt: Changelog

**Serverless, in-repo, people-centric secret management.**

PocketProtector provides a cryptographically-strong, serverless secret
management infrastructure. Secrets are encrypted and stored in a
versionable ``protected.yaml`` file, right alongside your application
code.

Quick install::

   pip install pocket_protector

Quick start::

   pprotect init
   pprotect add-domain
   pprotect add-secret
   pprotect decrypt-domain

Each command prompts for credentials when necessary. When done, simply
``git commit`` to save changes to your secret store.

Most secret management tools either sacrifice security for convenience, or
require infrastructure you have to operate. PocketProtector gives you both:
secrets live encrypted in your repo, versioned alongside code, with no
server to run. See :doc:`why` for the full argument.

.. raw:: html

   <div style="position: relative; padding-bottom: 56.25%; height: 0; overflow: hidden; max-width: 100%; margin: 1.5em 0;">
     <iframe src="https://www.youtube.com/embed/7Zhxu_4qhyM" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%;" frameborder="0" allowfullscreen></iframe>
   </div>


.. toctree::
   :maxdepth: 2
   :caption: Getting Started

   why
   installation
   tutorial

.. toctree::
   :maxdepth: 2
   :caption: Reference

   cli
   api

.. toctree::
   :maxdepth: 1
   :caption: Guides

   python_usage
   security

.. toctree::
   :maxdepth: 1
   :caption: Context

   comparison
   faq

.. toctree::
   :maxdepth: 1
   :caption: Project

   changelog

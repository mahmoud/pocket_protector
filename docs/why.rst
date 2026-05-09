Why PocketProtector
===================

Developers need secrets. API keys, database passwords, TLS certificates,
signing tokens. Every non-trivial application has them, and every team
has to decide how to manage them.

There are many approaches. Each solves one problem and introduces another.


The problem with secrets
------------------------

Secrets in the code
~~~~~~~~~~~~~~~~~~~

The earliest and easiest approach: paste the API key into your source file,
commit, push, deploy. It works until someone searches GitHub for
``password =`` or ``api_key =`` and finds yours.

Once a secret is in a public commit, it is compromised. Even in a private
repo, every developer with read access can see every secret for every
environment. There is no access control, no audit trail, and no way to
rotate without editing source.

Secrets in config files
~~~~~~~~~~~~~~~~~~~~~~~

Move the secrets out of code and into a config file: ``settings.py``,
``config.ini``, ``.cfg``. This feels better, but the config file is not
any more secure than your code. You just have two files to protect now,
and the config file still has to live somewhere accessible to the
application.

Most teams add the config file to ``.gitignore``, which means it is no
longer versioned, no longer shared, and no longer auditable. New developers
ask "where do I get the config?" and someone pastes it into Slack.

Secrets in environment variables
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The `twelve-factor app <https://12factor.net/config>`_ recommendation.
Environment variables keep secrets out of the repo, which is the right
instinct.

But as you add more secrets, you end up with dozens of environment variables
across dozens of environments, and you lose track. Each variable is a
separate thing that can leak: a stack trace, an ``os.environ`` dump in a
debug log, a ``docker inspect`` call. Any one of them can expose a secret.

And you still need a way to get the variables there in the first place.
Someone has to paste them into the CI config, the Heroku dashboard, the
``docker-compose.yml``. That process is the real secret management problem,
and environment variables do not solve it.

Password managers
~~~~~~~~~~~~~~~~~

1Password, LastPass, Bitwarden. By 2026 these tools have added
developer-focused features: 1Password has Secrets Automation and Connect
Server, Bitwarden has Secrets Manager with a CLI. They are better for
teams than they used to be.

But they are still external service dependencies. Your deploy pipeline has
to reach them. They do not version secrets alongside the code that uses
them, so there is no single commit that says "here is the feature and
here is the key it needs." And they add a service your infrastructure
must authenticate against, monitor, and keep running.

Key management services
~~~~~~~~~~~~~~~~~~~~~~~

HashiCorp Vault, AWS KMS, hardware security modules. These are serious
tools for serious infrastructure. They work.

But they do not scale down. You have to run a service, even for your local
dev environment. That means extra ``docker-compose`` components,
infrastructure to operate, and credentials to manage the credential manager.
For a team of three working on one application, this is overhead that does
not pay for itself.

Git-native encryption tools
~~~~~~~~~~~~~~~~~~~~~~~~~~~

git-crypt encrypts files in git and decrypts them on checkout. The idea
is sound, but the implementation is fragile. git-crypt relies on
``.gitattributes`` patterns to decide what gets encrypted. One wrong
entry, one merge that drops a line, and you push plaintext. There is no
per-user access control: everyone with the symmetric key can decrypt
everything.

`SOPS <https://github.com/getsops/sops>`_ is more capable. It encrypts
individual values within YAML, JSON, and ENV files, and it integrates
with AWS KMS, GCP KMS, Azure Key Vault, and age for key management.
It is widely adopted and well maintained.

But SOPS brings back the key management service problem: you need a KMS
backend to manage the encryption keys, which means infrastructure and
IAM configuration. It has no multi-party access model. There is no
equivalent of PocketProtector's domain custodians, where different people
hold different keys for different environments. And there is no way to
add a secret without having decryption access yourself.


Secrets as code
---------------

PocketProtector takes a different approach: the ease of putting secrets in
code, with the security of a key management service.

Encrypted secrets live in a ``protected.yaml`` file, right in your repo.
The file is safe to commit, push, and share. Anyone with repo access can
add a secret. Only authorized key custodians can decrypt.

Secrets are versioned with your code. When the code needs a new API key,
the key goes into the same commit. When someone reviews the pull request,
they see that a secret was added. When something breaks, ``git blame``
tells you who changed what and when.

The ``protected.yaml`` format is compact, readable, and git-friendly. You
can diff it, blame it, and merge it the same way you merge any other YAML
file.


It scales up and it scales down
-------------------------------

Key management services require infrastructure at every scale.
PocketProtector requires nothing.

**A solo developer on a laptop:** ``pip install pocket_protector``,
``pprotect init``, done. Secrets in the repo, encrypted, no service running.

**A team of a dozen across dev, staging, and prod:** each person is a key
custodian, each environment is a domain. Same file, same workflow, same git
history.

PocketProtector was used in production at
`SimpleLegal <https://www.simplelegal.com/>`_ for over two years across
multiple applications and environments. No incidents, no infrastructure to
babysit.


Anyone can write, only owners can read
---------------------------------------

Unlike most secret stores, adding a secret to PocketProtector does not
require authentication. Any developer with repo access can run
``pprotect add-secret`` and put a value into a domain. The secret is
encrypted with the domain's public key, which is stored in the file.

This means a developer integrating a new API can add the key to the repo
themselves. No asking a domain owner to do it for them. No side channel.
No shared password document.

Only domain owners can decrypt. The separation between write access
(anyone) and read access (authenticated owners) is the key design insight.
It removes the bottleneck that makes other secret management tools slow
to adopt: the need to grant credentials before someone can contribute
credentials.


One passphrase, many secrets
-----------------------------

Environment variable approaches require you to manage N secrets as N
separate variables. Each one is a separate thing to configure, rotate,
and protect.

With PocketProtector, a single custodian passphrase unlocks all secrets
in a domain. One credential to manage instead of dozens. And that one
credential never appears in the ``protected.yaml`` file, never appears in
environment dumps, never leaks through stack traces.

The passphrase is the bootstrap. Everything else is derived from it
cryptographically.


Learn more
----------

Watch the Pyninsula #24 talk that introduced the "secrets as code" concept:

.. raw:: html

   <div style="position: relative; padding-bottom: 56.25%; height: 0; overflow: hidden; max-width: 100%; margin: 1.5em 0;">
     <iframe src="https://www.youtube.com/embed/7Zhxu_4qhyM" style="position: absolute; top: 0; left: 0; width: 100%; height: 100%;" frameborder="0" allowfullscreen></iframe>
   </div>

Then try it yourself: :doc:`installation` and :doc:`tutorial`.

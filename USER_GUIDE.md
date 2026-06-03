# PocketProtector User Guide

PocketProtector is a streamlined, people-centric secret management
system, built to work with modern distributed version control systems.

This guide will walk you through security scenarios commonly faced by
teams, and showcase how PocketProtector's no-nonsense workflow offers
a practical alternative to more complicated solutions.

## Starting out

Let's say we have a small engineering team building a software service
whose source code is versioned in git, and they're looking to improve
their secret management. Our team consists of Engineer Alice, Engineer
Bob, CEO Claire, and CTO Tom.

The service interacts with other services, including an email
service. The email service provides an API key, which Claire checked
into the code on day 1, despite Tom's protests.

Let's migrate to a better way, the PocketProtector way!

## Installation

Right now, the easiest way to install PocketProtector across all
platforms is with `pip`:

```
pip install pocket_protector
```

This will install a command-line application, `pocket_protector`,
conveniently shortened to `pprotect`, which you can use to test your
installation:

```
$ pprotect version
pocket_protector version 26.0.0
```

Once the above is working, we're ready to start using PocketProtector!

PocketProtector requires Python 3.9 or newer.

## Creating a New Protected

With PocketProtector, secrets are encrypted and stored in a file which
is versioned alongside your code. Create this file like so:

```
$ pprotect init
```

You'll be prompted to add a *key custodian*, an administrator for the
secrets we're trying to protect. In our scenario, CTO Tom would be the
natural choice for our first key custodian.

```
tom@tomtop $ pprotect init
Adding new key custodian.
User email: tom@example.com
Passphrase:
Retype passphrase:
```

After successfully creating his credentials, Tom would see a
`protected.yaml` now exists in his current directory:

```
tom@tomtop $ ls -l protected.yaml
-rw-rw-r-- 1 tom tom 275 Nov 13 16:25 protected.yaml
```

PocketProtector will store all secrets encrypted in this YAML file,
which is always safe to check in to the project's repository. It's
commonly put at the root of the repository for discoverability, but
the protected.yaml is self-contained and can exist anywhere in the
project tree.

> **Key types:** When creating a custodian, you can choose a key type with
> `--key-type`: `hard` (default) uses a slow, memory-intensive KDF suitable
> for production passphrases; `fast` uses a quicker KDF for development and
> testing; `raw` generates a random hex key (format `P<64hex>P`) with no KDF,
> intended for CI/CD automation. If you don't specify `--key-type`, `hard` is
> used.

## Adding a Domain

Right now, the protected only contains credentials for our sole key
custodian, CTO Tom. Before anyone can add any secrets, Tom needs to
create one or more *domains*.

A domain can represent any set of keys accessible to the same actors,
and in our scenario we're going to have one domain per environment,
which means one domain for `prod` (our production datacenter) and one
for `dev` (our development laptops).

```
tom@tomtop $ pprotect add-domain
Verify credentials for /home/tom/work/project/protected.yaml
User email: tom@example.com
Passphrase:
Adding new domain.
Domain name: dev
```

Tom verifies his credentials and creates the "dev" domain, then does
the same for the "prod" domain.

> **Tip**: Almost all `pprotect` subcommands accept a `--confirm-diff`
> option, which enables you to see the actual changes being made to the
> protected file, with a prompt to accept or reject. You can use this
> functionality to do dry runs of changes, and don't forget that you can
> and should commit the file regularly so you can revert any changes you
> don't want.

Now that we have our first custodian and our two domains, we're ready
to start adding secrets!

## Adding Secrets

So far CTO Tom has done all the work. Now it's time for our Engineers
to pick up the slack. CTO Tom asks Engineer Alice to start
investigating chat integration. Since the chat service requires an API key, Alice is
going to have a secret on her hands.

Alice installs `pprotect`, pulls the repo with `protected.yaml`
created by Tom. She adds the "chat-api-key" to the protected's `dev`
domain like so:

```
alice@alicetop $ pprotect add-secret
Adding secret value.
Domain name: dev
Secret name: chat-api-key
Secret value: abc5ca1ab1e
```

Notice that PocketProtector did not prompt Alice for any
credentials. Because they were added to the "dev" domain, they were
safely added by encrypting them with a key accessible only to Tom
right now.

But how did the secret get secured without requiring an authenticated
user?

### PocketProtector Secret Storage by Analogy

The best analogy for PocketProtector's internal domain security
mechanism comes from [the NaCl project](#), on top of which PocketProtector
is implemented.

Imagine you're a security-conscious community member, holding a letter
you'd like a select few of your neighbors to read.

You want them to securely read the notarized original, so they can be
as sure of the authenticity as you are. A copy simply won't
do. Because we can't make copies of the letter, how do we securely
ensure only specific neighbors read it?

One elegant solution is to put the letter in your own mailbox, and
make copies of your mailbox key. Then, put a copy of the key (with
instructions) into each of the neighbors' mailboxes.

PocketProtector uses a cryptographic approach known as two-key
encryption to implement this scheme. Every domain is a mailbox, and
only key custodians assigned to that domain are neighbors with a key
to that mailbox.

Another advantage of PocketProtector's scheme is that you don't have
to own the mailbox to put another letter in, just as we saw with our
[Adding Secrets](#adding-secrets) scenario, above. Domains are
community mailboxes, where only specific community members have access
to the contents.

Thus, PocketProtector provides read protection against leaks,
unintentional or otherwise, while relying on repository management
practices for write protection. Anyone with push rights to the repo
can add a key. In our analogy, only people in the building can drop
letters in the mailbox, but it's up to your team to control who can
get into the building (i.e., push to your repo).

Speaking of reads, let's check in on our scenario using some
PocketProtector's read subcommands.

## Reading a Protected

The first thing to recognize about protected files is that they are
designed for some degree of human readability. They are plaintext YAML
files that you can open in your editor of choice. You should see
something like this:

```
dev:
  secret-chat-api-key: ABpVkJKq6WgOgl0rQYDSB0zAjNGD1Gn4aEFmWthMd9l+hjz8rjBJYDm/guyeIVZOwj7m/TQPJNz/yw0D
  meta:
    public-key: AKKRHVwQcbLkk2yK7L3DWmTKzqYhlFuavNpdzl//hbk1
    owners:
      tom@example.com: ANrCtPEyppOZt7waOrW/GDQTd7+/tGTLJNqmtaxX8FhbYVsbPWVgSdvzVNEUVM3/bRFsfpw5GHmF93qVwqC7wUtNnIngp1qiDpGyN12iVHEZ
key-custodians:
  tom@example.com:
    pwdkm: ALLq2pN0MCqlQ3V0SAl7d71zeOd1D0vBzjZ6y5L5uK3TFMuDKe5uCAA=
audit-log:
- 2020-01-22T18:06:40Z -- created key custodian tom@example.com
- 2020-01-22T19:46:15Z -- created domain dev with owner tom@example.com
- 2020-01-22T19:46:38Z -- added secret chat-api-key in dev
```

All of the state PocketProtector needs to operate is included in this
file. Several of the text values should be recognizable from our
scenario above.

But there are more convenient ways to get access to the values
designed for external consumption. Let's take a look, with a file
that's had a couple more values added to it.

### Listing available domains

The first way to get acquainted with a protected is to list the
domains within the file.

```
$ pprotect list-domains
dev
prod
```

As we can see, Tom has added a `prod` domain in addition to the `dev`
one we created above. Many projects need to function in multiple
environments, and PocketProtector's domains are a natural way to
segment the different secrets used in each environment.

### Listing secrets within a given domain

If we know which domain we want to inspect, we can list its secrets
like so:

```
$ pprotect list-domain-secrets dev
chat-api-key
mail-api-key
```

It seems Tom has recently added a new key for mail integration, in
addition to the chat key we added above.

But just because a key is in one domain, doesn't mean it has to be in
all of them. Let's get an overview.

### Listing all secrets in a protected

Because domains can overlap and also diverge, it can be very useful to
get an overview of all the secrets contained in a protected. The
`list-all-secrets` subcommand gives a sorted list with each secret,
followed by a colon and a comma-separated list of domains that contain
that secret, like so:

```
$ pprotect list-all-secrets
chat-api-key: dev
mail-api-key: dev, prod
```

As we can see, that mail integration key is actually present for both
`dev` and `prod` domains, so Tom may have rush deployed that
integration already.

The actual values for these secrets may or may not be the same. In
practice none of them should be, but even if they were, inspecting the
file would not give any indication, because internally different
encryption keys are used for each domain.

### Listing activity on the protected file

So far we've focused on protected domains and secrets, but
PocketProtector also builds in one very useful metadata feature: The
audit log.

The audit log keeps a human readable list of operations performed on
the protected. You can see this in our full-text example above, but
you can also access it from the command line, one entry per line:

```
$ pprotect list-audit-log
2020-01-22T18:06:40Z -- created key custodian tom@example.com
2020-01-22T19:46:15Z -- created domain dev with owner tom@example.com
2020-01-22T19:46:38Z -- added secret chat-api-key in dev
2020-01-23T05:12:28Z -- created domain prod with owner tom@example.com
2020-01-23T05:13:22Z -- added secret mail-api-key in dev
2020-01-23T05:13:50Z -- added secret mail-api-key in prod
```

And here we can see how it all went down. The audit log is a pretty
good summary that should be used in conjunction with your source
control management tools. Using `git` as an example, `git log
protected.yaml` and `git blame protected.yaml` are both excellent
complements to the audit log.

The audit log is also completely supplementary. It can safely be
truncated without affecting any other PocketProtector functionality.

## Granting Domain Access

One of PocketProtector's biggest features is its distributed
design. Any action performed with PocketProtector only requires one
set of credentials, if it requires credentials at all. This enables
teams, local and remote, to securely share keys without requiring side
channels.

Back in our scenario, Engineer Alice needs to decrypt secrets from the
`dev` domain to configure her local environment. Right now, only CTO Tom
owns that domain. Tom can grant Alice access by adding her as an owner:

```
tom@tomtop $ pprotect add-owner
Verify credentials for /home/tom/work/project/protected.yaml
User email: tom@example.com
Passphrase:
Adding domain owner.
Domain name: dev
New owner email: alice@example.com
```

Alice must already be a key custodian in the protected (added via
`pprotect add-key-custodian`) before she can be made an owner. Once
added, Alice can decrypt any secret in the `dev` domain using her own
credentials.

Alice can check which domains and secrets she has access to:

```
alice@alicetop $ pprotect list-user-secrets -u alice@example.com
dev:
  chat-api-key
  mail-api-key
```

This is especially useful when you're a custodian on multiple projects
and want a quick overview of what you can access.


## Decrypting Secrets

Now that Alice owns the `dev` domain, she can decrypt its secrets.
By default, `decrypt-domain` outputs JSON:

```
alice@alicetop $ pprotect decrypt-domain dev
User email: alice@example.com
Passphrase:
{"chat-api-key": "abc5ca1ab1e", "mail-api-key": "m41l-k3y-v4lu3"}
```

### Output formats

The `--output-format` flag controls how secrets are printed:

```sh
# JSON (default)
pprotect decrypt-domain dev

# dotenv format: KEY="value"
pprotect decrypt-domain dev --output-format env

# Shell export format: export KEY="value"
eval $(pprotect decrypt-domain dev --output-format shell)
```

### Single secret extraction

Use `--secret` to extract one secret. Without `--output-format`, the
raw value is printed (no quotes, no key name) for easy use in scripts:

```sh
db_pass=$(pprotect decrypt-domain prod --secret db-pass)
```

With `--output-format json`, the value is wrapped in a single-key JSON
object instead.


## Running Applications with Secrets

The `exec` subcommand is the recommended way to pass secrets to an
application. It decrypts a domain and injects the secrets as environment
variables into a child process, without ever writing them to disk or
exposing them in the parent shell's environment:

```sh
pprotect exec --domain prod -- ./myapp --flag arg
```

Returning to our scenario, suppose Tom wants to deploy the service with
production secrets. He can start the service like this:

```
tom@tomtop $ pprotect exec --domain prod -- python run_service.py
User email: tom@example.com
Passphrase:
# The service starts with chat-api-key and mail-api-key
# injected as environment variables
```

### exec options

* `--domain DOMAIN` -- the domain to decrypt (required)
* `--prefix PREFIX` -- prepend `PREFIX_` to each secret's env var name.
  If a prefixed name collides with an existing variable, `exec` raises
  an error rather than silently overwriting.
* `--uppercase` -- convert secret names to `UPPER_CASE`, replacing
  non-alphanumeric characters with underscores. For example,
  `chat-api-key` becomes `CHAT_API_KEY`.
* `--no-passthrough` -- start the child with a minimal environment
  (`PATH`, `HOME`, `TERM`, `LANG`, `USER`, `SHELL`, `LOGNAME`) plus
  the decrypted secrets, rather than inheriting the full parent
  environment.

**Security note:** `exec` scrubs `PPROTECT_USER`, `PPROTECT_PASSPHRASE`,
`PPROTECT_ENV_PREFIX`, and any custom `--env-prefix` variables from the
child process environment.
On Unix, `exec` replaces the current process entirely (`os.execvpe`), so
the passphrase never lingers in a parent shell. On Windows, it uses
`subprocess.run` instead.


## Managing Credentials

### Changing your passphrase

Key custodians can change their passphrase at any time:

```
alice@alicetop $ pprotect set-key-custodian-passphrase
Verify credentials for /home/alice/work/project/protected.yaml
User email: alice@example.com
Current passphrase:
New passphrase:
Retype new passphrase:
```

This re-encrypts Alice's key material with the new passphrase. Her
access to all domains remains unchanged.

### Key types

PocketProtector supports three key derivation modes, selectable with
`--key-type` when creating a custodian or rekeying:

* **`hard`** (default) -- uses a slow, memory-intensive KDF (~0.8s,
  256 MB). Best for human passphrases in production.
* **`fast`** -- uses a lighter KDF (~0.1s, 64 MB). Suitable for
  development and testing where you unlock frequently.
* **`raw`** -- no KDF at all. PocketProtector generates a 256-bit
  random key displayed in the format `P<64 hex chars>P`. You must
  store this key securely (e.g., in a CI secret or vault). At creation
  time you are asked to type `YES` to confirm you have saved the key.

### Rekeying a custodian

The `rekey-custodian` command re-encrypts a custodian's key material
with a new passphrase and optionally a different key type. This is
useful when migrating from a human passphrase to an automated raw key
for CI/CD:

```sh
# Switch from hard (human passphrase) to raw (automation key)
pprotect rekey-custodian -u ci@example.com --key-type raw
```

The custodian email must match an existing custodian. All domain
ownerships are preserved -- only the passphrase encryption changes.


## Multi-Project and Automation Setup

### Custom environment variable prefix

In environments where multiple PocketProtector-managed projects coexist,
use `--env-prefix` to namespace credential environment variables per
project:

```sh
# Project A
export PROJECTA_USER=alice@example.com
export PROJECTA_PASSPHRASE=secret_a
pprotect decrypt-domain prod --env-prefix PROJECTA

# Project B (simultaneously)
export PROJECTB_USER=bob@example.com
export PROJECTB_PASSPHRASE=secret_b
pprotect decrypt-domain staging --env-prefix PROJECTB
```

The default prefix remains `PPROTECT`, so existing workflows are
unaffected.

To avoid repeating `--env-prefix` on every invocation, set the
`PPROTECT_ENV_PREFIX` environment variable:

```sh
export PPROTECT_ENV_PREFIX=PROJECTA
export PROJECTA_USER=alice@example.com
export PROJECTA_PASSPHRASE=secret_a
pprotect decrypt-domain prod   # uses PROJECTA_USER / PROJECTA_PASSPHRASE
```

The resolution order for the prefix is:

1. `--env-prefix` CLI flag (explicit wins)
2. `PPROTECT_ENV_PREFIX` environment variable
3. `PPROTECT` (hardcoded default)

### Credential sources

PocketProtector resolves credentials in this order:

1. **Command-line flags**: `-u / --user`, `--passphrase-file`
2. **Environment variables**: `PPROTECT_USER`, `PPROTECT_PASSPHRASE`
   (or custom prefix equivalents via `--env-prefix` /
   `PPROTECT_ENV_PREFIX`)
3. **Interactive prompt** (unless `--non-interactive` is set)

Flags take precedence over environment variables, and both bypass
interactive prompts. If an incorrect credential is passed,
PocketProtector does *not* fall back to other sources.

### File-based passphrases

For mount-based secret management (Docker secrets, Kubernetes mounted
volumes), use `--passphrase-file`:

```sh
pprotect decrypt-domain prod --passphrase-file /run/secrets/pp_pass
```

### Non-interactive mode

For CI/CD pipelines where no human is present, pass `--non-interactive`
to cause the command to fail immediately if credentials cannot be
resolved from flags or environment variables:

```sh
pprotect exec --domain prod --non-interactive -- ./deploy.sh
```


## Team Changes and Key Rotation

Teams change. People join, people leave, and PocketProtector handles
these transitions with a small set of targeted commands.

### Onboarding a new team member

When Engineer Bob joins the team, he needs to be set up as a key
custodian and granted access to the domains he'll work with:

```sh
# Bob creates his custodian identity
pprotect add-key-custodian

# Tom grants Bob ownership of the dev domain
pprotect add-owner --domain dev -u tom@example.com
```

### Migrating ownership

When CTO Tom goes on sabbatical, he can transfer all of his domain
ownerships to CEO Claire in one step:

```
tom@tomtop $ pprotect migrate-owner
User email: tom@example.com
Passphrase:
New owner email: claire@example.com
Migrating ownership of 2 domain(s): dev, prod
Confirm? [y/N]: y
```

`migrate-owner` adds the new owner to every domain currently owned by
the authenticated custodian. It does not remove the original owner --
that is a separate step.

### Offboarding a team member

When someone leaves the team, remove their ownership from each domain
and then rotate the domain keys:

```sh
# Remove Tom's ownership of dev and prod
pprotect rm-owner --domain dev -u alice@example.com
pprotect rm-owner --domain prod -u alice@example.com

# Rotate domain keys so Tom's old keys can no longer decrypt
pprotect rotate-domain-keys --domain dev -u claire@example.com
pprotect rotate-domain-keys --domain prod -u claire@example.com
```

`rotate-domain-keys` generates a new keypair for the domain and
re-encrypts all secrets and owner key shares. Only current owners
retain access after rotation. This should be done after any personnel
change involving someone who had domain access.

### Updating and removing secrets

Secrets change over time. When the chat API key is rotated by the
upstream provider, Alice can update it:

```
alice@alicetop $ pprotect update-secret
Domain name: dev
Secret name: chat-api-key
New secret value: n3w-k3y-v4lu3
```

To remove a secret that is no longer needed:

```
alice@alicetop $ pprotect rm-secret
Domain name: dev
Secret name: old-api-key
```

### Removing a domain

When an environment is decommissioned, remove the entire domain:

```sh
pprotect rm-domain --domain staging -u tom@example.com
```

This deletes the domain and all its secrets from the protected file.

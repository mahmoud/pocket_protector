Competitive Landscape
=====================

PocketProtector occupies a specific niche in the secret management
landscape. This page provides an honest comparison with other tools,
particularly those designed for the emerging agent-assisted development
workflow.


PocketProtector's approach
--------------------------

PocketProtector is a **serverless, in-repo, people-centric secret
management system**. Secrets are encrypted and stored in a single
``protected.yaml`` file that lives alongside application code in version
control.

Core design principles:

* **No infrastructure.** No daemon, no server, no SaaS account. The
  file *is* the system.
* **Multi-user, multi-domain.** Key custodians hold passphrases.
  Domains partition secrets by environment (dev/staging/prod). Anyone
  can *add* a secret; only authorized custodians can *read* them.
* **Cryptographically strong.** Argon2id KDF, Curve25519 two-key
  encryption, NaCl SealedBox. No custom crypto.
* **Git-native.** The file format is designed for ``git diff``,
  ``git blame``, ``git log``.
* **Audit log.** Human-readable, append-only log of all operations,
  stored in the same file.


The landscape
-------------

Six tools now compete in the "agent-secret management" space. They split
into three architectural families.


Family A: Local encrypted vault + broker daemon
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**HASP** (Rust, source-available FCL-1.0-ALv2) and **fnox** (Rust, MIT)
both maintain local encrypted vaults.

HASP provides an MCP tool surface that returns *references* (never
values) to the agent, brokered execution that resolves secrets at exec
time, output redaction across 11 encoding forms, and pre-commit/push
leak scanning. Its audit log uses chained HMACs for tamper evidence.

fnox provides a built-in MCP server with ``get_secret`` and ``exec``
tools, an allowlist controlling which secrets agents see, and support
for 20+ external secret providers (AWS Secrets Manager, 1Password,
Bitwarden, HashiCorp Vault, etc.). It includes Aho-Corasick output
redaction.

Key tradeoff: HASP never exposes secret values to the agent; fnox does
(if allowlisted) but catches accidental leaks via redaction.


Family B: HTTP credential proxy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**OneCLI** (TypeScript + Rust, Apache-2.0) and **Infisical Agent Vault**
(Go, MIT core) both operate as HTTPS MITM proxies.

The agent authenticates via ``HTTPS_PROXY`` and makes normal HTTP
requests. The proxy intercepts matching requests and injects credentials
at the network layer. The agent never sees the actual secret value.

Key tradeoff: True network-level isolation, but heavy infrastructure
(running services, CA trust chains, PostgreSQL or SQLite). Only works
for HTTP-based secrets. TLS certificate pinning breaks the proxy model.


Family C: Agent guardrails and identity
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Kontext CLI** (Go, MIT) and **Tailscale Aperture** (proprietary,
managed service) focus on identity, policy, and audit rather than secret
storage.

Kontext provides ML-powered risk scoring for agent tool use and optional
short-lived credential exchange via RFC 8693. Aperture provides
centralized identity, request/response capture, and SIEM/S3 export
tied to Tailscale's identity layer.

Key tradeoff: Strongest centralized audit and governance, but no local
secret storage and SaaS/infrastructure dependencies.


Capability matrix
-----------------

.. list-table::
   :header-rows: 1
   :widths: 30 10 10 10 10 10 10 10

   * - Capability
     - PP
     - HASP
     - fnox
     - OneCLI
     - Agent Vault
     - Kontext
     - Aperture
   * - Encrypted secrets in VCS
     - **Yes**
     - No
     - Partial
     - No
     - No
     - No
     - No
   * - No infrastructure required
     - **Yes**
     - Yes
     - Yes
     - No
     - No
     - Guard only
     - No
   * - Multi-user key custodians
     - **Yes**
     - No
     - No
     - No
     - No
     - No
     - No
   * - Agent can never see secret value
     - No
     - **Yes**
     - No
     - **Yes**
     - **Yes**
     - Partial
     - Partial
   * - MCP integration
     - No
     - Yes
     - Yes
     - No
     - No
     - No
     - No
   * - Brokered execution
     - ``exec``
     - ``run``
     - ``exec``
     - Proxy
     - Proxy
     - Exchange
     - Gateway
   * - Output redaction
     - No
     - **Yes**
     - Yes
     - N/A
     - N/A
     - Partial
     - N/A
   * - Repo leak scanning
     - No
     - **Yes**
     - No
     - No
     - No
     - Scoring
     - No
   * - Audit trail
     - Yes
     - Yes
     - No
     - Yes
     - Yes
     - Yes
     - Yes
   * - Grant time limits
     - No
     - Yes
     - No
     - Rate limit
     - Session
     - Session
     - Quotas
   * - Offline / air-gapped
     - **Yes**
     - **Yes**
     - **Yes**
     - No
     - Moderate
     - Guard only
     - No
   * - Python API
     - **Yes**
     - No
     - No
     - No
     - No
     - No
     - No


Threat model layers
-------------------

The 2026 agent-security landscape has crystallized around three threat
layers:

1. **Secret at rest in the repo.** An agent editing files can
   accidentally commit a credential. A compromised repo exposes the
   history.

2. **Secret in the agent's context window.** An agent that reads a
   ``.env`` file, decrypts a domain, or receives a secret via env var
   now has the value in its working memory. It can echo it, log it,
   or include it in a diff.

3. **Secret in transit at the API boundary.** An agent making API calls
   with real credentials can be tricked into calling the wrong endpoint
   or leaking the credential via a crafted redirect.

.. list-table::
   :header-rows: 1
   :widths: 30 12 12 12 12 12 12 12

   * - Threat Layer
     - PP
     - HASP
     - fnox
     - OneCLI
     - Agent Vault
     - Kontext
     - Aperture
   * - Secret at rest
     - **Strong**
     - **Strong**
     - Moderate
     - Weak
     - Weak
     - Weak
     - Weak
   * - Secret in agent context
     - Weak
     - **Strong**
     - Moderate
     - **Strong**
     - **Strong**
     - Moderate
     - Moderate
   * - Secret in transit
     - None
     - Moderate
     - None
     - **Strong**
     - **Strong**
     - Moderate
     - **Strong**


Where PocketProtector fits
--------------------------

PocketProtector occupies a **foundational layer** that the newer tools
do not replace::

   +---------------------------------------------------+
   |  Layer 3: Runtime Governance                      |
   |  (Aperture, Kontext -- identity, policy,          |
   |   central audit, team dashboards)                 |
   +---------------------------------------------------+
   |  Layer 2: Agent-Invisible Delivery                |
   |  (HASP broker, Agent Vault proxy, OneCLI proxy,   |
   |   fnox MCP exec -- keeping values out of agent    |
   |   context windows and output streams)             |
   +---------------------------------------------------+
   |  Layer 1: Secret Storage & Access Control         |
   |  (PocketProtector -- encrypted at rest, multi-    |
   |   user, git-native, serverless, Python API)       |
   +---------------------------------------------------+

**PocketProtector is Layer 1.** It is the strongest tool in this
landscape for *storing* and *collaboratively managing* secrets in a
serverless, git-native, cryptographically-principled way.

The newer entrants are mostly Layer 2 tools that have bolted on their
own (often weaker) Layer 1. HASP's vault is single-user with no
custodian model. fnox defers to 20 external providers. Agent Vault and
OneCLI use AES-GCM in SQLite/PostgreSQL with no multi-party key
management.


What PocketProtector does that nobody else does
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. **Cryptographic multi-party access control.** Domains are
   cryptographic boundaries, not configuration toggles.
2. **True serverless, zero-dependency secret storage.** No daemon, no
   database, no binary dependency beyond Python + pip.
3. **Git-native change management.** The file format is designed for
   VCS workflows.
4. **Python-native API.** ``KeyFile.decrypt_domain()`` is a one-liner.
5. **Audit log in the same file.** No separate log infrastructure.


Honest gaps
~~~~~~~~~~~

1. **No agent-invisible delivery.** ``pprotect exec`` injects secrets
   as env vars. A process with shell access can still read them.
2. **No output redaction.** If a secret appears in a traceback or log,
   PocketProtector does not catch it.
3. **No repo leak scanning.** No pre-commit hook to detect accidentally
   committed secrets.
4. **No MCP integration.** No MCP server (explicit non-goal).
5. **No grant time limits.** Access is permanent until the passphrase is
   changed or the owner is removed.


When to use PocketProtector
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use PocketProtector when you want:

* Serverless secret management with no infrastructure to operate
* Git-native workflows where secret changes are commits
* Multi-user access control with cryptographic enforcement
* A Python API for programmatic secret management
* Offline and air-gapped operation


When to complement it
~~~~~~~~~~~~~~~~~~~~~

Pair PocketProtector with a Layer 2 tool when:

* AI agents need secrets but should never see the values
* You need output redaction to catch accidental leaks
* You need repo scanning to prevent committed secrets
* You need time-limited grants or session-scoped access

PocketProtector's ``pprotect decrypt-domain --output-format json``
produces output suitable for consumption by broker tools. A
``pprotect exec`` that launches through a broker lets PocketProtector
remain the storage and collaboration layer while gaining
agent-invisible delivery.

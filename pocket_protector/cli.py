# -*- coding: utf-8 -*-
"""
pocket_protector

People-centric secret management system, built to work with modern distributed version control systems.
"""
# Note that the doc above is part of "pprotect -h" output, add to it wisely.

import os
import re
import sys
import json
import shlex
import difflib
from dataclasses import dataclass

from face import Command, CommandGroup, Flag, face_middleware, CommandLineError, UsageError, echo, prompt

from . import __version__
from .file_keys import KeyFile, Creds, PPError

_ANSI_FORE_RED = '\x1b[31m'
_ANSI_FORE_GREEN = '\x1b[32m'
_ANSI_RESET_ALL = '\x1b[0m'

DEFAULT_ENV_PREFIX = 'PPROTECT'


def _env_var_names(prefix):
    """Return (user_var, passphrase_var) for a given prefix."""
    return (prefix + '_USER', prefix + '_PASSPHRASE')

# TODO: custodian-signed values. allow custodians to sign values
# added/set by others, then produced reports on which secrets have been
# updated/changed but not signed yet. enables a review/audit mechanism.
def _create_protected(path):
    if os.path.exists(path):
        raise UsageError('Protected file already exists: %s' % path, 2)
    open(path, 'wb').close()
    kf = KeyFile.create(path=path)
    kf.write()
    return kf


def _ensure_protected(path):
    if not os.path.exists(path):
        raise UsageError('Protected file not found: %s' % path, 2)
    kf = KeyFile.from_file(path)
    return kf


def _get_colorized_lines(lines):
    ret = []
    colors = {'-': _ANSI_FORE_RED, '+': _ANSI_FORE_GREEN}
    for line in lines:
        if line[0] in colors:
            line = colors[line[0]] + line + _ANSI_RESET_ALL
        ret.append(line)
    return ret


def _get_new_creds(confirm=True):
    user_id = prompt('User email: ')
    passphrase = prompt.secret('Passphrase: ', confirm=confirm)
    ret = Creds(user_id, passphrase)
    return ret



@dataclass
class EnvVars:
    """Parsed environment variables from a .env file, text, or direct construction.

    Supports dict-style ``in`` and ``[]`` lookups on the underlying vars.
    """
    vars: dict
    source: str = ''

    def __contains__(self, key):
        return key in self.vars

    def __getitem__(self, key):
        return self.vars[key]

    def __bool__(self):
        return bool(self.vars)

    @classmethod
    def from_text(cls, text, source=''):
        """Parse .env-formatted text into an EnvVars instance.

        Supports KEY=VALUE, ``export`` prefix, ``#`` comments, blank lines,
        single/double quoted values, and ``=`` in values.
        """
        result = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('export '):
                line = line[7:].lstrip()
            if '=' not in line:
                continue
            key, _, value = line.partition('=')
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            result[key] = value
        return cls(vars=result, source=source)

    @classmethod
    def from_file(cls, path):
        """Read and parse a .env file."""
        with open(path) as f:
            return cls.from_text(f.read(), source=path)


def _resolve_env_file(kf_path, env_file, no_env_file):
    """Resolve and parse a .env file for credential lookup.

    Returns an EnvVars instance, or None if no file applies.
    Raises UsageError if --env-file points to a missing file.
    """
    if no_env_file:
        return None
    if env_file:
        env_file = os.path.abspath(env_file)
        if not os.path.isfile(env_file):
            raise UsageError('env file not found: %s' % env_file)
        return EnvVars.from_file(env_file)
    # auto-discover .env next to the protected file
    candidate = os.path.join(os.path.dirname(kf_path), '.env')
    if os.path.isfile(candidate):
        return EnvVars.from_file(candidate)
    return None


def _get_creds(kf,
               user=None,
               interactive=True,
               check_env=True,
               passphrase_file=None,
               user_env_var='PPROTECT_USER',
               pass_env_var='PPROTECT_PASSPHRASE',
               env_file_vars=None):
    if not interactive and not check_env:
        raise UsageError('expected at least one of check_env'
                         ' and interactive to be True', 2)
    user_source = 'argument'
    passphrase, passphrase_source = None, None
    if passphrase_file:
        passphrase_file = os.path.abspath(passphrase_file)
        try:
            passphrase = open(passphrase_file, 'rb').read().decode('utf8').strip()
        except IOError as ioe:
            if getattr(ioe, 'strerror', None):
                msg = '%s while reading passphrase from file at "%s"' % (ioe.strerror, passphrase_file)
            else:
                msg = 'Failed to read passphrase from file at "%s"' % passphrase_file
            raise UsageError(msg=msg)
        else:
            passphrase_source = "passphrase file: %s" % passphrase_file
    if user is None and user_env_var:
        user = os.getenv(user_env_var)
        user_source = 'env var: %s' % user_env_var
    if passphrase is None and pass_env_var:
        passphrase = os.getenv(pass_env_var)
        passphrase_source = 'env var: %s' % pass_env_var

    # .env file fallback (below real env, above interactive prompt)
    if user is None and env_file_vars and user_env_var in env_file_vars:
        user = env_file_vars[user_env_var]
        user_source = 'env file: %s' % user_env_var
    if passphrase is None and env_file_vars and pass_env_var in env_file_vars:
        passphrase = env_file_vars[pass_env_var]
        passphrase_source = 'env file: %s' % pass_env_var

    if interactive:
        msg = ''
        if user is None:
            msg = 'Verify credentials for %s' % kf.path
        elif passphrase is None:
            msg = 'Verify passphrase for %s (Using user %s from %s)' % (kf.path, user, user_source)
        if msg:
            echo.err(msg)

        if user is None:
            user = prompt('User email: ')
            user_source = 'stdin'
        if passphrase is None:
            passphrase = prompt.secret('Passphrase: ', confirm=False)
            passphrase_source = 'stdin'

    creds = Creds(user or '', passphrase or '',
                  name_source=user_source, passphrase_source=passphrase_source)
    _check_creds(kf, creds)

    return creds


def _check_creds(kf, creds):
    if kf.check_creds(creds):
        return True

    msg = 'Invalid user email'
    if creds.name_source:
        msg += ' (from %s)' % creds.name_source
    msg += ' or passphrase'
    if creds.passphrase_source:
        msg += ' (from %s)' % creds.passphrase_source
    msg += '. Check credentials and try again.'
    empty_fields = []
    if creds.name == '':
        empty_fields.append('user ID')
    if creds.passphrase == '':
        empty_fields.append('passphrase')
    if empty_fields:
        msg += ' (Warning: Empty ' + ' and '.join(empty_fields) + '.)'

    raise UsageError(msg, 1)


def _get_cmd(prepare=False):
    cmd = Command(name='pocket_protector', func=None, doc=__doc__)  # func=None means output help

    # add flags
    cmd.add('--file', missing='protected.yaml',
            doc='path to the PocketProtector-managed file, defaults to protected.yaml in the working directory')
    cmd.add('--confirm', parse_as=True,
            doc='show diff and prompt for confirmation before modifying the file')
    cmd.add('--non-interactive', parse_as=True,
            doc='disable falling back to interactive authentication, useful for automation')
    cmd.add('--ignore-env', parse_as=True, display=False,  # TODO: keep?
            doc='ignore credential environment variables (e.g., PPROTECT_PASSPHRASE)')
    cmd.add('--user', char='-u',
            doc="the acting user's email credential")
    cmd.add('--passphrase-file',
            doc='path to a file containing only the passphrase, likely provided by a deployment system')
    cmd.add('--key-type',
            doc='custodian key type: hard (default, slow KDF), fast (quick KDF), or raw (no KDF, generated key)')
    cmd.add('--output-format',
            doc='output format for decrypt-domain: json (default), env, or shell')
    cmd.add('--secret',
            doc='decrypt a single secret by name (decrypt-domain only)')
    cmd.add('--domain',
            doc='domain name (used by exec subcommand)')
    cmd.add('--prefix',
            doc='prefix to prepend to secret env var names (exec only)')
    cmd.add('--uppercase', parse_as=True,
            doc='convert secret names to UPPER_CASE env var names (exec only)')
    cmd.add('--no-passthrough', parse_as=True,
            doc='exec with clean env: secrets + PATH/HOME/TERM/LANG only')
    cmd.add('--env-prefix', missing=os.getenv('PPROTECT_ENV_PREFIX', DEFAULT_ENV_PREFIX),
            doc='env var prefix for USER and PASSPHRASE credentials'
                ' (default: PPROTECT, overridable via PPROTECT_ENV_PREFIX env var)')
    cmd.add('--env-file',
            doc='path to a .env file for credential env vars (default: .env next to protected file)')
    cmd.add('--no-env-file', parse_as=True,
            doc='suppress automatic .env file discovery')

    # add middlewares, outermost first ("first added, first called")
    cmd.add(mw_verify_creds)
    cmd.add(mw_write_kf)
    cmd.add(mw_ensure_kf)
    cmd.add(mw_exit_handler)

    # bare (ungrouped) subcommands
    cmd.add(add_key_custodian, name='init', doc='create a new protected')
    cmd.add(print_version, name='version')
    cmd.add(list_audit_log)

    # Access Management (create, list, update, misc, delete)
    access = CommandGroup('Access Management')
    access.add(add_key_custodian)
    access.add(list_user_secrets)
    access.add(set_key_custodian_passphrase)
    access.add(rekey_custodian)
    cmd.add(access)

    # Domain Management (create, list, read, update, misc, delete)
    domains = CommandGroup('Domain Management')
    domains.add(add_domain)
    domains.add(add_owner)
    domains.add(list_domains)
    domains.add(rotate_domain_keys)
    domains.add(migrate_owner)
    domains.add(rm_owner)
    domains.add(rm_domain)
    cmd.add(domains)

    # Secret Management (create, list, update, delete)
    secrets = CommandGroup('Secret Management')
    secrets.add(add_secret)
    secrets.add(list_domain_secrets, posargs={'count': 1, 'provides': 'domain_name'})
    secrets.add(list_all_secrets)
    secrets.add(update_secret)
    secrets.add(rm_secret)
    cmd.add(secrets)

    # Secret Access (read, misc)
    secret_access = CommandGroup('Secret Access')
    secret_access.add(decrypt_domain, posargs={'count': 1, 'provides': 'domain_name'})
    secret_access.add(exec_command, name='exec', post_posargs=True)
    cmd.add(secret_access)

    if prepare:
        cmd.prepare()  # an optional check on all subcommands, not just the one being executed

    return cmd


def main(argv=None):  # pragma: no cover  (see note in tests.test_cli.test_main)
    cmd = _get_cmd()

    cmd.run(argv=argv)  # exit behavior is handled by mw_exit_handler

    return


"""
The following subcommand handlers all update/write to a protected file (wkf).
"""

_KEY_TYPES = ('hard', 'fast', 'raw')


def _validate_key_type(key_type):
    if key_type and key_type not in _KEY_TYPES:
        raise UsageError('--key-type must be one of: %s' % ', '.join(_KEY_TYPES))
    return key_type


def _show_raw_key_and_confirm(passphrase):
    '''Display a generated raw key and require YES confirmation. Returns True if confirmed.'''
    echo('')
    echo('=' * 72)
    echo('  GENERATED RAW KEY (copy this now, it will not be shown again):')
    echo('')
    echo('  ' + passphrase)
    echo('')
    echo('  Store this key securely. It is your passphrase.')
    echo('  LOSS OF THIS KEY MEANS LOSS OF CUSTODIAN ACCESS.')
    echo('=' * 72)
    echo('')
    confirm = prompt('Have you saved the key? Type YES to confirm: ')
    return confirm.strip() == 'YES'


def add_key_custodian(wkf, key_type=None):
    'add a new key custodian to the protected'
    from .file_keys import KDF_INTERACTIVE, generate_raw_passphrase
    key_type = _validate_key_type(key_type)
    echo('Adding new key custodian.')
    if key_type == 'raw':
        user_id = prompt('User email: ')
        passphrase = generate_raw_passphrase()
        if not _show_raw_key_and_confirm(passphrase):
            echo('Aborting. Key was not confirmed.')
            return None
        creds = Creds(user_id, passphrase)
        return wkf.add_raw_key_custodian(creds)
    creds = _get_new_creds()
    if key_type == 'fast':
        return wkf.add_key_custodian(creds, opslimit=KDF_INTERACTIVE[0], memlimit=KDF_INTERACTIVE[1])
    return wkf.add_key_custodian(creds)


def add_domain(wkf, creds):
    'add a new domain to the protected'
    echo('Adding new domain.')
    domain_name = prompt('Domain name: ')

    return wkf.add_domain(domain_name, creds.name)


def rm_domain(wkf):
    'remove a domain and all of its keys from the protected'
    echo('Removing domain.')
    domain_name = prompt('Domain name: ')
    return wkf.rm_domain(domain_name)


def add_owner(wkf, creds):
    'add a key custodian to the owner list of a specific domain'
    echo('Adding domain owner.')
    domain_name = prompt('Domain name: ')
    new_owner_name = prompt('New owner email: ')
    return wkf.add_owner(domain_name, new_owner_name, creds)


def rm_owner(wkf):
    'remove a key custodian from the owner list of a domain'
    echo('Removing domain owner.')
    domain_name = prompt('Domain name: ')
    owner_name = prompt('Owner email: ')
    return wkf.rm_owner(domain_name, owner_name)


def add_secret(wkf):
    'add a secret to a domain'
    echo('Adding secret value.')
    domain_name = prompt('Domain name: ')
    secret_name = prompt('Secret name: ')
    secret_value = prompt('Secret value: ')
    return wkf.add_secret(domain_name, secret_name, secret_value)


def update_secret(wkf):
    'update a secret value in a domain'
    echo('Updating secret value.')
    domain_name = prompt('Domain name: ')
    secret_name = prompt('Secret name: ')
    secret_value = prompt('Secret value: ')
    return wkf.update_secret(domain_name, secret_name, secret_value)


def rm_secret(wkf):
    'remove a secret from a domain'
    echo('Updating secret value.')
    domain_name = prompt('Domain name: ')
    secret_name = prompt('Secret name: ')
    return wkf.rm_secret(domain_name, secret_name)


def set_key_custodian_passphrase(wkf, key_type=None):
    'update a key custodian passphrase'
    from .file_keys import KDF_INTERACTIVE
    key_type = _validate_key_type(key_type)
    user_id = prompt('User email: ')
    passphrase = prompt.secret('Current passphrase: ')
    creds = Creds(user_id, passphrase)
    _check_creds(wkf, creds)
    new_passphrase = prompt.secret('New passphrase: ', confirm=True)
    if key_type == 'fast':
        return wkf.set_key_custodian_passphrase(creds, new_passphrase, opslimit=KDF_INTERACTIVE[0], memlimit=KDF_INTERACTIVE[1])
    return wkf.set_key_custodian_passphrase(creds, new_passphrase)


def rekey_custodian(wkf, key_type=None):
    'change a custodian key type (hard/fast/raw) and passphrase, re-encrypting all owned domains'
    from .file_keys import KDF_INTERACTIVE, generate_raw_passphrase
    key_type = _validate_key_type(key_type) or 'hard'
    user_id = prompt('User email: ')
    passphrase = prompt.secret('Current passphrase: ')
    creds = Creds(user_id, passphrase)
    _check_creds(wkf, creds)
    if key_type == 'raw':
        new_passphrase = generate_raw_passphrase()
        if not _show_raw_key_and_confirm(new_passphrase):
            echo('Aborting. Key was not confirmed.')
            return None
        new_creds = Creds(creds.name, new_passphrase)
        return wkf.rekey_custodian(creds, new_creds, raw_key=True)
    new_passphrase = prompt.secret('New passphrase: ', confirm=True)
    new_creds = Creds(creds.name, new_passphrase)
    if key_type == 'fast':
        return wkf.rekey_custodian(creds, new_creds, opslimit=KDF_INTERACTIVE[0], memlimit=KDF_INTERACTIVE[1])
    return wkf.rekey_custodian(creds, new_creds)


def rotate_domain_keys(wkf, creds):
    'rotate the internal encryption keys for a given domain'
    domain_name = prompt('Domain name: ')
    return wkf.rotate_domain_key(domain_name, creds)


def migrate_owner(wkf, creds):
    'grant a custodian ownership of all domains you own'
    new_owner = prompt('New owner email: ')
    owned = wkf.get_custodian_domains(creds.name)
    if not owned:
        echo('You do not own any domains.')
        return None
    echo('Will add %s as owner to: %s' % (new_owner, ', '.join(sorted(owned))))
    confirm = prompt('Proceed? [y/N] ')
    if not confirm.lower().startswith('y'):
        echo('Aborting.')
        return None
    return wkf.migrate_owner(new_owner, creds)



_VALID_SHELL_IDENTIFIER = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')

_OUTPUT_FORMATS = ('json', 'env', 'shell')


def _validate_output_format(output_format):
    if output_format is not None and output_format not in _OUTPUT_FORMATS:
        raise UsageError('--output-format must be one of: %s' % ', '.join(_OUTPUT_FORMATS))
    return output_format


def _format_secret_env(name, value):
    """Format a single name=value pair, shell-safe via single-quoting."""
    return '%s=%s' % (name, shlex.quote(value))


"""
Read-only operations follow
"""

def print_version():
    'print the PocketProtector version and exit'
    echo('pocket_protector version %s' % __version__)
    sys.exit(0)


def decrypt_domain(kf, creds, domain_name, output_format=None, secret=None):
    'decrypt and display cleartext for a domain, with optional format and secret filter'
    output_format = _validate_output_format(output_format)
    decrypted_dict = kf.decrypt_domain(domain_name, creds)

    if secret is not None:
        if secret not in decrypted_dict:
            raise UsageError('secret %r not found in domain %r' % (secret, domain_name))

    # Default format: json, unless --secret without explicit --output-format → raw value
    if output_format is None:
        if secret is not None:
            echo(decrypted_dict[secret])
        else:
            echo(json.dumps(decrypted_dict, indent=2, sort_keys=True))
    elif output_format == 'json':
        if secret is not None:
            echo(json.dumps({secret: decrypted_dict[secret]}, indent=2, sort_keys=True))
        else:
            echo(json.dumps(decrypted_dict, indent=2, sort_keys=True))
    elif output_format in ('env', 'shell'):
        prefix = 'export ' if output_format == 'shell' else ''
        items = {secret: decrypted_dict[secret]} if secret else decrypted_dict
        for name in sorted(items):
            if not _VALID_SHELL_IDENTIFIER.match(name):
                raise UsageError('%r is not a valid shell identifier;'
                                 ' cannot safely represent in env/shell format' % name)
            echo(prefix + _format_secret_env(name, items[name]))

    return 0


# Minimal env vars preserved when --no-passthrough is used
_PASSTHROUGH_VARS = ('PATH', 'HOME', 'TERM', 'LANG', 'USER', 'SHELL', 'LOGNAME')

# Env vars scrubbed from the child process unconditionally
_SCRUBBED_VARS = ('PPROTECT_PASSPHRASE', 'PPROTECT_USER', 'PPROTECT_ENV_PREFIX')


def _transform_secret_name(name, prefix=None, uppercase=False):
    """Apply prefix and/or uppercase transformation to a secret name."""
    if uppercase:
        name = re.sub(r'[^A-Za-z0-9]', '_', name).upper()
    if prefix:
        name = prefix + '_' + name
    return name


def _build_exec_env(decrypted_dict, prefix=None, uppercase=False,
                    no_passthrough=False, base_env=None, env_prefix=DEFAULT_ENV_PREFIX):
    """Build the child process environment for exec.

    Returns a dict of env vars: decrypted secrets (optionally transformed)
    injected into either a passthrough or minimal base environment, with
    credential vars always scrubbed.
    """
    if base_env is None:
        base_env = os.environ

    # Build secret env vars with optional name transformations
    secret_env = {}
    for name, value in decrypted_dict.items():
        env_name = _transform_secret_name(name, prefix=prefix, uppercase=uppercase)
        if env_name in secret_env:
            raise UsageError(
                'secret name collision after transformation: %r and a prior secret both map to %r'
                % (name, env_name))
        secret_env[env_name] = value

    # Build the child environment
    if no_passthrough:
        child_env = {k: base_env[k] for k in _PASSTHROUGH_VARS if k in base_env}
    else:
        child_env = dict(base_env)

    # Always scrub default PPROTECT_* plus any custom prefix vars
    scrub_vars = set(_SCRUBBED_VARS)
    if env_prefix != DEFAULT_ENV_PREFIX:
        custom_user, custom_pass = _env_var_names(env_prefix)
        scrub_vars.add(custom_user)
        scrub_vars.add(custom_pass)
    for var in scrub_vars:
        child_env.pop(var, None)

    # Inject decrypted secrets (after scrub, so secrets named PPROTECT_* still work)
    child_env.update(secret_env)

    return child_env


def exec_command(kf, creds, domain, post_posargs_,
                 prefix=None, uppercase=False, no_passthrough=False,
                 env_prefix=DEFAULT_ENV_PREFIX):
    'run a command with decrypted domain secrets injected as environment variables'
    if not domain:
        raise UsageError('--domain is required for exec')
    if not post_posargs_:
        raise UsageError('exec requires a command after -- (e.g. pprotect exec --domain prod -- ./myapp)')

    decrypted_dict = kf.decrypt_domain(domain, creds)
    child_env = _build_exec_env(decrypted_dict, prefix=prefix, uppercase=uppercase,
                                no_passthrough=no_passthrough, env_prefix=env_prefix)

    cmd_args = list(post_posargs_)
    executable = cmd_args[0]

    # Use os.execvpe to replace the current process (Unix).
    # On Windows, fall back to subprocess since execvpe behavior differs.
    if sys.platform == 'win32':
        import subprocess
        result = subprocess.run(cmd_args, env=child_env)
        sys.exit(result.returncode)
    else:
        os.execvpe(executable, cmd_args, child_env)

def list_domains(kf):
    'print a list of domain names, if any'
    domain_names = kf.get_domain_names()
    if domain_names:
        echo('\n'.join(domain_names))
    else:
        echo.err('(No domains in protected at %s)' % kf.path)
    return


def list_domain_secrets(kf, domain_name):
    'print a list of secret names for a given domain'
    secret_names = kf.get_domain_secret_names(domain_name)
    if secret_names:
        echo('\n'.join(secret_names))
    else:
        echo.err('(No secrets in domain %r of protected at %s)'
                 % (domain_name, kf.path))
    return


def list_all_secrets(kf):
    'print a list of all secret names, along with the domains that define each'
    secrets_map = kf.get_all_secret_names()
    if not secrets_map:
        echo.err('(No secrets in protected at %s)' % kf.path)
    else:
        for secret_name in sorted(secrets_map):
            domain_names = sorted(set(secrets_map[secret_name]))
            echo('%s: %s' % (secret_name, ', '.join(domain_names)))
    return


def list_audit_log(kf):
    'print a list of actions from the audit log, one per line'
    log_list = kf.get_audit_log()
    echo('\n'.join(log_list))
    return


def list_user_secrets(kf, creds):
    'display domains and secrets accessible to the authenticated user'
    owned = kf.get_custodian_domains(creds.name)
    if not owned:
        echo.err('User %s does not own any domains.' % creds.name)
        return
    for domain_name in sorted(owned):
        secrets = kf.get_domain_secret_names(domain_name)
        echo('%s: %s' % (domain_name, ', '.join(secrets) if secrets else '(no secrets)'))
    return


"""
End subcommand handlers

Begin middlewares
"""


@face_middleware(provides=['creds'], optional=True)
def mw_verify_creds(next_, kf, user, ignore_env, non_interactive,
                    passphrase_file, env_prefix, env_file, no_env_file):
    env_file_vars = {} if ignore_env else _resolve_env_file(kf.path, env_file, no_env_file)
    user_var, pass_var = _env_var_names(env_prefix)
    creds = _get_creds(kf, user,
                       check_env=not ignore_env,
                       interactive=not non_interactive,
                       passphrase_file=passphrase_file,
                       user_env_var=user_var,
                       pass_env_var=pass_var,
                       env_file_vars=env_file_vars)
    return next_(creds=creds)


@face_middleware(provides=['kf'], optional=True)
def mw_ensure_kf(next_, file, subcmds_):
    file_path = file or 'protected.yaml'
    file_abs_path = os.path.abspath(file_path)
    init_kf = subcmds_[0] == 'init'
    if init_kf:
        kf = _create_protected(file_abs_path)
    else:
        kf = _ensure_protected(file_abs_path)

    try:
        ret = next_(kf=kf)
    except:
        if init_kf:
            try:
                os.unlink(file_abs_path)
            except Exception:
                echo.err('Warning: failed to remove file: %s' % file_abs_path)
        raise

    return ret


@face_middleware(provides=['wkf'], optional=True)
def mw_write_kf(next_, kf, confirm):
    if not os.access(kf.path, os.W_OK):
        raise UsageError('expected %r to be a writable file. Check the'
                         ' permissions and try again.' % kf.path)

    modified_kf = next_(wkf=kf)

    if not modified_kf:
        return modified_kf

    if confirm:
        diff_lines = list(difflib.unified_diff(kf.get_contents().splitlines(),
                                               modified_kf.get_contents().splitlines(),
                                               kf.path + '.old', kf.path + '.new'))
        diff_lines = _get_colorized_lines(diff_lines)
        echo('Changes to be written:\n')
        echo('\n'.join(diff_lines) + '\n')
        do_write = prompt('Write changes? [y/N] ')
        if not do_write.lower().startswith('y'):
            echo('Aborting...')
            sys.exit(0)

    modified_kf.write()

    return


@face_middleware
def mw_exit_handler(next_):
    status = 55  # should always be set to something else
    try:
        try:
            status = next_() or 0
        except PPError as ppe:
            raise UsageError(ppe.args[0])
    except KeyboardInterrupt:
        echo('')
        status = 130
    except EOFError:
        echo('')
        status = 1

    sys.exit(status)

    return

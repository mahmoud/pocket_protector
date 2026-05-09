import os
import json
import subprocess
import shlex
import sys

import ruamel.yaml
from face import CommandChecker

from pocket_protector import cli


def _fwd(path):
    """Forward-slash path string, safe for shlex.split on all platforms."""
    return str(path).replace('\\', '/')


def test_prepare():
    # confirms that all subcommands compile together nicely
    assert cli._get_cmd(prepare=True)
    return


KURT_EMAIL = 'kurt@example.com'
KURT_PHRASE = 'passphrasë'
MH_EMAIL = 'mahmoud@hatnote.com'
MH_PHRASE = 'thegame'
DOMAIN_NAME = 'first-domain'
SECRET_NAME = 'secret-name'
SECRET_VALUE = 'secrët-value'



# _fast_crypto from conftest
def test_cli(tmp_path, _fast_crypto):
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)

    assert cc.run('pprotect version').stdout.startswith('pocket_protector version')

    protected_path = _fwd(tmp_path / 'protected.yaml')

    # fail init and ensure that file isn't created
    cc.fail_1('pprotect init --file %s' % protected_path,
              input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE + 'nope'])
    assert not os.path.exists(protected_path)

    # successfully create protected
    res = cc.run('pprotect init --file %s' % protected_path,
                 input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    assert res.stdout == 'Adding new key custodian.\nUser email: '
    assert res.stderr == 'Passphrase: Retype passphrase: '

    # check we can only create it once
    res = cc.fail_2('pprotect init --file %s' % protected_path,
                    input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])

    file_data = ruamel.yaml.YAML().load(open(protected_path).read())
    assert list(file_data['key-custodians'])[0] == KURT_EMAIL
    assert len(file_data['audit-log']) == 2

    res = cc.run('pprotect list-audit-log --file %s' % protected_path)
    audit_lines = res.stdout.splitlines()
    assert len(audit_lines) == 2
    assert 'created' in audit_lines[0]

    # make a new cc, with env and tmp_path baked in (also tests
    # protected.yaml in the cur dir being the default file)
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)

    res = cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    assert 'Adding new domain.' in res.stdout

    res = cc.run(['pprotect', 'list_domains'])
    assert res.stdout.splitlines() == [DOMAIN_NAME]

    cc.run(['pprotect', 'add-secret'],
           input=[DOMAIN_NAME, SECRET_NAME, 'tmpval'])
    cc.run(['pprotect', 'update-secret'],
           input=[DOMAIN_NAME, SECRET_NAME, SECRET_VALUE])
    res = cc.run(['pprotect', 'list-domain-secrets', DOMAIN_NAME])
    assert res.stdout == SECRET_NAME + '\n'

    res = cc.run(['pprotect', 'decrypt-domain', DOMAIN_NAME])
    res_data = json.loads(res.stdout)
    assert res_data[SECRET_NAME] == SECRET_VALUE

    cc.fail(['pprotect', 'decrypt-domain', 'nonexistent-domain'])

    # already exists
    cc.fail_1('pprotect add-key-custodian', input=[KURT_EMAIL, ''])

    cc.run('pprotect add-key-custodian', input=[MH_EMAIL, MH_PHRASE, MH_PHRASE])

    cc.run('pprotect add-owner', input=[DOMAIN_NAME, MH_EMAIL])

    # missing protected
    cc.fail_2('pprotect list-all-secrets', chdir=str(tmp_path.parent))

    res = cc.run('pprotect list-all-secrets')
    assert '{}: {}\n'.format(SECRET_NAME, DOMAIN_NAME) == res.stdout

    cc.run(['pprotect', 'rotate_domain_keys'], input=[DOMAIN_NAME])


    # test mixed env var and entry
    res = cc.run(['pprotect', 'decrypt-domain', DOMAIN_NAME],
                 env={'PPROTECT_USER': MH_EMAIL, 'PPROTECT_PASSPHRASE': None},
                 input=[MH_PHRASE])
    assert json.loads(res.stdout)[SECRET_NAME] == SECRET_VALUE
    assert 'Verify passphrase' in res.stderr

    # test bad creds
    cc.fail_1(['pprotect', 'decrypt-domain', DOMAIN_NAME],
              env={'PPROTECT_USER': None, 'PPROTECT_PASSPHRASE': 'nope'},
              input=[KURT_EMAIL])

    res = cc.fail_1('pprotect set-key-custodian-passphrase',
                    input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE, KURT_PHRASE + 'nope'])
    assert 'did not match' in res.stderr

    # correctly reset passphrase
    new_kurt_phrase = KURT_PHRASE + 'yep'
    res = cc.run('pprotect set-key-custodian-passphrase',
                 input=[KURT_EMAIL, KURT_PHRASE, new_kurt_phrase, new_kurt_phrase])

    # try new passphrase with a passphrase file why not
    ppfile_path = _fwd(tmp_path / 'tmp_passphrase')
    with open(ppfile_path, 'wb') as f:
        f.write(new_kurt_phrase.encode('utf8'))
    res = cc.run(['pprotect', 'decrypt-domain', '--non-interactive',
                  '--passphrase-file', ppfile_path, DOMAIN_NAME])

    res_data = json.loads(res.stdout)
    assert res_data[SECRET_NAME] == SECRET_VALUE

    # test mutual exclusivity of check env and interactive
    cc.fail_2(['pprotect', 'decrypt-domain',
               '--non-interactive', '--ignore-env', DOMAIN_NAME])

    res = cc.fail_1('pprotect decrypt-domain --non-interactive ' + DOMAIN_NAME,
                    env={'PPROTECT_PASSPHRASE': None})
    assert 'Warning: Empty passphrase' in res.stderr

    # print(open(protected_path).read())

    # test removals
    cc.run(['pprotect', 'rm-owner'], input=[DOMAIN_NAME, MH_EMAIL])
    cc.run(['pprotect', 'rm-secret'], input=[DOMAIN_NAME, SECRET_NAME])
    cc.run(['pprotect', 'rm-domain', '--confirm'], input=[DOMAIN_NAME, 'y'])


def test_main(tmp_path):
    # TODO: pytest-cov knows how to make coverage work across
    # subprocess boundaries...
    os.chdir(str(tmp_path))
    res = subprocess.check_output(['pprotect', 'version'])
    assert res.decode('utf8').startswith('pocket_protector version')

    res = subprocess.check_output(['pocket_protector', 'version'])
    assert res.decode('utf8').startswith('pocket_protector version')


def test_cli_key_type_fast(tmp_path, _fast_crypto):
    """Test the --key-type fast flag for init."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)

    protected_path = _fwd(tmp_path / 'protected.yaml')

    # Init with fast crypto
    res = cc.run(f'pprotect init --file {protected_path} --key-type fast',
                 input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    assert os.path.exists(protected_path)

    # Should still work - add domain, add secret, decrypt
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc2 = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    cc2.run(['pprotect', 'add-domain'], input=['dev'])
    cc2.run(['pprotect', 'add-secret'], input=['dev', 'key1', 'val1'])
    res = cc2.run(['pprotect', 'decrypt-domain', 'dev'])
    assert json.loads(res.stdout)['key1'] == 'val1'


def test_cli_migrate_owner(tmp_path, _fast_crypto):
    """Test the migrate-owner CLI subcommand."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')

    # Init with kurt
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])

    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)

    # Add MH as custodian
    cc.run('pprotect add-key-custodian', input=[MH_EMAIL, MH_PHRASE, MH_PHRASE])

    # Add two domains owned by kurt, with secrets
    cc.run(['pprotect', 'add-domain'], input=['dom1'])
    cc.run(['pprotect', 'add-domain'], input=['dom2'])
    cc.run(['pprotect', 'add-secret'], input=['dom1', 'key1', 'val1'])
    cc.run(['pprotect', 'add-secret'], input=['dom2', 'key2', 'val2'])

    # Migrate ownership to MH
    cc.run('pprotect migrate-owner', input=[MH_EMAIL, 'y'])

    # MH should now be able to decrypt both domains
    mh_env = {'PPROTECT_USER': MH_EMAIL, 'PPROTECT_PASSPHRASE': MH_PHRASE}
    cc_mh = CommandChecker(cmd, chdir=str(tmp_path), env=mh_env, reraise=True)
    res = cc_mh.run(['pprotect', 'decrypt-domain', 'dom1'])
    assert json.loads(res.stdout)['key1'] == 'val1'
    res = cc_mh.run(['pprotect', 'decrypt-domain', 'dom2'])
    assert json.loads(res.stdout)['key2'] == 'val2'


def test_cli_list_user_secrets(tmp_path, _fast_crypto):
    """Test the list-user-secrets CLI subcommand."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')

    # Init with kurt
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])

    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)

    # Add domain and secret
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    cc.run(['pprotect', 'add-secret'], input=[DOMAIN_NAME, SECRET_NAME, SECRET_VALUE])

    # List user secrets
    res = cc.run('pprotect list-user-secrets')
    assert DOMAIN_NAME in res.stdout
    assert SECRET_NAME in res.stdout


def test_cli_add_raw_key_custodian(tmp_path, _fast_crypto):
    """Test add-key-custodian --key-type raw."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    # Init with kurt (normal custodian)
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])

    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    # Add a domain and secret first
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    cc.run(['pprotect', 'add-secret'], input=[DOMAIN_NAME, SECRET_NAME, SECRET_VALUE])
    # Add raw-key custodian ("YES" confirms key was saved)
    res = cc.run('pprotect add-key-custodian --key-type raw', input=['raw@example.com', 'YES'])
    # Output should contain the generated key
    assert 'GENERATED RAW KEY' in res.stdout
    # Extract the key from output
    import re
    match = re.search(r'(P[0-9a-f]{64}P)', res.stdout)
    assert match, 'Expected raw key in output'
    raw_passphrase = match.group(1)
    # Add raw custodian as owner
    cc.run(['pprotect', 'add-owner'], input=[DOMAIN_NAME, 'raw@example.com'])
    raw_env = {'PPROTECT_USER': 'raw@example.com', 'PPROTECT_PASSPHRASE': raw_passphrase}
    cc_raw = CommandChecker(cmd, chdir=str(tmp_path), env=raw_env, reraise=True)
    res = cc_raw.run(['pprotect', 'decrypt-domain', DOMAIN_NAME])
    assert json.loads(res.stdout)[SECRET_NAME] == SECRET_VALUE


def test_cli_add_raw_key_custodian_abort(tmp_path, _fast_crypto):
    """Test that declining confirmation aborts without creating custodian."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')

    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])

    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    # Type "no" instead of "YES" - should abort
    res = cc.run('pprotect add-key-custodian --key-type raw', input=['raw@example.com', 'no'])
    assert 'Aborting' in res.stdout
    # Custodian should not exist
    import ruamel.yaml
    data = ruamel.yaml.YAML().load(open(_fwd(tmp_path / 'protected.yaml')).read())
    assert 'raw@example.com' not in data['key-custodians']


def test_cli_rekey_custodian(tmp_path, _fast_crypto):
    """Test rekey-custodian to change key type."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')

    # Init with kurt (hard key type)
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])

    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)

    # Add domain and secret
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    cc.run(['pprotect', 'add-secret'], input=[DOMAIN_NAME, SECRET_NAME, SECRET_VALUE])

    # Rekey to raw
    res = cc.run('pprotect rekey-custodian --key-type raw',
                 input=[KURT_EMAIL, KURT_PHRASE, 'YES'])
    assert 'GENERATED RAW KEY' in res.stdout
    import re
    match = re.search(r'(P[0-9a-f]{64}P)', res.stdout)
    assert match
    raw_passphrase = match.group(1)

    # Old passphrase should no longer work, new raw key should
    raw_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': raw_passphrase}
    cc_raw = CommandChecker(cmd, chdir=str(tmp_path), env=raw_env, reraise=True)
    res = cc_raw.run(['pprotect', 'decrypt-domain', DOMAIN_NAME])
    assert json.loads(res.stdout)[SECRET_NAME] == SECRET_VALUE


def test_cli_invalid_key_type(tmp_path, _fast_crypto):
    """Test that --key-type with an invalid value fails."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    res = cc.fail('pprotect init --file %s --key-type bogus' % protected_path,
                  input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    assert 'key-type' in res.stderr.lower() or 'hard' in res.stderr.lower()


def test_cli_passphrase_file_not_found(tmp_path, _fast_crypto):
    """Test that a nonexistent passphrase file gives a clear error."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    cc = CommandChecker(cmd, chdir=str(tmp_path), reraise=True)
    res = cc.fail('pprotect decrypt-domain --non-interactive --passphrase-file /nonexistent/path first-domain',
                  env={'PPROTECT_USER': KURT_EMAIL})
    assert 'passphrase' in res.stderr.lower() and 'file' in res.stderr.lower()


def test_cli_list_domains_empty(tmp_path, _fast_crypto):
    """Test list-domains with no domains shows message on stderr."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    cc = CommandChecker(cmd, chdir=str(tmp_path), reraise=True)
    res = cc.run('pprotect list-domains')
    assert 'No domains' in res.stderr


def test_cli_list_domain_secrets_empty(tmp_path, _fast_crypto):
    """Test list-domain-secrets with no secrets shows message on stderr."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    res = cc.run(['pprotect', 'list-domain-secrets', DOMAIN_NAME])
    assert 'No secrets' in res.stderr


def test_cli_list_all_secrets_empty(tmp_path, _fast_crypto):
    """Test list-all-secrets with no secrets shows message on stderr."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    res = cc.run('pprotect list-all-secrets')
    assert 'No secrets' in res.stderr


def test_cli_set_passphrase_fast(tmp_path, _fast_crypto):
    """Test set-key-custodian-passphrase with --key-type fast."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    cc.run(['pprotect', 'add-secret'], input=[DOMAIN_NAME, SECRET_NAME, SECRET_VALUE])
    new_phrase = KURT_PHRASE + '_new'
    cc.run('pprotect set-key-custodian-passphrase --key-type fast',
           input=[KURT_EMAIL, KURT_PHRASE, new_phrase, new_phrase])
    # Verify decrypt works with new passphrase
    new_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': new_phrase}
    cc2 = CommandChecker(cmd, chdir=str(tmp_path), env=new_env, reraise=True)
    res = cc2.run(['pprotect', 'decrypt-domain', DOMAIN_NAME])
    assert json.loads(res.stdout)[SECRET_NAME] == SECRET_VALUE


def test_cli_rekey_custodian_fast(tmp_path, _fast_crypto):
    """Test rekey-custodian --key-type fast."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    cc.run(['pprotect', 'add-secret'], input=[DOMAIN_NAME, SECRET_NAME, SECRET_VALUE])
    new_phrase = KURT_PHRASE + '_fast'
    cc.run('pprotect rekey-custodian --key-type fast',
           input=[KURT_EMAIL, KURT_PHRASE, new_phrase, new_phrase])
    new_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': new_phrase}
    cc2 = CommandChecker(cmd, chdir=str(tmp_path), env=new_env, reraise=True)
    res = cc2.run(['pprotect', 'decrypt-domain', DOMAIN_NAME])
    assert json.loads(res.stdout)[SECRET_NAME] == SECRET_VALUE


def test_cli_rekey_custodian_hard(tmp_path, _fast_crypto):
    """Test rekey-custodian --key-type hard."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    cc.run(['pprotect', 'add-secret'], input=[DOMAIN_NAME, SECRET_NAME, SECRET_VALUE])
    new_phrase = KURT_PHRASE + '_hard'
    cc.run('pprotect rekey-custodian --key-type hard',
           input=[KURT_EMAIL, KURT_PHRASE, new_phrase, new_phrase])
    new_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': new_phrase}
    cc2 = CommandChecker(cmd, chdir=str(tmp_path), env=new_env, reraise=True)
    res = cc2.run(['pprotect', 'decrypt-domain', DOMAIN_NAME])
    assert json.loads(res.stdout)[SECRET_NAME] == SECRET_VALUE


def test_cli_rekey_custodian_abort(tmp_path, _fast_crypto):
    """Test rekey-custodian --key-type raw abort when user types 'no'."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    # Rekey to raw but decline confirmation
    res = cc.run('pprotect rekey-custodian --key-type raw',
                 input=[KURT_EMAIL, KURT_PHRASE, 'no'])
    assert 'Aborting' in res.stdout
    # Old passphrase should still work
    res = cc.run(['pprotect', 'list-domains'])
    # No crash means old creds still valid


def test_cli_migrate_owner_no_domains(tmp_path, _fast_crypto):
    """Test migrate-owner when the user owns no domains."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    # Add MH as custodian
    cc.run('pprotect add-key-custodian', input=[MH_EMAIL, MH_PHRASE, MH_PHRASE])
    # MH owns no domains, try migrate-owner as MH
    mh_env = {'PPROTECT_USER': MH_EMAIL, 'PPROTECT_PASSPHRASE': MH_PHRASE}
    cc_mh = CommandChecker(cmd, chdir=str(tmp_path), env=mh_env, reraise=True)
    res = cc_mh.run('pprotect migrate-owner', input=[KURT_EMAIL])
    assert 'do not own any domains' in res.stdout.lower()


def test_cli_migrate_owner_abort(tmp_path, _fast_crypto):
    """Test migrate-owner abort when user types 'n' at confirm."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    cc.run('pprotect add-key-custodian', input=[MH_EMAIL, MH_PHRASE, MH_PHRASE])
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    # Abort migrate-owner
    res = cc.run('pprotect migrate-owner', input=[MH_EMAIL, 'n'])
    assert 'Aborting' in res.stdout
    # Domain should still be owned by kurt, not MH
    mh_env = {'PPROTECT_USER': MH_EMAIL, 'PPROTECT_PASSPHRASE': MH_PHRASE}
    cc_mh = CommandChecker(cmd, chdir=str(tmp_path), env=mh_env, reraise=True)
    # MH should not be owner - list-user-secrets should show no domains
    res = cc_mh.run('pprotect list-user-secrets')
    assert 'does not own any domains' in res.stderr


def test_decrypt_domain_format_env(tmp_path, _fast_crypto):
    """Test --output-format env produces dotenv-style output."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    cc.run(['pprotect', 'add-secret'], input=[DOMAIN_NAME, 'DB_PASS', 'my secret'])
    cc.run(['pprotect', 'add-secret'], input=[DOMAIN_NAME, 'API_KEY', 'key123'])

    res = cc.run(['pprotect', 'decrypt-domain', '--output-format', 'env', DOMAIN_NAME])
    lines = res.stdout.strip().splitlines()
    assert len(lines) == 2
    # sorted by name: API_KEY before DB_PASS
    assert lines[0] == 'API_KEY=key123'
    assert lines[1] == "DB_PASS='my secret'"


def test_decrypt_domain_format_shell(tmp_path, _fast_crypto):
    """Test --output-format shell produces eval-able export lines."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    cc.run(['pprotect', 'add-secret'], input=[DOMAIN_NAME, 'DB_PASS', 'val with spaces'])

    res = cc.run(['pprotect', 'decrypt-domain', '--output-format', 'shell', DOMAIN_NAME])
    lines = res.stdout.strip().splitlines()
    assert len(lines) == 1
    assert lines[0] == "export DB_PASS='val with spaces'"


def test_decrypt_domain_format_env_special_chars(tmp_path, _fast_crypto):
    """Test env format correctly escapes quotes and backslashes in values."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    cc.run(['pprotect', 'add-secret'], input=[DOMAIN_NAME, 'TRICKY', 'has"quotes\\and=equals'])

    res = cc.run(['pprotect', 'decrypt-domain', '--output-format', 'env', DOMAIN_NAME])
    # Value should be single-quoted by shlex.quote
    assert res.stdout.strip() == "TRICKY='has\"quotes\\and=equals'"


def test_decrypt_domain_format_env_shell_metacharacters(tmp_path, _fast_crypto):
    """Test env format safely handles shell metacharacters ($, `, newline) in values."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    cc.run(['pprotect', 'add-secret'], input=[DOMAIN_NAME, 'DB_PASS', 'p@ss$word`id`'])

    res = cc.run(['pprotect', 'decrypt-domain', '--output-format', 'env', DOMAIN_NAME])
    # shlex.quote wraps in single quotes; value is preserved literally
    assert res.stdout.strip() == "DB_PASS='p@ss$word`id`'"


def test_decrypt_domain_format_env_invalid_name_errors(tmp_path, _fast_crypto):
    """Test that secret names that aren't valid shell identifiers produce an error."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    cc.run(['pprotect', 'add-secret'], input=[DOMAIN_NAME, 'has-hyphens', 'val'])

    res = cc.fail_1(['pprotect', 'decrypt-domain', '--output-format', 'env', DOMAIN_NAME])
    assert 'not a valid shell identifier' in res.stderr
    assert 'has-hyphens' in res.stderr


def test_decrypt_domain_secret_raw(tmp_path, _fast_crypto):
    """Test --secret without --output-format outputs raw value."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    cc.run(['pprotect', 'add-secret'], input=[DOMAIN_NAME, SECRET_NAME, SECRET_VALUE])

    res = cc.run(['pprotect', 'decrypt-domain', '--secret', SECRET_NAME, DOMAIN_NAME])
    # Raw value, no JSON wrapping, no trailing newline from json.dumps
    assert res.stdout.strip() == SECRET_VALUE


def test_decrypt_domain_secret_json(tmp_path, _fast_crypto):
    """Test --secret with --output-format json outputs single-key JSON."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    cc.run(['pprotect', 'add-secret'], input=[DOMAIN_NAME, SECRET_NAME, SECRET_VALUE])

    res = cc.run(['pprotect', 'decrypt-domain', '--output-format', 'json',
                  '--secret', SECRET_NAME, DOMAIN_NAME])
    data = json.loads(res.stdout)
    assert data == {SECRET_NAME: SECRET_VALUE}


def test_decrypt_domain_secret_shell(tmp_path, _fast_crypto):
    """Test --secret with --output-format shell outputs single export line."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    cc.run(['pprotect', 'add-secret'], input=[DOMAIN_NAME, 'DB_PASS', SECRET_VALUE])

    res = cc.run(['pprotect', 'decrypt-domain', '--output-format', 'shell',
                  '--secret', 'DB_PASS', DOMAIN_NAME])
    assert res.stdout.strip() == 'export DB_PASS=%s' % shlex.quote(SECRET_VALUE)


def test_decrypt_domain_secret_not_found(tmp_path, _fast_crypto):
    """Test --secret with a nonexistent name fails with clear error."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    cc.run(['pprotect', 'add-secret'], input=[DOMAIN_NAME, SECRET_NAME, SECRET_VALUE])

    res = cc.fail_1(['pprotect', 'decrypt-domain', '--secret', 'nonexistent', DOMAIN_NAME])
    assert 'not found' in res.stderr


def test_decrypt_domain_format_invalid(tmp_path, _fast_crypto):
    """Test --output-format with an invalid value fails."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])

    res = cc.fail_1(['pprotect', 'decrypt-domain', '--output-format', 'xml', DOMAIN_NAME])
    assert 'output-format' in res.stderr.lower()


# --- Phase 3: exec subcommand tests ---


def test_build_exec_env_basic():
    """Test _build_exec_env injects secrets into a base env."""
    base = {'PATH': '/usr/bin', 'HOME': '/home/user', 'OTHER': 'val'}
    secrets = {'DB_PASS': 's3cret', 'API_KEY': 'key123'}
    result = cli._build_exec_env(secrets, base_env=base)
    assert result['DB_PASS'] == 's3cret'
    assert result['API_KEY'] == 'key123'
    assert result['PATH'] == '/usr/bin'
    assert result['OTHER'] == 'val'  # passthrough by default


def test_build_exec_env_scrubs_credentials():
    """Test that PPROTECT_PASSPHRASE and PPROTECT_USER are always scrubbed."""
    base = {'PATH': '/usr/bin', 'PPROTECT_PASSPHRASE': 'leaked', 'PPROTECT_USER': 'leaked@user'}
    secrets = {'DB_PASS': 'ok'}
    result = cli._build_exec_env(secrets, base_env=base)
    assert 'PPROTECT_PASSPHRASE' not in result
    assert 'PPROTECT_USER' not in result
    assert result['DB_PASS'] == 'ok'
    assert result['PATH'] == '/usr/bin'


def test_build_exec_env_no_passthrough():
    """Test --no-passthrough produces minimal env with only system vars + secrets."""
    base = {
        'PATH': '/usr/bin',
        'HOME': '/home/user',
        'TERM': 'xterm',
        'LANG': 'en_US.UTF-8',
        'AWS_SECRET_KEY': 'should_not_appear',
        'PPROTECT_PASSPHRASE': 'also_scrubbed',
    }
    secrets = {'DB_PASS': 's3cret'}
    result = cli._build_exec_env(secrets, no_passthrough=True, base_env=base)
    assert result['DB_PASS'] == 's3cret'
    assert result['PATH'] == '/usr/bin'
    assert result['HOME'] == '/home/user'
    assert result['TERM'] == 'xterm'
    assert result['LANG'] == 'en_US.UTF-8'
    assert 'AWS_SECRET_KEY' not in result
    assert 'PPROTECT_PASSPHRASE' not in result


def test_build_exec_env_prefix():
    """Test --prefix prepends to secret names."""
    secrets = {'DB_PASS': 'val'}
    result = cli._build_exec_env(secrets, prefix='MYAPP', base_env={})
    assert 'MYAPP_DB_PASS' in result
    assert 'DB_PASS' not in result


def test_build_exec_env_uppercase():
    """Test --uppercase converts secret names."""
    secrets = {'db-pass': 'val', 'api.key': 'val2'}
    result = cli._build_exec_env(secrets, uppercase=True, base_env={})
    assert 'DB_PASS' in result
    assert 'API_KEY' in result
    assert 'db-pass' not in result


def test_build_exec_env_prefix_and_uppercase():
    """Test --prefix and --uppercase combined."""
    secrets = {'db-pass': 'val'}
    result = cli._build_exec_env(secrets, prefix='APP', uppercase=True, base_env={})
    assert 'APP_DB_PASS' in result


def test_build_exec_env_collision():
    """Test that name collisions after transformation raise UsageError."""
    from face import UsageError
    import pytest
    # 'db-pass' and 'db_pass' both map to 'DB_PASS' when uppercased
    secrets = {'db-pass': 'val1', 'db_pass': 'val2'}
    with pytest.raises(UsageError, match='collision'):
        cli._build_exec_env(secrets, uppercase=True, base_env={})


def test_transform_secret_name():
    """Test _transform_secret_name with various inputs."""
    assert cli._transform_secret_name('DB_PASS') == 'DB_PASS'
    assert cli._transform_secret_name('db-pass', uppercase=True) == 'DB_PASS'
    assert cli._transform_secret_name('db.key', uppercase=True) == 'DB_KEY'
    assert cli._transform_secret_name('KEY', prefix='APP') == 'APP_KEY'
    assert cli._transform_secret_name('my-key', prefix='X', uppercase=True) == 'X_MY_KEY'


def test_exec_missing_domain(tmp_path, _fast_crypto):
    """Test exec without --domain fails with clear error."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    res = cc.fail_1(['pprotect', 'exec', '--', 'echo', 'hello'])
    assert 'domain' in res.stderr.lower()


def test_exec_missing_command(tmp_path, _fast_crypto):
    """Test exec without a command after -- fails with clear error."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    res = cc.fail_1(['pprotect', 'exec', '--domain', DOMAIN_NAME])
    assert 'command' in res.stderr.lower()


def test_exec_subprocess_integration(tmp_path, _fast_crypto):
    """Integration test: exec injects secrets and scrubs credentials via subprocess."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s --key-type fast' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    # Use env-var-safe name (no hyphens) — hyphenated names are not portable as
    # env vars on Windows, and exec injects secrets as env vars.
    cc.run(['pprotect', 'add-secret'], input=[DOMAIN_NAME, 'EXEC_KEY', 'exec_val'])

    # Run pprotect exec via subprocess, using a python one-liner to dump env
    env = dict(os.environ)
    env['PPROTECT_USER'] = KURT_EMAIL
    env['PPROTECT_PASSPHRASE'] = KURT_PHRASE
    result = subprocess.run(
        ['pprotect', 'exec', '--non-interactive',
         '--domain', DOMAIN_NAME,
         '--file', protected_path,
         '--', sys.executable, '-c',
         'import os, json; print(json.dumps(dict(os.environ)))'],
        capture_output=True, text=True, env=env, cwd=str(tmp_path))
    assert result.returncode == 0, 'stderr: %s' % result.stderr
    child_env = json.loads(result.stdout)
    # Secret should be in child env
    assert child_env['EXEC_KEY'] == 'exec_val'
    # Credentials should NOT be in child env
    assert 'PPROTECT_PASSPHRASE' not in child_env
    assert 'PPROTECT_USER' not in child_env


def test_exec_subprocess_no_passthrough(tmp_path, _fast_crypto):
    """Integration test: --no-passthrough produces minimal env."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s --key-type fast' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    cc.run(['pprotect', 'add-secret'], input=[DOMAIN_NAME, 'EXEC_KEY', 'exec_val'])

    env = dict(os.environ)
    env['PPROTECT_USER'] = KURT_EMAIL
    env['PPROTECT_PASSPHRASE'] = KURT_PHRASE
    env['SHOULD_NOT_APPEAR'] = 'leaked'
    result = subprocess.run(
        ['pprotect', 'exec', '--non-interactive',
         '--domain', DOMAIN_NAME,
         '--no-passthrough',
         '--file', protected_path,
         '--', sys.executable, '-c',
         'import os, json; print(json.dumps(dict(os.environ)))'],
        capture_output=True, text=True, env=env, cwd=str(tmp_path))
    assert result.returncode == 0, 'stderr: %s' % result.stderr
    child_env = json.loads(result.stdout)
    assert child_env['EXEC_KEY'] == 'exec_val'
    assert 'SHOULD_NOT_APPEAR' not in child_env
    assert 'PPROTECT_PASSPHRASE' not in child_env
    # PATH should still be present
    assert 'PATH' in child_env


def test_exec_subprocess_prefix_uppercase(tmp_path, _fast_crypto):
    """Integration test: --prefix and --uppercase transform secret names."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s --key-type fast' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    cc.run(['pprotect', 'add-domain'], input=[DOMAIN_NAME])
    cc.run(['pprotect', 'add-secret'], input=[DOMAIN_NAME, 'db-pass', 'myval'])

    env = dict(os.environ)
    env['PPROTECT_USER'] = KURT_EMAIL
    env['PPROTECT_PASSPHRASE'] = KURT_PHRASE
    result = subprocess.run(
        ['pprotect', 'exec', '--non-interactive',
         '--domain', DOMAIN_NAME,
         '--prefix', 'MYAPP', '--uppercase',
         '--file', protected_path,
         '--', sys.executable, '-c',
         'import os, json; print(json.dumps(dict(os.environ)))'],
        capture_output=True, text=True, env=env, cwd=str(tmp_path))
    assert result.returncode == 0, 'stderr: %s' % result.stderr
    child_env = json.loads(result.stdout)
    assert child_env['MYAPP_DB_PASS'] == 'myval'
    assert 'db-pass' not in child_env


# --- Custom env prefix tests ---


def test_build_exec_env_default_prefix_unchanged():
    """Default env_prefix preserves existing scrub behavior exactly."""
    base = {'PATH': '/usr/bin', 'PPROTECT_PASSPHRASE': 'leaked', 'PPROTECT_USER': 'leaked@user'}
    secrets = {'DB_PASS': 'ok'}
    result = cli._build_exec_env(secrets, base_env=base)
    assert 'PPROTECT_PASSPHRASE' not in result
    assert 'PPROTECT_USER' not in result
    assert result['DB_PASS'] == 'ok'
    assert result['PATH'] == '/usr/bin'


def test_build_exec_env_custom_prefix_scrub():
    """Custom env_prefix scrubs both custom AND default PPROTECT_* vars."""
    base = {
        'PATH': '/usr/bin',
        'PPROTECT_PASSPHRASE': 'default_leaked',
        'PPROTECT_USER': 'default_user',
        'MYAPP_USER': 'custom_user',
        'MYAPP_PASSPHRASE': 'custom_leaked',
        'KEEP_THIS': 'yes',
    }
    secrets = {'DB_PASS': 'ok'}
    result = cli._build_exec_env(secrets, base_env=base, env_prefix='MYAPP')
    # Both default and custom prefix vars scrubbed
    assert 'PPROTECT_PASSPHRASE' not in result
    assert 'PPROTECT_USER' not in result
    assert 'MYAPP_USER' not in result
    assert 'MYAPP_PASSPHRASE' not in result
    # Non-credential vars preserved
    assert result['KEEP_THIS'] == 'yes'
    assert result['DB_PASS'] == 'ok'


def test_custom_env_prefix_creds(tmp_path, _fast_crypto):
    """Verify _get_creds reads from custom-prefixed env vars."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])

    # Use custom prefix env vars with --env-prefix
    custom_env = {'MYAPP_USER': KURT_EMAIL, 'MYAPP_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=custom_env, reraise=True)
    cc.run(['pprotect', 'add-domain', '--env-prefix', 'MYAPP'], input=[DOMAIN_NAME])
    cc.run(['pprotect', 'add-secret'],
           input=[DOMAIN_NAME, SECRET_NAME, SECRET_VALUE])
    res = cc.run(['pprotect', 'decrypt-domain', '--env-prefix', 'MYAPP', DOMAIN_NAME])
    assert json.loads(res.stdout)[SECRET_NAME] == SECRET_VALUE


def test_cli_env_prefix_flag(tmp_path, _fast_crypto):
    """Integration test: --env-prefix with CommandChecker reads custom vars
    and ignores default PPROTECT_* vars."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])

    # Set custom prefix vars, do NOT set PPROTECT_*
    custom_env = {'MYAPP_USER': KURT_EMAIL, 'MYAPP_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=custom_env, reraise=True)
    cc.run(['pprotect', 'add-domain', '--env-prefix', 'MYAPP'], input=[DOMAIN_NAME])
    cc.run(['pprotect', 'add-secret'],
           input=[DOMAIN_NAME, SECRET_NAME, SECRET_VALUE])

    # Verify custom prefix works for decrypt
    res = cc.run(['pprotect', 'decrypt-domain', '--env-prefix', 'MYAPP', DOMAIN_NAME])
    assert json.loads(res.stdout)[SECRET_NAME] == SECRET_VALUE

    # Verify default prefix env vars are NOT used when custom is set
    default_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': 'wrong_phrase'}
    cc2 = CommandChecker(cmd, chdir=str(tmp_path), env=default_env, reraise=True)
    # With --env-prefix MYAPP, PPROTECT_* vars should be ignored for credential lookup,
    # so this should fail (no MYAPP_USER/MYAPP_PASSPHRASE set, non-interactive)
    cc2.fail_1(['pprotect', 'decrypt-domain', '--env-prefix', 'MYAPP',
                '--non-interactive', DOMAIN_NAME])


def test_exec_subprocess_custom_prefix(tmp_path, _fast_crypto):
    """Subprocess integration: exec with --env-prefix scrubs both default and custom vars."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = _fwd(tmp_path / 'protected.yaml')
    cc.run('pprotect init --file %s --key-type fast' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    custom_env = {'MYAPP_USER': KURT_EMAIL, 'MYAPP_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=custom_env, reraise=True)
    cc.run(['pprotect', 'add-domain', '--env-prefix', 'MYAPP'], input=[DOMAIN_NAME])
    cc.run(['pprotect', 'add-secret'],
           input=[DOMAIN_NAME, 'EXEC_KEY', 'exec_val'])

    # Run exec via subprocess with both default and custom env vars set
    env = dict(os.environ)
    env['PPROTECT_USER'] = 'should_be_scrubbed'
    env['PPROTECT_PASSPHRASE'] = 'should_be_scrubbed'
    env['MYAPP_USER'] = KURT_EMAIL
    env['MYAPP_PASSPHRASE'] = KURT_PHRASE
    result = subprocess.run(
        ['pprotect', 'exec', '--non-interactive',
         '--domain', DOMAIN_NAME,
         '--env-prefix', 'MYAPP',
         '--file', protected_path,
         '--', sys.executable, '-c',
         'import os, json; print(json.dumps(dict(os.environ)))'],
        capture_output=True, text=True, env=env, cwd=str(tmp_path))
    assert result.returncode == 0, 'stderr: %s' % result.stderr
    child_env = json.loads(result.stdout)
    # Secret should be injected
    assert child_env['EXEC_KEY'] == 'exec_val'
    # Both default and custom credential vars should be scrubbed
    assert 'PPROTECT_PASSPHRASE' not in child_env
    assert 'PPROTECT_USER' not in child_env
    assert 'MYAPP_USER' not in child_env
    assert 'MYAPP_PASSPHRASE' not in child_env

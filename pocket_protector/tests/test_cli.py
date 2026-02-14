import os
import json
import subprocess

import ruamel.yaml
from face import CommandChecker

from pocket_protector import cli


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

    tmp_path = str(tmp_path)
    protected_path = tmp_path + '/protected.yaml'

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
    cc = CommandChecker(cmd, chdir=tmp_path, env=kurt_env, reraise=True)

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
    cc.fail_2('pprotect list-all-secrets', chdir=tmp_path + '/..')

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
    ppfile_path = str(tmp_path) + 'tmp_passphrase'
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

    protected_path = str(tmp_path) + '/protected.yaml'

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
    protected_path = str(tmp_path) + '/protected.yaml'

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
    protected_path = str(tmp_path) + '/protected.yaml'

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
    protected_path = str(tmp_path) + '/protected.yaml'
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
    protected_path = str(tmp_path) + '/protected.yaml'

    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])

    kurt_env = {'PPROTECT_USER': KURT_EMAIL, 'PPROTECT_PASSPHRASE': KURT_PHRASE}
    cc = CommandChecker(cmd, chdir=str(tmp_path), env=kurt_env, reraise=True)
    # Type "no" instead of "YES" - should abort
    res = cc.run('pprotect add-key-custodian --key-type raw', input=['raw@example.com', 'no'])
    assert 'Aborting' in res.stdout
    # Custodian should not exist
    import ruamel.yaml
    data = ruamel.yaml.YAML().load(open(str(tmp_path) + '/protected.yaml').read())
    assert 'raw@example.com' not in data['key-custodians']


def test_cli_rekey_custodian(tmp_path, _fast_crypto):
    """Test rekey-custodian to change key type."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = str(tmp_path) + '/protected.yaml'

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
    protected_path = str(tmp_path) + '/protected.yaml'
    res = cc.fail('pprotect init --file %s --key-type bogus' % protected_path,
                  input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    assert 'key-type' in res.stderr.lower() or 'hard' in res.stderr.lower()


def test_cli_passphrase_file_not_found(tmp_path, _fast_crypto):
    """Test that a nonexistent passphrase file gives a clear error."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = str(tmp_path) + '/protected.yaml'
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
    protected_path = str(tmp_path) + '/protected.yaml'
    cc.run('pprotect init --file %s' % protected_path,
           input=[KURT_EMAIL, KURT_PHRASE, KURT_PHRASE])
    cc = CommandChecker(cmd, chdir=str(tmp_path), reraise=True)
    res = cc.run('pprotect list-domains')
    assert 'No domains' in res.stderr


def test_cli_list_domain_secrets_empty(tmp_path, _fast_crypto):
    """Test list-domain-secrets with no secrets shows message on stderr."""
    cmd = cli._get_cmd()
    cc = CommandChecker(cmd, reraise=True)
    protected_path = str(tmp_path) + '/protected.yaml'
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
    protected_path = str(tmp_path) + '/protected.yaml'
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
    protected_path = str(tmp_path) + '/protected.yaml'
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
    protected_path = str(tmp_path) + '/protected.yaml'
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
    protected_path = str(tmp_path) + '/protected.yaml'
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
    protected_path = str(tmp_path) + '/protected.yaml'
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
    protected_path = str(tmp_path) + '/protected.yaml'
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
    protected_path = str(tmp_path) + '/protected.yaml'
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
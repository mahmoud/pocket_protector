import tempfile

import pytest

from pocket_protector import file_keys


def test_file_keys(_fast_crypto):
    bob_creds = file_keys.Creds('bob@example.com', 'super-secret')
    alice_creds = file_keys.Creds('alice@example.com', 'super-duper-secret')

    _prev = [None]
    def chk(fk):
        assert fk.from_contents_and_path(fk.get_contents(), fk.path) == fk
        assert _prev[0] != fk, "function call resulted in no changes to data"
        _prev[0] = fk

    tmp = tempfile.NamedTemporaryFile()
    test1 = test = file_keys.KeyFile.create(path=tmp.name)
    chk(test)
    test2 = test = test.add_key_custodian(bob_creds)
    chk(test)
    test3 = test = test.add_domain('new_domain', bob_creds.name)
    chk(test)

    with pytest.raises(ValueError):
        test3f = test = test.add_secret('new_domain', '$brokenkey', 'world')

    test3a = test = test.add_secret('new_domain', 'hello', 'world')
    chk(test)
    test3b = test = test.update_secret('new_domain', 'hello', 'world2')
    chk(test)
    test4 = test = test.set_secret('new_domain', 'hello', 'world')
    chk(test)
    test4a = test = test.rm_secret('new_domain', 'hello')
    chk(test)
    test4b = test = test.set_secret('new_domain', 'hello', 'world')
    chk(test)
    assert test.decrypt_domain('new_domain', bob_creds)['hello'] == 'world'
    test5 = test = test.set_secret('new_domain', 'hello', 'better-world')
    chk(test)
    assert test.decrypt_domain('new_domain', bob_creds)['hello'] == 'better-world'
    test6 = test = test.add_key_custodian(alice_creds)
    chk(test)
    test7 = test = test.add_owner('new_domain', alice_creds.name, bob_creds)
    chk(test)
    test8 = _test = test.rm_owner('new_domain', alice_creds.name)
    chk(_test)  # throw away this mutation
    test9 = _test = test.rm_key_custodian(alice_creds.name)
    chk(_test)  # throw away this mutation
    test9a = _test = test.rm_domain('new_domain')
    chk(_test)
    before_rotate = test.decrypt_domain('new_domain', bob_creds)
    test10 = test = test.rotate_domain_key('new_domain', bob_creds)
    chk(test)
    assert test.get_all_secret_names() == {'hello': ['new_domain']}
    assert test.decrypt_domain('new_domain', bob_creds) == before_rotate
    test11 = test = test.set_key_custodian_passphrase(bob_creds, 'ultra-extra-secret')
    test.write()
    round_trip = file_keys.KeyFile.from_file(test.path)
    assert round_trip == test
    print("generated file:")
    print(open(test.path).read())
    print("...")


def test_v1_custodian_round_trip(_fast_crypto):
    """Test that v1 custodians (with stored KDF params) round-trip correctly."""
    from pocket_protector.file_keys import KDF_INTERACTIVE, _KeyCustodian
    creds = file_keys.Creds('v1user@example.com', 'test-passphrase')
    # Create with explicit KDF params
    kc = _KeyCustodian.from_creds(creds, opslimit=KDF_INTERACTIVE[0], memlimit=KDF_INTERACTIVE[1])
    # Round-trip through data
    data = kc.as_data()
    kc2 = _KeyCustodian.from_data(creds.name, data)
    # Verify decrypt works
    enc = kc.encrypt_for(b'hello')
    dec = kc2.decrypt_as(creds, enc)
    assert dec == b'hello'


def test_v0_v1_coexistence(_fast_crypto):
    """Test v0 and v1 custodians can coexist in the same KeyFile."""
    from pocket_protector.file_keys import KDF_INTERACTIVE
    # Create a keyfile with a v0 custodian (uses module globals)
    bob = file_keys.Creds('bob@example.com', 'secret1')
    tmp = tempfile.NamedTemporaryFile()
    kf = file_keys.KeyFile.create(path=tmp.name)
    kf = kf.add_key_custodian(bob)  # v0 (no explicit params)
    # Add a v1 custodian
    alice = file_keys.Creds('alice@example.com', 'secret2')
    kf = kf.add_key_custodian(alice, opslimit=KDF_INTERACTIVE[0], memlimit=KDF_INTERACTIVE[1])
    # Add domain, add secret
    kf = kf.add_domain('dev', bob.name)
    kf = kf.add_owner('dev', alice.name, bob)
    kf = kf.set_secret('dev', 'key1', 'value1')
    # Write and re-read
    kf.write()
    kf2 = file_keys.KeyFile.from_file(tmp.name)
    # Both can decrypt
    assert kf2.decrypt_domain('dev', bob)['key1'] == 'value1'
    assert kf2.decrypt_domain('dev', alice)['key1'] == 'value1'


def test_kdf_params_in_keyfile(_fast_crypto):
    """Test that KDF params survive KeyFile serialization."""
    from pocket_protector.file_keys import KDF_INTERACTIVE
    creds = file_keys.Creds('user@example.com', 'mypass')
    tmp = tempfile.NamedTemporaryFile()
    kf = file_keys.KeyFile.create(path=tmp.name)
    kf = kf.add_key_custodian(creds, opslimit=KDF_INTERACTIVE[0], memlimit=KDF_INTERACTIVE[1])
    kf = kf.add_domain('test', creds.name)
    kf = kf.set_secret('test', 'secret1', 'value1')
    kf.write()
    kf2 = file_keys.KeyFile.from_file(tmp.name)
    assert kf2.decrypt_domain('test', creds)['secret1'] == 'value1'
    assert kf2 == kf


def test_check_creds(_fast_crypto):
    """Test check_creds works for both v0 and v1 custodians."""
    from pocket_protector.file_keys import KDF_INTERACTIVE
    bob = file_keys.Creds('bob@example.com', 'secret1')
    alice = file_keys.Creds('alice@example.com', 'secret2')
    tmp = tempfile.NamedTemporaryFile()
    kf = file_keys.KeyFile.create(path=tmp.name)
    kf = kf.add_key_custodian(bob)  # v0
    kf = kf.add_key_custodian(alice, opslimit=KDF_INTERACTIVE[0], memlimit=KDF_INTERACTIVE[1])  # v1
    assert kf.check_creds(bob)
    assert kf.check_creds(alice)
    assert not kf.check_creds(file_keys.Creds('bob@example.com', 'wrong'))
    assert not kf.check_creds(file_keys.Creds('nobody@example.com', 'whatever'))


def test_truncate_audit_log(_fast_crypto):
    """Test audit log truncation."""
    creds = file_keys.Creds('user@example.com', 'pass')
    tmp = tempfile.NamedTemporaryFile()
    kf = file_keys.KeyFile.create(path=tmp.name)
    kf = kf.add_key_custodian(creds)
    kf = kf.add_domain('d', creds.name)
    for i in range(20):
        kf = kf.set_secret('d', f'key{i}', f'val{i}')
    # Should have >20 log entries
    assert len(kf.get_audit_log()) > 20
    kf2 = kf.truncate_audit_log(5)
    assert len(kf2.get_audit_log()) == 6  # 1 truncation message + 5 kept


def test_error_cases(_fast_crypto):
    """Test error handling."""
    creds = file_keys.Creds('user@example.com', 'pass')
    tmp = tempfile.NamedTemporaryFile()
    kf = file_keys.KeyFile.create(path=tmp.name)
    kf = kf.add_key_custodian(creds)
    kf = kf.add_domain('d', creds.name)
    kf = kf.set_secret('d', 'key1', 'val1')

    # Can't add duplicate domain
    with pytest.raises(file_keys.PPError):
        kf.add_domain('d', creds.name)

    # Can't add duplicate custodian
    with pytest.raises(file_keys.PPError):
        kf.add_key_custodian(creds)

    # Can't add secret that exists
    with pytest.raises(file_keys.PPError):
        kf.add_secret('d', 'key1', 'other')

    # Can't access nonexistent domain
    with pytest.raises(file_keys.PPKeyError):
        kf.decrypt_domain('nonexistent', creds)

    # Invalid secret name
    with pytest.raises(ValueError):
        kf.set_secret('d', '$invalid', 'val')


def test_set_passphrase_with_kdf_params(_fast_crypto):
    """Test set_key_custodian_passphrase with explicit KDF params."""
    from pocket_protector.file_keys import KDF_INTERACTIVE
    bob = file_keys.Creds('bob@example.com', 'secret1')
    tmp = tempfile.NamedTemporaryFile()
    kf = file_keys.KeyFile.create(path=tmp.name)
    kf = kf.add_key_custodian(bob)  # v0 custodian
    kf = kf.add_domain('prod', bob.name)
    kf = kf.set_secret('prod', 'db-pass', 'hunter2')
    # Change passphrase with explicit KDF params
    new_pass = 'new-secret1'
    kf = kf.set_key_custodian_passphrase(
        bob, new_pass,
        opslimit=KDF_INTERACTIVE[0], memlimit=KDF_INTERACTIVE[1])
    # Verify decrypt works with new passphrase
    new_bob = file_keys.Creds('bob@example.com', new_pass)
    assert kf.decrypt_domain('prod', new_bob)['db-pass'] == 'hunter2'
    # Round-trip through file
    kf.write()
    kf2 = file_keys.KeyFile.from_file(tmp.name)
    assert kf2 == kf
    assert kf2.decrypt_domain('prod', new_bob)['db-pass'] == 'hunter2'


def test_get_custodian_domains(_fast_crypto):
    """Test get_custodian_domains returns correct domain lists."""
    alice = file_keys.Creds('alice@example.com', 'alice-pass')
    bob = file_keys.Creds('bob@example.com', 'bob-pass')
    tmp = tempfile.NamedTemporaryFile()
    kf = file_keys.KeyFile.create(path=tmp.name)
    kf = kf.add_key_custodian(alice)
    kf = kf.add_key_custodian(bob)
    # Alice owns both domains
    kf = kf.add_domain('domain1', alice.name)
    kf = kf.add_domain('domain2', alice.name)
    # Bob owns only domain1
    kf = kf.add_owner('domain1', bob.name, alice)
    alice_domains = kf.get_custodian_domains(alice.name)
    bob_domains = kf.get_custodian_domains(bob.name)
    assert sorted(alice_domains) == ['domain1', 'domain2']
    assert sorted(bob_domains) == ['domain1']


def test_migrate_owner(_fast_crypto):
    """Test migrate_owner transfers ownership across all domains."""
    alice = file_keys.Creds('alice@example.com', 'alice-pass')
    bob = file_keys.Creds('bob@example.com', 'bob-pass')
    tmp = tempfile.NamedTemporaryFile()
    kf = file_keys.KeyFile.create(path=tmp.name)
    kf = kf.add_key_custodian(alice)
    kf = kf.add_key_custodian(bob)
    # Alice owns three domains with secrets
    for d in ('d1', 'd2', 'd3'):
        kf = kf.add_domain(d, alice.name)
        kf = kf.set_secret(d, 'key', 'val-' + d)
    # Migrate ownership to bob
    kf = kf.migrate_owner(bob.name, alice)
    # Bob should now own all three
    assert sorted(kf.get_custodian_domains(bob.name)) == ['d1', 'd2', 'd3']
    # Bob can decrypt all three
    for d in ('d1', 'd2', 'd3'):
        assert kf.decrypt_domain(d, bob)['key'] == 'val-' + d
    # Error: nonexistent new custodian
    with pytest.raises(Exception):
        kf.migrate_owner('nobody@example.com', alice)
    # Error: user with no domains
    carol = file_keys.Creds('carol@example.com', 'carol-pass')
    kf2 = kf.add_key_custodian(carol)
    with pytest.raises(Exception):
        kf2.migrate_owner(bob.name, carol)


def test_raw_key_custodian(_fast_crypto):
    """Test raw-key (v2) custodian creation, encrypt/decrypt, and round-trip."""
    from pocket_protector.file_keys import generate_raw_passphrase, is_raw_passphrase, _KeyCustodian
    passphrase = generate_raw_passphrase()
    assert is_raw_passphrase(passphrase)
    assert not is_raw_passphrase('notarawkey')
    assert not is_raw_passphrase('P1234P')  # too short

    creds = file_keys.Creds('rawuser@example.com', passphrase)
    kc = _KeyCustodian.from_raw_creds(creds)
    # Round-trip through data
    data = kc.as_data()
    kc2 = _KeyCustodian.from_data(creds.name, data)
    assert kc2._raw_key is True
    # Encrypt/decrypt
    enc = kc.encrypt_for(b'secret-data')
    dec = kc2.decrypt_as(creds, enc)
    assert dec == b'secret-data'


def test_raw_key_in_keyfile(_fast_crypto):
    """Test raw-key custodian works end-to-end in a KeyFile."""
    from pocket_protector.file_keys import generate_raw_passphrase
    passphrase = generate_raw_passphrase()
    raw_creds = file_keys.Creds('raw@example.com', passphrase)
    bob = file_keys.Creds('bob@example.com', 'bob-pass')

    tmp = tempfile.NamedTemporaryFile()
    kf = file_keys.KeyFile.create(path=tmp.name)
    kf = kf.add_key_custodian(bob)  # v0
    kf = kf.add_raw_key_custodian(raw_creds)  # v2
    kf = kf.add_domain('dev', bob.name)
    kf = kf.add_owner('dev', raw_creds.name, bob)
    kf = kf.set_secret('dev', 'db_pass', 'hunter2')

    # Both can decrypt
    assert kf.decrypt_domain('dev', bob)['db_pass'] == 'hunter2'
    assert kf.decrypt_domain('dev', raw_creds)['db_pass'] == 'hunter2'

    # Round-trip through file
    kf.write()
    kf2 = file_keys.KeyFile.from_file(tmp.name)
    assert kf2 == kf
    assert kf2.decrypt_domain('dev', raw_creds)['db_pass'] == 'hunter2'
    assert kf2.check_creds(raw_creds)
    assert kf2.check_creds(bob)


def test_v0_v1_v2_coexistence(_fast_crypto):
    """Test all three custodian versions coexist in one KeyFile."""
    from pocket_protector.file_keys import KDF_INTERACTIVE, generate_raw_passphrase
    v0_creds = file_keys.Creds('v0@example.com', 'pass0')
    v1_creds = file_keys.Creds('v1@example.com', 'pass1')
    raw_pass = generate_raw_passphrase()
    v2_creds = file_keys.Creds('v2@example.com', raw_pass)

    tmp = tempfile.NamedTemporaryFile()
    kf = file_keys.KeyFile.create(path=tmp.name)
    kf = kf.add_key_custodian(v0_creds)
    kf = kf.add_key_custodian(v1_creds, opslimit=KDF_INTERACTIVE[0], memlimit=KDF_INTERACTIVE[1])
    kf = kf.add_raw_key_custodian(v2_creds)

    kf = kf.add_domain('shared', v0_creds.name)
    kf = kf.add_owner('shared', v1_creds.name, v0_creds)
    kf = kf.add_owner('shared', v2_creds.name, v0_creds)
    kf = kf.set_secret('shared', 'token', 'abc123')

    kf.write()
    kf2 = file_keys.KeyFile.from_file(tmp.name)
    assert kf2 == kf
    for c in (v0_creds, v1_creds, v2_creds):
        assert kf2.decrypt_domain('shared', c)['token'] == 'abc123'
        assert kf2.check_creds(c)


def test_raw_key_invalid_passphrase(_fast_crypto):
    """Test that from_raw_creds rejects non-raw passphrases."""
    from pocket_protector.file_keys import _KeyCustodian
    bad_creds = file_keys.Creds('user@example.com', 'regular-password')
    with pytest.raises(file_keys.PPError):
        _KeyCustodian.from_raw_creds(bad_creds)

import base64


def test_decode_unsupported_version(_fast_crypto):
    """Test that _decode() raises PPError for non-zero version byte."""
    from pocket_protector.file_keys import _decode
    bad_b64 = base64.b64encode(b'\x05' + b'some payload').decode('utf8')
    with pytest.raises(file_keys.PPError, match='not supported'):
        _decode(bad_b64)


def test_custodian_from_data_unsupported_version(_fast_crypto):
    """Test _KeyCustodian.from_data with unknown version byte."""
    from pocket_protector.file_keys import _KeyCustodian
    raw = b'\x63' + b'\x00' * 40
    encoded = base64.b64encode(raw).decode('utf8')
    with pytest.raises(file_keys.PPError, match='unsupported'):
        _KeyCustodian.from_data('user@example.com', {'pwdkm': encoded})


def test_decrypt_domain_non_owner(_fast_crypto):
    """Test that decrypt_domain raises PPError for non-owner."""
    bob = file_keys.Creds('bob@example.com', 'bob-pass')
    alice = file_keys.Creds('alice@example.com', 'alice-pass')
    tmp = tempfile.NamedTemporaryFile()
    kf = file_keys.KeyFile.create(path=tmp.name)
    kf = kf.add_key_custodian(bob)
    kf = kf.add_key_custodian(alice)
    kf = kf.add_domain('domain', bob.name)  # only bob is owner
    kf = kf.set_secret('domain', 'key', 'val')
    with pytest.raises(file_keys.PPError, match='not an owner'):
        kf.decrypt_domain('domain', alice)


def test_rm_owner_not_an_owner(_fast_crypto):
    """Test rm_owner raises PPError when custodian is not an owner."""
    bob = file_keys.Creds('bob@example.com', 'bob-pass')
    tmp = tempfile.NamedTemporaryFile()
    kf = file_keys.KeyFile.create(path=tmp.name)
    kf = kf.add_key_custodian(bob)
    kf = kf.add_domain('domain', bob.name)
    with pytest.raises(file_keys.PPError, match='not an owner'):
        kf.rm_owner('domain', 'nonexistent@example.com')


def test_rm_owner_last_owner(_fast_crypto):
    """Test rm_owner raises PPError when removing the last owner."""
    bob = file_keys.Creds('bob@example.com', 'bob-pass')
    tmp = tempfile.NamedTemporaryFile()
    kf = file_keys.KeyFile.create(path=tmp.name)
    kf = kf.add_key_custodian(bob)
    kf = kf.add_domain('domain', bob.name)
    with pytest.raises(file_keys.PPError, match='irretrievable'):
        kf.rm_owner('domain', bob.name)


def test_key_domain_missing_secret(_fast_crypto):
    """Test _KeyDomain raises PPKeyError on missing key."""
    bob = file_keys.Creds('bob@example.com', 'bob-pass')
    tmp = tempfile.NamedTemporaryFile()
    kf = file_keys.KeyFile.create(path=tmp.name)
    kf = kf.add_key_custodian(bob)
    kf = kf.add_domain('domain', bob.name)
    kf = kf.set_secret('domain', 'exists', 'val')
    decrypted = kf.decrypt_domain('domain', bob)
    with pytest.raises(file_keys.PPKeyError, match='no secret'):
        decrypted['nonexistent']


def test_add_raw_key_custodian_duplicate(_fast_crypto):
    """Test add_raw_key_custodian raises PPError for duplicate email."""
    from pocket_protector.file_keys import generate_raw_passphrase
    passphrase = generate_raw_passphrase()
    creds = file_keys.Creds('raw@example.com', passphrase)
    tmp = tempfile.NamedTemporaryFile()
    kf = file_keys.KeyFile.create(path=tmp.name)
    kf = kf.add_raw_key_custodian(creds)
    with pytest.raises(file_keys.PPError, match='already exists'):
        kf.add_raw_key_custodian(creds)


def test_rekey_custodian_name_mismatch(_fast_crypto):
    """Test rekey_custodian raises PPError when names differ."""
    bob = file_keys.Creds('bob@example.com', 'bob-pass')
    alice = file_keys.Creds('alice@example.com', 'alice-pass')
    tmp = tempfile.NamedTemporaryFile()
    kf = file_keys.KeyFile.create(path=tmp.name)
    kf = kf.add_key_custodian(bob)
    with pytest.raises(file_keys.PPError, match='same custodian name'):
        kf.rekey_custodian(bob, alice)


def test_rekey_custodian_kdf(_fast_crypto):
    """Test rekey_custodian with raw_key=False (KDF path)."""
    bob = file_keys.Creds('bob@example.com', 'bob-pass')
    tmp = tempfile.NamedTemporaryFile()
    kf = file_keys.KeyFile.create(path=tmp.name)
    kf = kf.add_key_custodian(bob)
    kf = kf.add_domain('domain', bob.name)
    kf = kf.set_secret('domain', 'key', 'val')
    new_bob = file_keys.Creds('bob@example.com', 'new-bob-pass')
    kf = kf.rekey_custodian(bob, new_bob, raw_key=False)
    assert kf.decrypt_domain('domain', new_bob)['key'] == 'val'
    assert kf.check_creds(new_bob)
    assert not kf.check_creds(bob)


def test_truncate_audit_log_no_op(_fast_crypto):
    """Test truncate_audit_log returns same object when log is short."""
    creds = file_keys.Creds('user@example.com', 'pass')
    tmp = tempfile.NamedTemporaryFile()
    kf = file_keys.KeyFile.create(path=tmp.name)
    kf = kf.add_key_custodian(creds)
    # kf has 2 log entries (create + add_key_custodian)
    result = kf.truncate_audit_log(100)
    assert result is kf
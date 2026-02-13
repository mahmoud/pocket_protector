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

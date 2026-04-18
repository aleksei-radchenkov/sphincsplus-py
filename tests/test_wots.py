from sphincsplus import (wots, adrs)

import pytest
import secrets

n = 32
w = 16

sk_seed = secrets.token_bytes(n)
pk_seed = secrets.token_bytes(n)
msg = secrets.token_bytes(n)


@pytest.fixture
def keypair():
    out = adrs.new_hash_adrs(0, 0, 0, 0, 0)

    return out, wots.gen_pk(sk_seed, pk_seed, out, n, w)


def test_sig_verify(keypair):
    adrs, pk = keypair
    sig = wots.sign(msg, sk_seed, pk_seed, adrs, n, w)

    assert wots.verify(sig, msg, pk_seed, pk, adrs, n, w)


def test_sig_verify_fail(keypair):
    adrs, pk = keypair
    sig = wots.sign(msg, sk_seed, pk_seed, adrs, n, w)

    assert not wots.verify([bytes(n)] + sig[1:], msg, pk_seed, pk, adrs, n, w)


def test_fake_msg_fail(keypair):
    adrs, pk = keypair
    sig = wots.sign(msg, sk_seed, pk_seed, adrs, n, w)

    assert not wots.verify(sig, secrets.token_bytes(n),
                           pk_seed, pk, adrs, n, w)


def test_fake_pub_key_fail(keypair):
    adrs, _ = keypair
    sig = wots.sign(msg, sk_seed, pk_seed, adrs, n, w)

    assert not wots.verify(
        sig, msg, pk_seed, secrets.token_bytes(n), adrs, n, w)


def test_sig_deterministic(keypair):
    adrs, _ = keypair

    assert wots.sign(msg, sk_seed, pk_seed, adrs, n, w) == \
        wots.sign(msg, sk_seed, pk_seed, adrs, n, w)


def test_different_msgs_give_different_sigs(keypair):
    adrs, _ = keypair

    assert wots.sign(msg, sk_seed, pk_seed, adrs, n, w) != \
        wots.sign(secrets.token_bytes(n), sk_seed, pk_seed, adrs, n, w)


def test_different_keypairs_give_different_pks():
    pk0 = wots.gen_pk(sk_seed, pk_seed,
                      adrs.new_hash_adrs(0, 0, 0, 0, 0), n, w)
    pk1 = wots.gen_pk(sk_seed, pk_seed,
                      adrs.new_hash_adrs(0, 0, 1, 0, 0), n, w)

    assert pk0 != pk1


def test_pk_from_sig_matches_pk(keypair):
    adrs, pk = keypair
    sig = wots.sign(msg, sk_seed, pk_seed, adrs, n, w)

    assert wots.sig_to_pk(sig, msg, pk_seed, adrs, n, w) == pk

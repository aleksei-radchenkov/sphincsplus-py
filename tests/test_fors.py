from sphincsplus import adrs, fors

import pytest
import secrets
import math

n = 16
k = 10
a = 6

msg_len = math.ceil((k * a) / 8)

sk_seed = secrets.token_bytes(n)
pk_seed = secrets.token_bytes(n)

addr = adrs._new()
adrs._set_layer(addr, 0)
adrs._set_tree(addr, 0)
adrs._set_keypair(addr, 0)


@pytest.fixture
def keypair():
    pk = fors.gen_pk(sk_seed, pk_seed, addr, k, a, n)

    return addr, pk


@pytest.fixture
def msg_chunk():
    return secrets.token_bytes(msg_len)


def test_verify(keypair, msg_chunk):
    addr, pk = keypair
    sig_leafs, sig_auth = fors.sign(msg_chunk, sk_seed, pk_seed, addr, k, a, n)

    assert fors.verify(
        sig_leafs, sig_auth, msg_chunk,
        pk_seed, pk, addr, k, a, n
    )


def test_wrong_msg_fail(keypair, msg_chunk):
    addr, pk = keypair

    sig_leafs, sig_auth = fors.sign(msg_chunk, sk_seed, pk_seed, addr, k, a, n)
    bad_msg = secrets.token_bytes(msg_len)

    assert not fors.verify(
        sig_leafs, sig_auth, bad_msg,
        pk_seed, pk, addr, k, a, n
    )


def test_bad_leaf_fail(keypair, msg_chunk):
    addr, pk = keypair

    sig_leafs, sig_auth = fors.sign(msg_chunk, sk_seed, pk_seed, addr, k, a, n)
    bad_leafs = [bytes(n)] + sig_leafs[1:]

    assert not fors.verify(
        bad_leafs, sig_auth, msg_chunk,
        pk_seed, pk, addr, k, a, n
    )


def test_bad_auth_fail(keypair, msg_chunk):
    addr, pk = keypair

    sig_leafs, sig_auth = fors.sign(msg_chunk, sk_seed, pk_seed, addr, k, a, n)
    bad_auth = [[bytes(n)] + sig_auth[0][1:]] + sig_auth[1:]

    assert not fors.verify(
        sig_leafs, bad_auth, msg_chunk,
        pk_seed, pk, addr, k, a, n
    )


def test_wrong_pk_fail(keypair, msg_chunk):
    addr, _ = keypair

    sig_leafs, sig_auth = fors.sign(msg_chunk, sk_seed, pk_seed, addr, k, a, n)
    fake_pk = secrets.token_bytes(n)

    assert not fors.verify(
        sig_leafs, sig_auth, msg_chunk,
        pk_seed, fake_pk, addr, k, a, n
    )


def test_gen_pk_is_sign_pk(keypair, msg_chunk):
    addr, pk_direct = keypair

    sig_leafs, sig_auth = fors.sign(msg_chunk, sk_seed, pk_seed, addr, k, a, n)

    i = fors.msg_to_indices(msg_chunk, k, a)
    pk_from_s = fors.pk_from_sig(
        sig_leafs, sig_auth, i,
        pk_seed, addr, k, a, n
    )

    assert pk_direct == pk_from_s

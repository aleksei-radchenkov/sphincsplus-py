import math
import secrets

import pytest

from sphincsplus import adrs, fors

n = 16
k = 10
a = 6

msg_len = math.ceil((k * a) / 8)

sk_seed = secrets.token_bytes(n)
pk_seed = secrets.token_bytes(n)

addr = adrs._adrs_new()
adrs._adrs_set_layer(addr, 0)
adrs._adrs_set_tree(addr, 0)
adrs._adrs_set_keypair(addr, 0)


@pytest.fixture
def keypair():
    pk = fors.fors_pk_gen(sk_seed, pk_seed, addr, k, a)

    return addr, pk


@pytest.fixture
def msg_chunk():
    return secrets.token_bytes(msg_len)


def test_verify(keypair, msg_chunk):
    addr, pk = keypair
    sig_leafs, sig_auth = fors.fors_sign(msg_chunk, sk_seed, pk_seed, addr, k, a)

    assert fors.fors_verify((sig_leafs, sig_auth), msg_chunk, pk_seed, pk, addr, k, a)


def test_wrong_msg_fail(keypair, msg_chunk):
    addr, pk = keypair

    sig_leafs, sig_auth = fors.fors_sign(msg_chunk, sk_seed, pk_seed, addr, k, a)
    bad_msg = secrets.token_bytes(msg_len)

    assert not fors.fors_verify((sig_leafs, sig_auth), bad_msg, pk_seed, pk, addr, k, a)


def test_bad_leaf_fail(keypair, msg_chunk):
    addr, pk = keypair

    sig_leafs, sig_auth = fors.fors_sign(msg_chunk, sk_seed, pk_seed, addr, k, a)
    bad_leafs = [bytes(n)] + sig_leafs[1:]

    assert not fors.fors_verify(
        (bad_leafs, sig_auth), msg_chunk, pk_seed, pk, addr, k, a
    )


def test_bad_auth_fail(keypair, msg_chunk):
    addr, pk = keypair

    sig_leafs, sig_auth = fors.fors_sign(msg_chunk, sk_seed, pk_seed, addr, k, a)
    bad_auth = [[bytes(n)] + sig_auth[0][1:]] + sig_auth[1:]

    assert not fors.fors_verify(
        (sig_leafs, bad_auth), msg_chunk, pk_seed, pk, addr, k, a
    )


def test_wrong_pk_fail(keypair, msg_chunk):
    addr, _ = keypair

    sig_leafs, sig_auth = fors.fors_sign(msg_chunk, sk_seed, pk_seed, addr, k, a)
    fake_pk = secrets.token_bytes(n)

    assert not fors.fors_verify(
        (sig_leafs, sig_auth), msg_chunk, pk_seed, fake_pk, addr, k, a
    )


def test_gen_pk_is_sign_pk(keypair, msg_chunk):
    addr, pk_direct = keypair

    sig_leafs, sig_auth = fors.fors_sign(msg_chunk, sk_seed, pk_seed, addr, k, a)

    pk_from_s = fors.fors_sig_to_pk(
        (sig_leafs, sig_auth), msg_chunk, pk_seed, addr, k, a
    )

    assert pk_direct == pk_from_s

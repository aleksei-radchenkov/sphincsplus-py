from sphincsplus import (wots, adrs)

import pytest
import secrets


@pytest.fixture
def keypair_random(request):
    n, w = request.param
    sk_seed = secrets.token_bytes(n)
    pk_seed = secrets.token_bytes(n)
    out = adrs._adrs_new_hash_adrs(0, 0, 0, 0, 0)

    return out, wots.wots_gen_pk(sk_seed, pk_seed, out, n, w), sk_seed, pk_seed, n, w


@pytest.fixture
def keypair_fixed(request):
    n, w = request.param
    fixed_sk_seed = b"\x01" * n
    fixed_pk_seed = b"\x02" * n
    out = adrs._adrs_new_hash_adrs(0, 0, 0, 0, 0)

    return out, wots.wots_gen_pk(fixed_sk_seed, fixed_pk_seed, out, n, w), fixed_sk_seed, fixed_pk_seed, n, w


@pytest.mark.parametrize("keypair_random", [(16, 16), (24, 16), (32, 16)], indirect=True)
def test_sig_verify(keypair_random):
    adrs, pk, sk_seed, pk_seed, n, w = keypair_random
    msg = secrets.token_bytes(n)
    sig = wots.wots_sign(msg, sk_seed, pk_seed, adrs, n, w)

    assert wots.wots_verify(sig, msg, pk_seed, pk, adrs, n, w)


@pytest.mark.parametrize("keypair_random", [(16, 16), (24, 16), (32, 16)], indirect=True)
def test_sig_verify_fail(keypair_random):
    adrs, pk, sk_seed, pk_seed, n, w = keypair_random
    msg = secrets.token_bytes(n)
    sig = wots.wots_sign(msg, sk_seed, pk_seed, adrs, n, w)

    assert not wots.wots_verify([bytes(n)] + sig[1:], msg, pk_seed, pk, adrs, n, w)


@pytest.mark.parametrize("keypair_random", [(16, 16), (24, 16), (32, 16)], indirect=True)
def test_fake_msg_fail(keypair_random):
    adrs, pk, sk_seed, pk_seed, n, w = keypair_random
    msg = secrets.token_bytes(n)
    sig = wots.wots_sign(msg, sk_seed, pk_seed, adrs, n, w)

    assert not wots.wots_verify(
        sig,
        secrets.token_bytes(n),
        pk_seed,
        pk,
        adrs,
        n,
        w,
    )


@pytest.mark.parametrize("keypair_random", [(16, 16), (24, 16), (32, 16)], indirect=True)
def test_fake_pub_key_fail(keypair_random):
    adrs, _, sk_seed, pk_seed, n, w = keypair_random
    msg = secrets.token_bytes(n)
    sig = wots.wots_sign(msg, sk_seed, pk_seed, adrs, n, w)

    assert not wots.wots_verify(
        sig, msg, pk_seed, secrets.token_bytes(n), adrs, n, w)


@pytest.mark.parametrize("keypair_random", [(16, 16), (24, 16), (32, 16)], indirect=True)
def test_sig_deterministic(keypair_random):
    adrs, _, sk_seed, pk_seed, n, w = keypair_random
    msg = secrets.token_bytes(n)

    assert wots.wots_sign(msg, sk_seed, pk_seed, adrs, n, w) == \
        wots.wots_sign(msg, sk_seed, pk_seed, adrs, n, w)


@pytest.mark.parametrize("keypair_random", [(16, 16), (24, 16), (32, 16)], indirect=True)
def test_different_msgs_give_different_sigs(keypair_random):
    adrs, _, sk_seed, pk_seed, n, w = keypair_random
    msg = secrets.token_bytes(n)

    assert wots.wots_sign(msg, sk_seed, pk_seed, adrs, n, w) != \
        wots.wots_sign(secrets.token_bytes(n), sk_seed, pk_seed, adrs, n, w)


@pytest.mark.parametrize("n,w", [(16, 16), (24, 16), (32, 16)])
def test_different_keypair_randoms_give_different_pks(n, w):
    pk0 = wots.wots_gen_pk(secrets.token_bytes(n), secrets.token_bytes(n),
                           adrs._adrs_new_hash_adrs(0, 0, 0, 0, 0), n, w)
    pk1 = wots.wots_gen_pk(secrets.token_bytes(n), secrets.token_bytes(n),
                           adrs._adrs_new_hash_adrs(0, 0, 1, 0, 0), n, w)

    assert pk0 != pk1


@pytest.mark.parametrize("keypair_random", [(16, 16), (24, 16), (32, 16)], indirect=True)
def test_pk_from_sig_matches_pk(keypair_random):
    adrs, pk, sk_seed, pk_seed, n, w = keypair_random
    msg = secrets.token_bytes(n)
    sig = wots.wots_sign(msg, sk_seed, pk_seed, adrs, n, w)

    assert wots.wots_sig_to_pk(sig, msg, pk_seed, adrs, n, w) == pk


@pytest.mark.parametrize("keypair_fixed", [(32, 16)], indirect=True)
def test_sig_fixed(keypair_fixed):
    adrs, pk, fixed_sk_seed, fixed_pk_seed, n, w = keypair_fixed

    fixed_msg = b"A" * n
    sig = wots.wots_sign(fixed_msg, fixed_sk_seed, fixed_pk_seed, adrs, n, w)
    with open("./tests/expected_outputs/fixed_wots_signature.txt", "rb") as f:
        fixed_sig = f.read()

    assert fixed_sig == b''.join(sig)
    assert wots.wots_verify(sig, fixed_msg, fixed_pk_seed, pk, adrs, n, w)


@pytest.mark.parametrize("keypair_random", [(16, 16), (24, 16), (32, 16)], indirect=True)
def test_chain_index_steps_too_low(keypair_random):
    adr, _, _, pk_seed, n, w = keypair_random
    msg = secrets.token_bytes(n)
    res = wots.chain(msg, 100, 100, pk_seed, adr, w)

    assert res is None

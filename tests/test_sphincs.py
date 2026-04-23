from sphincsplus import sphincs

import pytest
import secrets

N = 16
H = 8
D = 2
A = 4
K = 4
W = 16

msg = b"Hello, World! and some more text"

@pytest.fixture(
    params=[False, True],
    ids=["no_cache", "has_cache"],
)
def keypair(request):
    if request.param:
        cache = {}
        sk, pk = sphincs.keygen(
            N, H, D, A, K, W, merkle_cache=cache
        )
        return sk, pk, cache
    sk, pk = sphincs.keygen(N, H, D, A, K, W)
    return sk, pk, None

def test_sign_verify(keypair):
    sk, pk, cache = keypair
    sig = sphincs.sign(msg, sk, N, H, D, A, K, W, merkle_cache=cache)

    assert sphincs.verify(msg, sig, pk, N, H, D, A, K, W)


def test_wrong_message_fail(keypair):
    sk, pk, cache = keypair
    sig = sphincs.sign(msg, sk, N, H, D, A, K, W, merkle_cache=cache)

    wrong_msg = b"This is a bs message."

    assert not sphincs.verify(wrong_msg, sig, pk, N, H, D, A, K, W)


def test_wrong_pk_fail(keypair):
    sk, _, cache = keypair
    sig = sphincs.sign(msg, sk, N, H, D, A, K, W, merkle_cache=cache)

    assert not sphincs.verify(
        msg, sig, secrets.token_bytes(2 * N), N, H, D, A, K, W)


def test_bad_sig_fail(keypair):
    sk, pk, cache = keypair
    sig = sphincs.sign(msg, sk, N, H, D, A, K, W, merkle_cache=cache)

    sig_bad = bytearray(sig)
    sig_bad[0] &= 0xaa

    assert not sphincs.verify(msg, bytes(sig_bad), pk, N, H, D, A, K, W)


def test_deterministic(keypair):
    sk, _, cache = keypair

    sig1 = sphincs.sign(msg, sk, N, H, D, A, K, W, rand=False, merkle_cache=cache)
    sig2 = sphincs.sign(msg, sk, N, H, D, A, K, W, rand=False, merkle_cache=cache)

    assert sig1 == sig2


def test_random_different_fail(keypair):
    sk, _, cache = keypair

    sig1 = sphincs.sign(msg, sk, N, H, D, A, K, W, rand=True, merkle_cache=cache)
    sig2 = sphincs.sign(msg, sk, N, H, D, A, K, W, rand=True, merkle_cache=cache)

    assert sig1 != sig2


def test_random_verify(keypair):
    sk, pk, cache = keypair

    for _ in range(3):
        sig = sphincs.sign(msg, sk, N, H, D, A, K, W, rand=True, merkle_cache=cache)
        assert sphincs.verify(msg, sig, pk, N, H, D, A, K, W)


def test_multiple(keypair):
    sk, pk, cache = keypair

    messages = [
        b"",
        b"texts",
        secrets.token_bytes(100),
        secrets.token_bytes(1000),
    ]

    for m in messages:
        sig = sphincs.sign(m, sk, N, H, D, A, K, W, merkle_cache=cache)

        assert sphincs.verify(m, sig, pk, N, H, D, A, K, W)

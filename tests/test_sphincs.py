from sphincsplus import sphincs

import pytest
import secrets

N = 16
H = 8
D = 2
A = 4
K = 4
W = 16
M = K * A + H

msg = b"Hello, World! and some more text"


@pytest.fixture
def keypair():
    return sphincs.keygen(N, H, D, A, K, W, M)


def test_sign_verify(keypair):
    sk, pk = keypair
    sig = sphincs.sign(msg, sk, N, H, D, A, K, W, M)

    assert sphincs.verify(msg, sig, pk, N, H, D, A, K, W, M)


def test_wrong_message_fail(keypair):
    sk, pk = keypair
    sig = sphincs.sign(msg, sk, N, H, D, A, K, W, M)

    wrong_msg = b"This is a bs message."

    assert not sphincs.verify(wrong_msg, sig, pk, N, H, D, A, K, W, M)


def test_wrong_pk_fail(keypair):
    sk, _ = keypair
    sig = sphincs.sign(msg, sk, N, H, D, A, K, W, M)

    assert not sphincs.verify(
        msg, sig, secrets.token_bytes(2 * N), N, H, D, A, K, W, M)


def test_bad_sig_fail(keypair):
    sk, pk = keypair
    sig = sphincs.sign(msg, sk, N, H, D, A, K, W, M)

    sig_bad = bytearray(sig)
    sig_bad[0] &= 0xaa

    assert not sphincs.verify(msg, bytes(sig_bad), pk, N, H, D, A, K, W, M)


def test_deterministic(keypair):
    sk, _ = keypair

    sig1 = sphincs.sign(msg, sk, N, H, D, A, K, W, M, rand=False)
    sig2 = sphincs.sign(msg, sk, N, H, D, A, K, W, M, rand=False)

    assert sig1 == sig2


def test_random_different_fail(keypair):
    sk, _ = keypair

    sig1 = sphincs.sign(msg, sk, N, H, D, A, K, W, M, rand=True)
    sig2 = sphincs.sign(msg, sk, N, H, D, A, K, W, M, rand=True)

    assert sig1 != sig2


def test_random_verify(keypair):
    sk, pk = keypair

    for _ in range(3):
        sig = sphincs.sign(msg, sk, N, H, D, A, K, W, M, rand=True)
        assert sphincs.verify(msg, sig, pk, N, H, D, A, K, W, M)


def test_multiple(keypair):
    sk, pk = keypair

    messages = [
        b"",
        b"texts",
        secrets.token_bytes(100),
        secrets.token_bytes(1000),
    ]

    for m in messages:
        sig = sphincs.sign(m, sk, N, H, D, A, K, W, M)

        assert sphincs.verify(m, sig, pk, N, H, D, A, K, W, M)

from sphincsplus import sphincs, tree

import pytest
import secrets
from collections import namedtuple

TestCase = namedtuple('TestCase', ['name', 'n', 'h', 'd', 'a', 'k', 'w'])

test_cases = [
    TestCase("SPHINCS+-128s", 16, 63, 7, 12, 14, 16),
    TestCase("SPHINCS+-128f", 16, 66, 22, 6, 33, 16),
    TestCase("SPHINCS+-192s", 24, 63, 7, 14, 17, 16),
    TestCase("SPHINCS+-192f", 24, 66, 22, 8, 33, 16),
    TestCase("SPHINCS+-256s", 32, 64, 8, 14, 22, 16),
    TestCase("SPHINCS+-256f", 32, 68, 17, 9, 35, 16),
]

msg = b"Hello, World! and some more text"


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_sign_verify(test_case):
    _, n, h, d, a, k, w = test_case
    sk, pk = sphincs.keygen(n, h, d, a, k, w)
    sig = sphincs.sign(msg, sk, n, h, d, a, k, w)

    assert sphincs.verify(msg, sig, pk, n, h, d, a, k, w)


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_wrong_message_fail(test_case):
    _, n, h, d, a, k, w = test_case
    sk, pk = sphincs.keygen(n, h, d, a, k, w)
    sig = sphincs.sign(msg, sk, n, h, d, a, k, w)

    wrong_msg = b"This is a bs message."

    assert not sphincs.verify(wrong_msg, sig, pk, n, h, d, a, k, w)


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_wrong_pk_fail(test_case):
    _, n, h, d, a, k, w = test_case
    sk, _ = sphincs.keygen(n, h, d, a, k, w)
    sig = sphincs.sign(msg, sk, n, h, d, a, k, w)

    assert not sphincs.verify(
        msg, sig, secrets.token_bytes(2 * n), n, h, d, a, k, w)


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_bad_sig_fail(test_case):
    _, n, h, d, a, k, w = test_case
    sk, pk = sphincs.keygen(n, h, d, a, k, w)
    sig = sphincs.sign(msg, sk, n, h, d, a, k, w)

    sig_bad = bytearray(sig)
    sig_bad[0] ^= 0xaa

    assert not sphincs.verify(msg, bytes(sig_bad), pk, n, h, d, a, k, w)


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_deterministic(test_case):
    _, n, h, d, a, k, w = test_case
    sk, _ = sphincs.keygen(n, h, d, a, k, w)

    sig1 = sphincs.sign(msg, sk, n, h, d, a, k, w, rand=False)
    sig2 = sphincs.sign(msg, sk, n, h, d, a, k, w, rand=False)

    assert sig1 == sig2


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_random_different_fail(test_case):
    _, n, h, d, a, k, w = test_case
    sk, _ = sphincs.keygen(n, h, d, a, k, w)

    sig1 = sphincs.sign(msg, sk, n, h, d, a, k, w, rand=True)
    sig2 = sphincs.sign(msg, sk, n, h, d, a, k, w, rand=True)

    assert sig1 != sig2


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_random_verify(test_case):
    _, n, h, d, a, k, w = test_case
    sk, pk = sphincs.keygen(n, h, d, a, k, w)

    for _ in range(3):
        sig = sphincs.sign(msg, sk, n, h, d, a, k, w, rand=True)
        assert sphincs.verify(msg, sig, pk, n, h, d, a, k, w)


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_multiple(test_case):
    _, n, h, d, a, k, w = test_case
    sk, pk = sphincs.keygen(n, h, d, a, k, w)

    messages = [
        b"",
        b"texts",
        secrets.token_bytes(100),
        secrets.token_bytes(1000),
    ]

    for message in messages:
        sig = sphincs.sign(message, sk, n, h, d, a, k, w)

        assert sphincs.verify(message, sig, pk, n, h, d, a, k, w)

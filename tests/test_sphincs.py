from sphincsplus import sphincs

import pytest
import secrets
from collections import namedtuple

TestCase = namedtuple('TestCase', ['name', 'n', 'h', 'd', 'a', 'k', 'w', 'm'])

test_cases = [
    TestCase("SPHINCS+-128s", 16, 63, 7, 12, 14, 16, 14*12+63),
    TestCase("SPHINCS+-128f", 16, 66, 22, 6, 33, 16, 33*6+66),
    TestCase("SPHINCS+-192s", 24, 63, 7, 14, 17, 16, 17*14+63),
    TestCase("SPHINCS+-192f", 24, 66, 22, 8, 33, 16, 33*8+66),
    TestCase("SPHINCS+-256s", 32, 64, 8, 14, 22, 16, 22*14+64),
    TestCase("SPHINCS+-256f", 32, 68, 17, 9, 35, 16, 35*9+68),
]

msg = b"Hello, World! and some more text"


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_sign_verify(test_case):
    _, n, h, d, a, k, w, m = test_case
    sk, pk = sphincs.keygen(n, h, d, a, k, w, m)
    sig = sphincs.sign(msg, sk, n, h, d, a, k, w, m)

    assert sphincs.verify(msg, sig, pk, n, h, d, a, k, w, m)


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_wrong_message_fail(test_case):
    _, n, h, d, a, k, w, m = test_case
    sk, pk = sphincs.keygen(n, h, d, a, k, w, m)
    sig = sphincs.sign(msg, sk, n, h, d, a, k, w, m)

    wrong_msg = b"This is a bs message."

    assert not sphincs.verify(wrong_msg, sig, pk, n, h, d, a, k, w, m)


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_wrong_pk_fail(test_case):
    _, n, h, d, a, k, w, m = test_case
    sk, _ = sphincs.keygen(n, h, d, a, k, w, m)
    sig = sphincs.sign(msg, sk, n, h, d, a, k, w, m)

    assert not sphincs.verify(
        msg, sig, secrets.token_bytes(2 * n), n, h, d, a, k, w, m)


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_bad_sig_fail(test_case):
    _, n, h, d, a, k, w, m = test_case
    sk, pk = sphincs.keygen(n, h, d, a, k, w, m)
    sig = sphincs.sign(msg, sk, n, h, d, a, k, w, m)

    sig_bad = bytearray(sig)
    sig_bad[0] ^= 0xaa

    assert not sphincs.verify(msg, bytes(sig_bad), pk, n, h, d, a, k, w, m)


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_deterministic(test_case):
    _, n, h, d, a, k, w, m = test_case
    sk, _ = sphincs.keygen(n, h, d, a, k, w, m)

    sig1 = sphincs.sign(msg, sk, n, h, d, a, k, w, m, rand=False)
    sig2 = sphincs.sign(msg, sk, n, h, d, a, k, w, m, rand=False)

    assert sig1 == sig2


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_random_different_fail(test_case):
    _, n, h, d, a, k, w, m = test_case
    sk, _ = sphincs.keygen(n, h, d, a, k, w, m)

    sig1 = sphincs.sign(msg, sk, n, h, d, a, k, w, m, rand=True)
    sig2 = sphincs.sign(msg, sk, n, h, d, a, k, w, m, rand=True)

    assert sig1 != sig2


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_random_verify(test_case):
    _, n, h, d, a, k, w, m = test_case
    sk, pk = sphincs.keygen(n, h, d, a, k, w, m)

    for _ in range(3):
        sig = sphincs.sign(msg, sk, n, h, d, a, k, w, m, rand=True)
        assert sphincs.verify(msg, sig, pk, n, h, d, a, k, w, m)


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_multiple(test_case):
    _, n, h, d, a, k, w, m = test_case
    sk, pk = sphincs.keygen(n, h, d, a, k, w, m)

    messages = [
        b"",
        b"texts",
        secrets.token_bytes(100),
        secrets.token_bytes(1000),
    ]

    for message in messages:
        sig = sphincs.sign(message, sk, n, h, d, a, k, w, m)

        assert sphincs.verify(message, sig, pk, n, h, d, a, k, w, m)

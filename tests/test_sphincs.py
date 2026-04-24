from sphincsplus import sphincs
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


@pytest.fixture(
    params=[False, True],
    ids=["no_merkle_cache", "with_merkle_cache"],
)
def use_cache(request):
    return request.param


def keygen(n, h, d, a, k, w, use_cache):
    if use_cache:
        cache: dict[tuple[int, int], bytes] = {}
        sk, pk = sphincs.keygen(n, h, d, a, k, w, merkle_cache=cache)
        return sk, pk, cache
    sk, pk = sphincs.keygen(n, h, d, a, k, w)
    return sk, pk, None


def sign(msg, sk, n, h, d, a, k, w, cache=None, rand=True):
    return sphincs.sign(msg, sk, n, h, d, a, k, w, rand=rand, merkle_cache=cache)


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_sign_verify(test_case, use_cache):
    _, n, h, d, a, k, w = test_case
    sk, pk, cache = keygen(n, h, d, a, k, w, use_cache)
    sig = sign(msg, sk, n, h, d, a, k, w, cache=cache)

    assert sphincs.verify(msg, sig, pk, n, h, d, a, k, w)


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_wrong_message_fail(test_case, use_cache):
    _, n, h, d, a, k, w = test_case
    sk, pk, cache = keygen(n, h, d, a, k, w, use_cache)
    sig = sign(msg, sk, n, h, d, a, k, w, cache=cache)

    wrong_msg = b"This is a bs message."

    assert not sphincs.verify(wrong_msg, sig, pk, n, h, d, a, k, w)


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_wrong_pk_fail(test_case, use_cache):
    _, n, h, d, a, k, w = test_case
    sk, _, cache = keygen(n, h, d, a, k, w, use_cache)
    sig = sign(msg, sk, n, h, d, a, k, w, cache=cache)

    assert not sphincs.verify(
        msg, sig, secrets.token_bytes(2 * n), n, h, d, a, k, w)


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_bad_sig_fail(test_case, use_cache):
    _, n, h, d, a, k, w = test_case
    sk, pk, cache = keygen(n, h, d, a, k, w, use_cache)
    sig = sign(msg, sk, n, h, d, a, k, w, cache=cache)

    sig_bad = bytearray(sig)
    sig_bad[0] ^= 0xaa

    assert not sphincs.verify(msg, bytes(sig_bad), pk, n, h, d, a, k, w)


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_deterministic(test_case, use_cache):
    _, n, h, d, a, k, w = test_case
    sk, _, cache = keygen(n, h, d, a, k, w, use_cache)

    sig1 = sign(msg, sk, n, h, d, a, k, w, rand=False, cache=cache)
    sig2 = sign(msg, sk, n, h, d, a, k, w, rand=False, cache=cache)

    assert sig1 == sig2


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_random_different_fail(test_case, use_cache):
    _, n, h, d, a, k, w = test_case
    sk, _, cache = keygen(n, h, d, a, k, w, use_cache)

    sig1 = sign(msg, sk, n, h, d, a, k, w, rand=True, cache=cache)
    sig2 = sign(msg, sk, n, h, d, a, k, w, rand=True, cache=cache)

    assert sig1 != sig2


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_random_verify(test_case, use_cache):
    _, n, h, d, a, k, w = test_case
    sk, pk, cache = keygen(n, h, d, a, k, w, use_cache)

    for _ in range(3):
        sig = sign(msg, sk, n, h, d, a, k, w, rand=True, cache=cache)
        assert sphincs.verify(msg, sig, pk, n, h, d, a, k, w)


@pytest.mark.parametrize("test_case", test_cases, ids=lambda tc: tc.name)
def test_multiple(test_case, use_cache):
    _, n, h, d, a, k, w = test_case
    sk, pk, cache = keygen(n, h, d, a, k, w, use_cache)

    messages = [
        b"",
        b"texts",
        secrets.token_bytes(100),
        secrets.token_bytes(1000),
    ]

    for message in messages:
        sig = sign(message, sk, n, h, d, a, k, w, cache=cache)

        assert sphincs.verify(message, sig, pk, n, h, d, a, k, w)

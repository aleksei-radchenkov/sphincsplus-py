import secrets
from typing import NamedTuple

import pytest

from sphincsplus import keygen, sign, sphincs, verify, wots


class TestCase(NamedTuple):
    name: str
    n: int
    h: int
    d: int
    a: int  # log(t)
    k: int
    w: int


test_cases = [
    TestCase("low-sec-demo-CS", 16, 8, 2, 4, 4, 16),
    TestCase("SPHINCS+-128s-CS", 16, 63, 7, 12, 14, 16),
    TestCase("SPHINCS+-128f-CS", 16, 66, 22, 6, 33, 16),
    TestCase("SPHINCS+-192s-CS", 24, 63, 7, 14, 17, 16),
    TestCase("SPHINCS+-192f-CS", 24, 66, 22, 8, 33, 16),
    TestCase("SPHINCS+-256s-CS", 32, 64, 8, 14, 22, 16),
    TestCase("SPHINCS+-256f-CS", 32, 68, 17, 9, 35, 16),
]


@pytest.mark.parametrize("tc", test_cases, ids=lambda tc: tc.name)
def test_keygen(benchmark, tc):
    benchmark.pedantic(
        keygen, args=(tc.n, tc.h, tc.d, tc.a, tc.k, tc.w), rounds=3, warmup_rounds=1
    )


@pytest.mark.parametrize("tc", test_cases, ids=lambda tc: tc.name)
def test_sign(benchmark, tc):
    sk, _ = keygen(tc.n, tc.h, tc.d, tc.a, tc.k, tc.w)
    message = secrets.token_bytes(32)

    benchmark.pedantic(
        sign,
        args=(message, sk, tc.n, tc.h, tc.d, tc.a, tc.k, tc.w),
        rounds=3,
        warmup_rounds=1,
    )


@pytest.mark.parametrize("tc", test_cases, ids=lambda tc: tc.name)
def test_verify(benchmark, tc):
    sk, pk = keygen(tc.n, tc.h, tc.d, tc.a, tc.k, tc.w)
    message = secrets.token_bytes(32)
    sig = sign(message, sk, tc.n, tc.h, tc.d, tc.a, tc.k, tc.w)

    expected_len = sphincs.sig_bytes_len(tc.n, tc.h, tc.d, tc.a, tc.k, tc.w)
    assert len(sig) == expected_len

    benchmark.pedantic(
        verify,
        args=(message, sig, pk, tc.n, tc.h, tc.d, tc.a, tc.k, tc.w),
        rounds=10,
        iterations=1,
        warmup_rounds=1,
    )

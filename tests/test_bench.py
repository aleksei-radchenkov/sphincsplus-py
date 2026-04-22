import pytest
from sphincsplus import keygen, sign, verify
from typing import NamedTuple
import random


class TestCase(NamedTuple):
    name: str
    n: int
    h: int
    d: int
    a: int  # log(t)
    k: int
    w: int
    m: int


# these m values are wrong - maybe look here https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf
test_cases = [
    TestCase("low security demo", 16, 8, 2, 4, 4, 16, 24),
    TestCase("SPHINCS+-128s", 16, 63, 7, 12, 14, 16, 133),
    TestCase("SPHINCS+-128f", 16, 66, 22, 6, 33, 16, 128),
    TestCase("SPHINCS+-192s", 24, 63, 7, 14, 17, 16, 193),
    TestCase("SPHINCS+-192f", 24, 66, 22, 8, 33, 16, 194),
    TestCase("SPHINCS+-256s", 32, 64, 8, 14, 22, 16, 255),
    TestCase("SPHINCS+-256f", 32, 68, 17, 9, 35, 16, 255),
]


@pytest.mark.parametrize("tc", test_cases, ids=lambda tc: tc.name)
def test_keygen(benchmark, tc):
    benchmark.pedantic(
        keygen,
        args=(tc.n, tc.h, tc.d, tc.a, tc.k, tc.w, tc.m),
        rounds=3,
        warmup_rounds=1
    )


@pytest.mark.parametrize("tc", test_cases, ids=lambda tc: tc.name)
def test_sign(benchmark, tc):
    sk, _ = keygen(tc.n, tc.h, tc.d, tc.a, tc.k, tc.w, tc.m)

    benchmark.pedantic(
        sign,
        args=(random.randbytes(32), sk, tc.n, tc.h, tc.d, tc.a, tc.k, tc.w, tc.m),
        rounds=3,
        warmup_rounds=1
    )


@pytest.mark.parametrize("tc", test_cases, ids=lambda tc: tc.name)
def test_verify(benchmark, tc):
    sk, pk = keygen(tc.n, tc.h, tc.d, tc.a, tc.k, tc.w, tc.m)

    message = random.randbytes(32)

    sig = sign(message, sk, tc.n, tc.h, tc.d, tc.a, tc.k, tc.w, tc.m)

    benchmark.pedantic(
        verify,
        args=(message, sig, pk, tc.n, tc.h, tc.d, tc.a, tc.k, tc.w, tc.m),
        rounds=10,
        iterations=10,
        warmup_rounds=1
    )

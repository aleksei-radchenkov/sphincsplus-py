import secrets
from typing import NamedTuple
import random
import pytest

from sphincsplus import keygen, sign, sphincs, verify


class BenchCase(NamedTuple):
    name: str
    n: int
    h: int
    d: int
    a: int  # log(t)
    k: int
    w: int


test_cases = [
    BenchCase("low security demo", 16, 8, 2, 4, 4, 16),
    BenchCase("SPHINCS+-128s", 16, 63, 7, 12, 14, 16),
    BenchCase("SPHINCS+-128f", 16, 66, 22, 6, 33, 16),
    BenchCase("SPHINCS+-192s", 24, 63, 7, 14, 17, 16),
    BenchCase("SPHINCS+-192f", 24, 66, 22, 8, 33, 16),
    BenchCase("SPHINCS+-256s", 32, 64, 8, 14, 22, 16),
    BenchCase("SPHINCS+-256f", 32, 68, 17, 9, 35, 16),
]


@pytest.mark.benchmark(group="keygen-wo-c")
@pytest.mark.parametrize("tc", test_cases, ids=lambda tc: tc.name)
def test_keygen_without_cache(benchmark, tc):
    benchmark.pedantic(
        keygen, args=(tc.n, tc.h, tc.d, tc.a, tc.k, tc.w), rounds=3, warmup_rounds=1
    )


@pytest.mark.benchmark(group="keygen-c")
# caching should only affect signing time, so this is just a double-check
@pytest.mark.parametrize("tc", test_cases, ids=lambda tc: tc.name)
def test_keygen_with_cache(benchmark, tc):
    cache = {}
    benchmark.pedantic(
        keygen,
        args=(tc.n, tc.h, tc.d, tc.a, tc.k, tc.w, cache),
        rounds=3,
        warmup_rounds=1
    )


@pytest.mark.benchmark(group="sign-wo-c")
@pytest.mark.parametrize("tc", test_cases, ids=lambda tc: tc.name)
def test_sign_without_cache(benchmark, tc):
    sk, _ = keygen(tc.n, tc.h, tc.d, tc.a, tc.k, tc.w)
    message = secrets.token_bytes(32)

    benchmark.pedantic(
        sign,
        args=(message, sk, tc.n, tc.h, tc.d, tc.a, tc.k, tc.w),
        rounds=3,
        warmup_rounds=1,
    )


@pytest.mark.benchmark(group="sign-c")
@pytest.mark.parametrize("tc", test_cases, ids=lambda tc: tc.name)
def test_sign_with_cache(benchmark, tc):
    cache = {}
    sk, _ = keygen(tc.n, tc.h, tc.d, tc.a, tc.k, tc.w, cache)
    assert len(cache) > 0

    benchmark.pedantic(
        sign,
        args=(random.randbytes(32), sk, tc.n, tc.h, tc.d, tc.a, tc.k, tc.w, True, cache),
        rounds=3,
        warmup_rounds=1
    )


@pytest.mark.benchmark(group="verify-wo-c")
@pytest.mark.parametrize("tc", test_cases, ids=lambda tc: tc.name)
def test_verify_without_cache(benchmark, tc):
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


@pytest.mark.benchmark(group="verify-c")
# caching should only affect signing time, so this is just a double-check
@pytest.mark.parametrize("tc", test_cases, ids=lambda tc: tc.name)
def test_verify_with_cache(benchmark, tc):
    cache = {}
    sk, pk = keygen(tc.n, tc.h, tc.d, tc.a, tc.k, tc.w, cache)

    message = random.randbytes(32)

    sig = sign(message, sk, tc.n, tc.h, tc.d, tc.a, tc.k, tc.w, True, cache)

    benchmark.pedantic(
        verify,
        args=(message, sig, pk, tc.n, tc.h, tc.d, tc.a, tc.k, tc.w),
        rounds=10,
        iterations=10,
        warmup_rounds=1
    )

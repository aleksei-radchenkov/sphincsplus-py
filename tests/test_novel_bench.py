import pytest
from sphincsplus import keygen, sign

# for these tests, we'll only vary the 'd' parameter.
# other benchmark tests with the cache are located in test_bench.py
N = 16
H = 16
A = 4
K = 4
W = 16

MSG = b"Hello, hello, hello!"


@pytest.mark.benchmark(group="varying")
@pytest.mark.parametrize("d", [2, 4, 8])
def test_sign_without_cache(benchmark, d):
    assert H % d == 0

    sk, _ = keygen(N, H, d, A, K, W)

    benchmark.pedantic(
        sign,
        args=(MSG, sk, N, H, d, A, K, W, True, None),
        rounds=5,
        warmup_rounds=1,
    )


@pytest.mark.benchmark(group="varying")
@pytest.mark.parametrize("d", [2, 4, 8])
def test_sign_with_cache(benchmark, d):
    assert H % d == 0

    cache = {}

    sk, _ = keygen(N, H, d, A, K, W, merkle_cache=cache)
    assert len(cache) > 0
    benchmark.pedantic(
        sign,
        args=(MSG, sk, N, H, d, A, K, W, True, cache),
        rounds=5,
        warmup_rounds=1,
    )

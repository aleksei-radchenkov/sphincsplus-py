#!/usr/bin/env python3
from typing import NamedTuple

import pyperf
from sphincsplus import keygen, sign, verify

runner = pyperf.Runner()

class TestCase(NamedTuple):
    name: str
    n: int
    h: int
    d: int
    a: int # log(t)
    k: int
    w: int
    m: int

test_cases = [
    TestCase("demo", 16, 8, 2, 4, 4, 16, 24),
    TestCase("SPHINCS+-128s", 16, 63, 7, 12, 14, 16, 133),
    TestCase("SPHINCS+-128f", 16, 66, 22, 6, 33, 16, 128),
    TestCase("SPHINCS+-192s", 24, 63, 7, 14, 17, 16, 193),
    TestCase("SPHINCS+-192f", 24, 66, 22, 8, 33, 16, 194),
    TestCase("SPHINCS+-256s", 32, 64, 8, 14, 22, 16, 255),
    TestCase("SPHINCS+-256f", 32, 68, 17, 9, 35, 16, 255),
]

for name, n, h, d, a, k, w, m in test_cases:
    print("start preparring", name)
    sk, pk = keygen(n, h, d, a, k, w, m)
    sig = sign(b"message", sk, n, h, d, a, k, w, m)
    # print(verify(b"message", sig, pk, n, h, d, a, k, w, m))

    print("start benchmarking", name)
    # runner.bench_func(name, keygen, n, h, d, a, k, w, m)
    # runner.bench_func(name, sign, b"message", sk, n, h, d, a, k, w, m)
    # runner.bench_func(name, verify, b"message", sig, pk, n, h, d, a, k, w, m)

    print("finish benchmarking", name)

# runner.timeit(name="sort a sorted list",
            #   stmt="sorted(s, key=f)",
            #   setup="f = lambda x: x; s = list(range(1000))")
#!/usr/bin/env python3
import time
from typing import NamedTuple

import pyperf
from sphincsplus import keygen, sign, verify

runner = pyperf.Runner()
program_start = time.perf_counter()


def log(message: str) -> None:
    elapsed = time.perf_counter() - program_start
    print(f"[{elapsed:8.2f}s] {message}")

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
    TestCase("SPHINCS+-256f", 32, 68, 17, 9, 35, 16, 255),
]

for name, n, h, d, a, k, w, m in test_cases:
    log("start")
    sk, pk = keygen(n, h, d, a, k, w, m)
    log("finished keygen")
    sig = sign(b"message", sk, n, h, d, a, k, w, m)
    log("finished sign")
    print(verify(b"message", sig, pk, n, h, d, a, k, w, m))
    log("finished verify")

# runner.timeit(name="sort a sorted list",
            #   stmt="sorted(s, key=f)",
            #   setup="f = lambda x: x; s = list(range(1000))")
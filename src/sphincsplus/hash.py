import hashlib
import math


def _hash(inp: bytes, length: int) -> bytes:
    return hashlib.shake_256(inp).digest(length)


def _mask_gen(pk_seed: bytes, adrs: bytes, inp: bytes) -> bytes:
    mask = _hash(pk_seed + adrs, len(inp))
    return bytes(x ^ y for x, y in zip(inp, mask))


def h_msg(r: bytes, pk_seed: bytes, pk_root: bytes, msg: bytes, m: int) -> bytes:
    return _hash(r + pk_seed + pk_root + msg, math.ceil(m / 8))


def prf(sk_seed: bytes, adrs: bytes) -> bytes:
    return _hash(sk_seed + adrs, len(sk_seed))


def prf_msg(sk_prf: bytes, opt_rand: bytes, msg: bytes) -> bytes:
    return _hash(sk_prf + opt_rand + msg, len(sk_prf))


def f(pk_seed: bytes, adrs: bytes, inp: bytes) -> bytes:
    n = len(pk_seed)
    return _hash(pk_seed + adrs + _mask_gen(pk_seed, adrs, inp), n)


def h(pk_seed: bytes, adrs: bytes, inp: bytes) -> bytes:
    n = len(pk_seed)
    return _hash(pk_seed + adrs + _mask_gen(pk_seed, adrs, inp), n)


def th(pk_seed: bytes, adrs: bytes, inp: bytes) -> bytes:
    n = len(pk_seed)
    return _hash(pk_seed + adrs + _mask_gen(pk_seed, adrs, inp), n)

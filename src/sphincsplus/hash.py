# Hash functions (SHAKE-256-robust)
# (Defined in https://sphincs.org/data/sphincs+-round3-specification.pdf, 7.2.1,
# pg. 38-39)
#
# h_msg = SHAKE_256(R || PK.seed || PK.root || M, 8m)
# prf = SHAKE_256(SEED || ADRS, 8n)
# prf_msg = SHAKE_256(SK.prf || OptRand || M, 8n)
#
# Tweak-funcs for the robust variant:
# f = SHAKE_256(PK.seed || ADRS || M1 (masked) 8n)
# h = SHAKE_256(PK.seed || ADRS || M1 (masked) || M2 (masked), 8n)
# tl = SHAKE_256(PK.seed || ADRS || M (masked), 8n)
#
# Mask M = m xor SHAKE_256(PK.seed || ADRS, l)

import hashlib

from .adrs import (_set_hash)


def _hash(inp: bytes, out_len: int) -> bytes:
    return hashlib.shake_256(inp).digest(out_len)


def _mask_gen(pk_seed: bytes, adrs: bytearray, m: bytes) -> bytes:
    mask = _hash(pk_seed + adrs, len(m))
    return bytes(x ^ y for x, y in zip(m, mask))


def _h_msg(r: bytes, pk_seed: bytes, pk_root: bytes, msg: bytes, m: int) -> bytes:
    return _hash(r + pk_seed + pk_root + msg, m)


def _prf(sk_seed: bytes, adrs: bytearray) -> bytes:
    return _hash(sk_seed + adrs, len(sk_seed))


def _prf_msg(sk_prf: bytes, opt_rand: bytes, msg: bytes) -> bytes:
    return _hash(sk_prf + opt_rand + msg, len(sk_prf))


def _f(pk_seed: bytes, adrs: bytearray, m1: bytes) -> bytes:
    mask = _mask_gen(pk_seed, adrs, m1)
    return _hash(pk_seed + adrs + mask, len(pk_seed))


def _h(pk_seed: bytes, adrs: bytearray, m1: bytes, m2: bytes) -> bytes:
    adrs_1 = bytearray(adrs)
    adrs_2 = bytearray(adrs)

    # All functions must be updating the addresses after each hash call.
    _set_hash(adrs_1, 0)
    _set_hash(adrs_2, 1)

    mask_m1 = _mask_gen(pk_seed, adrs_1, m1)
    mask_m2 = _mask_gen(pk_seed, adrs_2, m2)

    return _hash(pk_seed + adrs + mask_m1 + mask_m2, len(pk_seed))


def _tl(pk_seed: bytes, adrs: bytearray, m: bytes) -> bytes:
    mask = _mask_gen(pk_seed, adrs, m)
    return _hash(pk_seed + adrs + mask, len(pk_seed))

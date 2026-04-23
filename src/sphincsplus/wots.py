import math
from functools import lru_cache

from .adrs import (TYPE_WOTS_PK, _adrs_get_keypair, _adrs_set_chain,
                   _adrs_set_hash, _adrs_set_keypair, _adrs_set_type)
from .hash import _f, _prf, _tl


def _log_w(w: int) -> int:
    return int(math.log2(w))


@lru_cache(maxsize=None)
def _get_D(length: int, s: int, w: int) -> int:
    if s < 0 or s > length * (w - 1):
        return 0
    if length == 0:
        return 1 if s == 0 else 0

    res = 0
    for i in range(length + 1):
        sign = (-1) ** i
        comb_l_i = math.comb(length, i)
        val = s - i * w + length - 1
        if val >= length - 1:
            res += sign * comb_l_i * math.comb(val, length - 1)
    return res


def _constant_sum_encode(msg: bytes, length: int, w: int) -> list:
    s = (length * (w - 1)) // 2
    total = _get_D(length, s, w)

    x = int.from_bytes(msg, "big") % total
    v = [0] * length
    current_sum = s

    for i in range(length, 0, -1):
        chosen = min(w - 1, current_sum)
        for j in range(min(w - 1, current_sum) + 1):
            count = _get_D(i - 1, current_sum - j, w)
            if x < count:
                chosen = j
                break
            x -= count

        v[length - i] = chosen
        current_sum -= chosen

    return v


def get_len(n: int, w: int) -> int:
    return math.ceil((8 * n) / _log_w(w))


def chain(
    msg: bytes, start: int, steps: int, pk_seed: bytes, adrs: bytearray, w: int
) -> bytes | None:
    if start + steps > w - 1:
        return None

    tmp = msg
    for j in range(steps):
        _adrs_set_hash(adrs, start + j)
        tmp = _f(pk_seed, adrs, tmp)
    return tmp


def wots_gen_pk(
    sk_seed: bytes, pk_seed: bytes, adrs: bytearray, n: int, w: int
) -> bytes:
    pk_list = []
    pk_adrs = bytearray(adrs)
    length = get_len(n, w)

    for i in range(length):
        new_adrs = bytearray(adrs)
        _adrs_set_chain(new_adrs, i)
        _adrs_set_hash(new_adrs, 0)

        sk = _prf(sk_seed, new_adrs)
        pk_list.append(chain(sk, 0, w - 1, pk_seed, new_adrs, w))

    _adrs_set_type(pk_adrs, TYPE_WOTS_PK)
    _adrs_set_keypair(pk_adrs, _adrs_get_keypair(adrs))
    return _tl(pk_seed, pk_adrs, b"".join(pk_list))


def wots_sign(
    msg: bytes, sk_seed: bytes, pk_seed: bytes, adrs: bytearray, n: int, w: int
) -> list:
    length = get_len(n, w)
    msg_c = _constant_sum_encode(msg, length, w)

    sig = []
    for i in range(length):
        new_adrs = bytearray(adrs)
        _adrs_set_chain(new_adrs, i)
        _adrs_set_hash(new_adrs, 0)

        sk = _prf(sk_seed, new_adrs)
        sig.append(chain(sk, 0, msg_c[i], pk_seed, new_adrs, w))
    return sig


def wots_sig_to_pk(
    sig: list, msg: bytes, pk_seed: bytes, adrs: bytearray, n: int, w: int
) -> bytes:
    length = get_len(n, w)
    msg_c = _constant_sum_encode(msg, length, w)

    pk_list = []
    pk_adrs = bytearray(adrs)
    for i in range(length):
        new_adrs = bytearray(adrs)
        _adrs_set_chain(new_adrs, i)
        _adrs_set_hash(new_adrs, 0)

        pk_list.append(chain(sig[i], msg_c[i], w - 1 - msg_c[i], pk_seed, new_adrs, w))

    _adrs_set_type(pk_adrs, TYPE_WOTS_PK)
    _adrs_set_keypair(pk_adrs, _adrs_get_keypair(adrs))
    return _tl(pk_seed, pk_adrs, b"".join(pk_list))


def wots_verify(
    sig: list, msg: bytes, pk_seed: bytes, pk: bytes, adrs: bytearray, n: int, w: int
) -> bool:
    derived_pk = wots_sig_to_pk(sig, msg, pk_seed, adrs, n, w)
    return derived_pk == pk

import math

from .adrs import _set_hash, _set_chain, _set_type, _set_keypair, _get_keypair
from .adrs import TYPE_WOTS_PK

from .hash import _f, _prf, _tl


def _log_w(w: int) -> int:
    return int(math.log2(w))


def _get_len_1(n: int, w: int) -> int:
    return math.ceil((8 * n) / _log_w(w))


def _get_len_2(n: int, w: int) -> int:
    return math.floor(math.log2(_get_len_1(n, w) * (w - 1)) / _log_w(w)) + 1


def get_len(n: int, w: int) -> int:
    return _get_len_1(n, w) + _get_len_2(n, w)


def _base_w(msg: bytes, w: int, out_len: int) -> list:
    assert w in {4, 16, 256}
    assert out_len >= 0 and out_len <= (8 * len(msg)) // _log_w(w)

    out = []
    bits, val, i = 0, 0, 0

    for _ in range(out_len):
        if bits == 0:
            val = msg[i]
            i += 1
            bits += 8

        bits -= _log_w(w)
        out.append((val >> bits) & (w - 1))

    return out


def _int_to_base_w(inp: int, w: int, out_len: int) -> list:
    out = []
    for i in range(out_len):
        bits = _log_w(w) * (out_len - i - 1)
        out.append((inp >> bits) & (w - 1))
    return out


def _chain(msg: bytes, start: int, steps: int, pk_seed: bytes, adrs: bytearray, w: int) -> bytes:
    if steps == 0:
        return msg

    assert (start + steps) <= (w - 1)

    x = msg

    for j in range(steps):
        new_adrs = bytearray(adrs)
        _set_hash(new_adrs, start + j)
        x = _f(pk_seed, new_adrs, x)

    return x


def _gen_sk(sk_seed: bytes, adrs: bytearray, n: int, w: int) -> list:
    out = []
    for i in range(get_len(n, w)):
        new_adrs = bytearray(adrs)

        _set_chain(new_adrs, i)
        _set_hash(new_adrs, 0)

        out.append(_prf(sk_seed, new_adrs))

    return out


def gen_pk(sk_seed: bytes, pk_seed: bytes, adrs: bytearray, n: int, w: int) -> bytes:
    pk_list = []

    pk_adrs = bytearray(adrs)

    for i in range(get_len(n, w)):
        new_adrs = bytearray(adrs)

        _set_chain(new_adrs, i)
        _set_hash(new_adrs, 0)

        sk = _prf(sk_seed, new_adrs)
        pk_list.append(_chain(sk, 0, w - 1, pk_seed, new_adrs, w))

    _set_type(pk_adrs, TYPE_WOTS_PK)
    _set_keypair(pk_adrs, _get_keypair(adrs))

    return _tl(pk_seed, pk_adrs, b"".join(pk_list))


def _checksum(msg_w: list, w: int, n: int) -> list:
    s = sum(w - 1 - i for i in msg_w)
    return _int_to_base_w(s, w, _get_len_2(n, w))


def sign(msg: bytes, sk_seed: bytes, pk_seed: bytes, adrs: bytearray, n: int, w: int) -> list:
    msg_w = _base_w(msg, w, _get_len_1(n, w))
    csum = _checksum(msg_w, w, n)
    msg_c = msg_w + csum

    sig = []
    length = get_len(n, w)

    for i in range(length):
        new_adrs = bytearray(adrs)

        _set_chain(new_adrs, i)
        _set_hash(new_adrs, 0)

        sk = _prf(sk_seed, new_adrs)
        sig.append(_chain(sk, 0, msg_c[i], pk_seed, new_adrs, w))

    return sig


def sig_to_pk(sig: list, msg: bytes, pk_seed: bytes, adrs: bytearray, n: int, w: int) -> bytes:
    msg_w = _base_w(msg, w, _get_len_1(n, w))
    csum = _checksum(msg_w, w, n)
    msg_c = msg_w + csum

    pk_list = []
    pk_adrs = bytearray(adrs)

    for i in range(get_len(n, w)):
        new_adrs = bytearray(adrs)

        _set_chain(new_adrs, i)
        _set_hash(new_adrs, 0)

        pk_list.append(
            _chain(sig[i], 0, w - 1 - msg_c[i], pk_seed, new_adrs, w)
        )

    _set_type(pk_adrs, TYPE_WOTS_PK)
    _set_keypair(pk_adrs, _get_keypair(adrs))

    return _tl(pk_seed, pk_adrs, b"".join(pk_list))


def verify(sig: list, msg: bytes, pk_seed: bytes, pk: bytes, adrs: bytearray, n: int, w: int) -> bool:
    return sig_to_pk(sig, msg, pk_seed, adrs, n, w) == pk

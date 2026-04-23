# WOTS+ One-Time Signature Scheme
#
# Parameters:
#
# n - security paramter (length of message, keys and signature)
# w - Winternitz parameter (in set of {4, 16, 256})
#
# WOTS+ generates one-time signatures by iteratively hashing message into chains
# of hash outputs and revealing parts of it to create a signature.

import math

from .adrs import (
    _adrs_set_hash,
    _adrs_set_chain,
    _adrs_set_type,
    _adrs_set_keypair,
    _adrs_get_keypair,
    TYPE_WOTS_PK
)

from .hash import _f, _prf, _tl


def _log_w(w: int) -> int:
    return int(math.log2(w))


def _get_len_1(n: int, w: int) -> int:
    return math.ceil((8 * n) / _log_w(w))


def _get_len_2(n: int, w: int) -> int:
    return math.floor(math.log2(_get_len_1(n, w) * (w - 1)) / _log_w(w)) + 1

# len - the number of n-byte-string elements in WOTS+ keys and signature.


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


# Computes an iteration of F on an n-byte input.
def chain(msg: bytes, start: int, steps: int, pk_seed: bytes, adrs: bytearray, w: int) -> bytes | None:
    if start + steps > w - 1:
        return None

    if steps == 0:
        return msg

    tmp = msg

    for j in range(steps):
        new_adrs = bytearray(adrs)
        _adrs_set_hash(new_adrs, start + j)

        tmp = _f(pk_seed, new_adrs, tmp)

    return tmp


def _gen_sk(sk_seed: bytes, adrs: bytearray, n: int, w: int) -> list:
    out = []
    for i in range(get_len(n, w)):
        new_adrs = bytearray(adrs)

        _adrs_set_chain(new_adrs, i)
        _adrs_set_hash(new_adrs, 0)

        out.append(_prf(sk_seed, new_adrs))

    return out


def wots_gen_pk(sk_seed: bytes, pk_seed: bytes, adrs: bytearray, n: int, w: int) -> bytes:
    pk_list = []
    pk_adrs = bytearray(adrs)

    for i in range(get_len(n, w)):
        new_adrs = bytearray(adrs)
        _adrs_set_chain(new_adrs, i)
        _adrs_set_hash(new_adrs, 0)

        sk = _prf(sk_seed, new_adrs)
        pk_list.append(chain(sk, 0, w - 1, pk_seed, new_adrs, w))

    _adrs_set_type(pk_adrs, TYPE_WOTS_PK)
    _adrs_set_keypair(pk_adrs, _adrs_get_keypair(adrs))

    return _tl(pk_seed, pk_adrs, b"".join(pk_list))


def _checksum(msg_w: list, w: int, n: int) -> list:
    s = sum(w - 1 - i for i in msg_w)
    len_2 = _get_len_2(n, w)

    log_w = _log_w(w)
    if (log_w % 8) != 0:
        s = s << (8 - ((len_2 * log_w) % 8))

    len_2_bytes = math.ceil((len_2 * log_w) / 8)
    s_bytes = int(s).to_bytes(len_2_bytes, "big")

    return _base_w(s_bytes, w, len_2)


# Generates the WOTS+ one-time signature
def wots_sign(msg: bytes, sk_seed: bytes, pk_seed: bytes, adrs: bytearray, n: int, w: int) -> list:
    msg_w = _base_w(msg, w, _get_len_1(n, w))
    csum = _checksum(msg_w, w, n)
    msg_c = msg_w + csum

    sig = []
    length = get_len(n, w)

    for i in range(length):
        new_adrs = bytearray(adrs)

        _adrs_set_chain(new_adrs, i)
        _adrs_set_hash(new_adrs, 0)

        sk = _prf(sk_seed, new_adrs)
        sig.append(chain(sk, 0, msg_c[i], pk_seed, new_adrs, w))

    return sig


# Computes the WOTS+ public key from signature
def wots_sig_to_pk(sig: list, msg: bytes, pk_seed: bytes, adrs: bytearray, n: int, w: int) -> bytes:
    msg_w = _base_w(msg, w, _get_len_1(n, w))
    csum = _checksum(msg_w, w, n)
    msg_c = msg_w + csum

    pk_list = []
    pk_adrs = bytearray(adrs)

    for i in range(get_len(n, w)):
        new_adrs = bytearray(adrs)

        _adrs_set_chain(new_adrs, i)
        _adrs_set_hash(new_adrs, 0)

        pk_list.append(
            chain(sig[i], msg_c[i], w - 1 - msg_c[i], pk_seed, new_adrs, w)
        )

    _adrs_set_type(pk_adrs, TYPE_WOTS_PK)
    _adrs_set_keypair(pk_adrs, _adrs_get_keypair(adrs))

    return _tl(pk_seed, pk_adrs, b"".join(pk_list))


def wots_verify(sig: list, msg: bytes, pk_seed: bytes, pk: bytes, adrs: bytearray, n: int, w: int) -> bool:
    return wots_sig_to_pk(sig, msg, pk_seed, adrs, n, w) == pk

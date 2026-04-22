# WOTS+ implementation
# Reference - https://sphincs.org/data/sphincs+-round3-specification.pdf (pg. 13-18)

import math

from .adrs import *
from .hash import *


def log_w(w: int) -> int:
    return int(math.log2(w))


def get_len_1(n: int, w: int) -> int:
    return math.ceil((8 * n) / log_w(w))


def get_len_2(n: int, w: int) -> int:
    return math.floor(math.log2(get_len_1(n, w) * (w - 1)) / log_w(w)) + 1


def get_len(n: int, w: int) -> int:
    return get_len_1(n, w) + get_len_2(n, w)


def _base_w(msg: bytes, w: int, out_len: int) -> list:
    assert w in {4, 16, 256}
    assert out_len >= 0
    assert out_len <= (8 * len(msg)) // log_w(w)

    out = []
    bits, val, i = 0, 0, 0

    for _ in range(out_len):
        if bits == 0:
            val = msg[i]
            i += 1
            bits += 8

        bits -= log_w(w)
        out.append((val >> bits) & (w - 1))

    return out


def bytes_to_base_w(msg: bytes, w: int, out_len: int) -> list:
    return _base_w(msg, w, out_len)


def int_to_base_w(val: int, w: int, out_len: int) -> list:
    out = []
    bits = log_w(w)

    for i in range(out_len):
        shift = bits * (out_len - i - 1)
        out.append((val >> shift) & (w - 1))

    return out


def checksum(msg_base_w: list, w: int, n: int) -> list:
    s = sum(w - 1 - digit for digit in msg_base_w)

    return int_to_base_w(s, w, get_len_2(n, w))


def chain(inp: bytes, start: int, steps: int,
          pk_seed: bytes, layer: int, tree: int, keypair: int, chain_idx: int) -> bytes:
    out = inp

    for i in range(start, start + steps):
        adrs = new_hash_adrs(layer, tree, keypair, chain_idx, i)
        out = f(pk_seed, adrs_to_bytes(adrs), out)

    return out


def gen_sk(sk_seed: bytes, adrs: bytearray, n: int, w: int) -> list:
    return [
        prf(sk_seed,
            adrs_to_bytes(new_hash_adrs(get_layer(adrs),
                                        get_tree(adrs),
                                        get_keypair(adrs), i, 0)))

        for i in range(get_len(n, w))
    ]


def gen_pk(sk_seed: bytes, pk_seed: bytes, adrs: bytearray, n: int, w: int) -> bytes:
    sk = gen_sk(sk_seed, adrs, n, w)

    pk_list = [
        chain(sk[i], 0, w - 1,
              pk_seed, get_layer(adrs),
              get_tree(adrs), get_keypair(adrs), i)

        for i in range(get_len(n, w))
    ]

    return th(pk_seed,
              adrs_to_bytes(new_pk_adrs(get_layer(adrs),
                                        get_tree(adrs),
                                        get_keypair(adrs))), b"".join(pk_list))


def sign(msg: bytes, sk_seed: bytes, pk_seed: bytes,
         adrs: bytearray, n: int, w: int) -> list:
    sk = gen_sk(sk_seed, adrs, n, w)

    msg_w = bytes_to_base_w(msg, w, get_len_1(n, w))
    val = msg_w + checksum(msg_w, w, n)

    return [
        chain(sk[i], 0, val[i], pk_seed, get_layer(adrs), get_tree(adrs),
              get_keypair(adrs), i)

        for i in range(get_len(n, w))
    ]


def sig_to_pk(sig: list, msg: bytes, pk_seed: bytes,
              adrs: bytearray, n: int, w: int) -> bytes:
    msg_w = bytes_to_base_w(msg, w, get_len_1(n, w))
    val = msg_w + checksum(msg_w, w, n)

    pk = []

    for i in range(get_len(n, w)):

        pk.append(chain(
            sig[i],
            val[i],
            w - 1 - val[i],
            pk_seed,
            get_layer(adrs),
            get_tree(adrs),
            get_keypair(adrs),
            i,
        ))

    return th(pk_seed,
              adrs_to_bytes(
                  new_pk_adrs(get_layer(adrs),
                              get_tree(adrs), get_keypair(adrs))), b"".join(pk))


def verify(sig: list, msg: bytes, pk_seed: bytes,
           pk: bytes, adrs: bytearray, n: int, w: int) -> bool:
    return sig_to_pk(sig, msg, pk_seed, adrs, n, w) == pk

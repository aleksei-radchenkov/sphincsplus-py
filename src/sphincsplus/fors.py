from .adrs import (
    TYPE_FORS_ROOTS,
    TYPE_FORS_TREE,
    _set_keypair,
    _set_tree_height,
    _set_tree_idx,
    _set_type,
)
from .hash import _f, _prf, _tl
from .merkle import *


def msg_to_indices(msg_chunk: bytes, k: int, a: int) -> list:
    bits = 0
    val = 0
    indices = []

    for byte in msg_chunk:
        val = (val << 8) | byte
        bits += 8

        while bits >= a and len(indices) < k:
            bits -= a
            indices.append((val >> bits) & ((1 << a) - 1))
            val &= (1 << bits) - 1

    while len(indices) < k:
        indices.append(val & ((1 << a) - 1))
        val = 0

    return indices[:k]


def fors_leaf(sk_seed: bytes, pk_seed: bytes,
              adrs: bytearray, tree_idx: int, leaf_idx: int, n: int) -> bytes:
    sk_adrs = bytearray(adrs)
    _set_type(sk_adrs, TYPE_FORS_TREE)
    _set_keypair(sk_adrs, tree_idx)
    _set_tree_height(sk_adrs, 0)
    _set_tree_idx(sk_adrs, leaf_idx)
    sk_val = _prf(sk_seed, sk_adrs)

    leaf_adrs = bytearray(adrs)
    _set_type(leaf_adrs, TYPE_FORS_TREE)
    _set_keypair(leaf_adrs, tree_idx)
    _set_tree_height(leaf_adrs, 0)
    _set_tree_idx(leaf_adrs, leaf_idx)

    return _f(pk_seed, leaf_adrs, sk_val)


def fors_leafs(sk_seed: bytes, pk_seed: bytes,
               adrs: bytearray, tree_idx: int, a: int, n: int) -> list:
    return [
        fors_leaf(sk_seed, pk_seed, adrs, tree_idx, i, n)
        for i in range(1 << a)
    ]


def sign(msg_chunk: bytes, sk_seed: bytes, pk_seed: bytes,
         adrs: bytearray, k: int, a: int, n: int) -> tuple:
    indices = msg_to_indices(msg_chunk, k, a)
    sig_leafs = []
    sig_auth_paths = []

    for tree_idx in range(k):
        idx = indices[tree_idx]
        leafs = fors_leafs(sk_seed, pk_seed, adrs, tree_idx, a, n)

        sk_adrs = bytearray(adrs)
        _set_type(sk_adrs, TYPE_FORS_TREE)
        _set_keypair(sk_adrs, tree_idx)
        _set_tree_height(sk_adrs, 0)
        _set_tree_idx(sk_adrs, idx)
        sig_leafs.append(_prf(sk_seed, sk_adrs))

        _, auth = get_root_path(pk_seed, adrs, leafs, idx, TYPE_FORS_TREE)
        sig_auth_paths.append(auth)

    return sig_leafs, sig_auth_paths


def pk_from_sig(sig_leafs: list, sig_auth: list, indices: list,
                pk_seed: bytes, adrs: bytearray, k: int, a: int, n: int) -> bytes:
    roots = []
    for tree_idx in range(k):
        idx = indices[tree_idx]

        leaf_adrs = bytearray(adrs)
        _set_type(leaf_adrs, TYPE_FORS_TREE)
        _set_keypair(leaf_adrs, tree_idx)
        _set_tree_height(leaf_adrs, 0)
        _set_tree_idx(leaf_adrs, idx)
        leaf = _f(pk_seed, leaf_adrs, sig_leafs[tree_idx])

        root = root_from_path(leaf, idx, sig_auth[tree_idx],
                              pk_seed, adrs, TYPE_FORS_TREE)
        roots.append(root)

    pk_adrs = bytearray(adrs)
    _set_type(pk_adrs, TYPE_FORS_ROOTS)

    return _tl(pk_seed, pk_adrs, b"".join(roots))


def gen_pk(sk_seed: bytes, pk_seed: bytes,
           adrs: bytearray, k: int, a: int, n: int) -> bytes:
    roots = []

    # print("here")

    for tree_idx in range(k):
        leafs = fors_leafs(sk_seed, pk_seed, adrs, tree_idx, a, n)
        root = get_root(pk_seed, adrs, leafs, TYPE_FORS_TREE)
        roots.append(root)

    pk_adrs = bytearray(adrs)
    _set_type(pk_adrs, TYPE_FORS_ROOTS)

    # print(pk);

    return _tl(pk_seed, pk_adrs, b"".join(roots))


def verify(sig_leafs: list, sig_auth: list, msg_chunk: bytes,
           pk_seed: bytes, pk: bytes, adrs: bytearray,
           k: int, a: int, n: int) -> bool:
    indices = msg_to_indices(msg_chunk, k, a)

    return pk_from_sig(sig_leafs, sig_auth, indices, pk_seed, adrs, k, a, n) == pk

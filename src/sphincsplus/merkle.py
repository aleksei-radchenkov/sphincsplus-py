# Reference - https://sphincs.org/data/sphincs+-round3-specification.pdf
# pg. 15-25
#
# Tree Parameters:
#
# h - the height of the tree (lvl nums)
# n - the length of messages/nodes in bytes
# w - WOTS constant

from .adrs import (
    TYPE_TREE,
    TYPE_WOTS_HASH,
    _adrs_set_keypair,
    _adrs_set_type,
    _adrs_set_tree_height,
    _adrs_set_tree_idx,
)

from .hash import _h
from .wots import (wots_gen_pk, wots_sign, wots_sig_to_pk)


def _get_leaf_pk(
    sk_seed: bytes,
    pk_seed: bytes,
    adrs: bytearray,
    idx: int,
    n: int,
    w: int
) -> bytes:
    leaf_adrs = bytearray(adrs)

    _adrs_set_type(leaf_adrs, TYPE_WOTS_HASH)
    _adrs_set_keypair(leaf_adrs, idx)

    return wots_gen_pk(sk_seed, pk_seed, leaf_adrs, n, w)


# Ref - algo. 7 (4.1.3)
def tree_hash(
    sk_seed: bytes,
    pk_seed: bytes,
    adrs: bytearray,
    start_idx: int,
    height: int,
    n: int,
    w: int,
) -> bytes:
    assert start_idx % (1 << height) == 0

    stack = []

    for i in range(1 << height):
        node = _get_leaf_pk(sk_seed, pk_seed, adrs, start_idx + i, n, w)
        node_height = 0

        while stack and stack[-1][1] == node_height:
            tree_adrs = bytearray(adrs)
            _adrs_set_type(tree_adrs, TYPE_TREE)
            _adrs_set_tree_height(tree_adrs, node_height + 1)
            _adrs_set_tree_idx(tree_adrs, (start_idx + i) >> (node_height + 1))

            node = _h(pk_seed, tree_adrs, stack.pop()[0], node)
            node_height += 1

        stack.append([node, node_height])

    return stack.pop()[0]


# Ref - algo. 8 (4.1.4)
def merkle_pk_gen(sk_seed: bytes, pk_seed: bytes, adrs:  bytearray, height:
                  int, n: int, w: int) -> bytes:
    return tree_hash(sk_seed, pk_seed, adrs, 0, height, n, w)


# Ref - algo. 9 (4.1.6)
def merkle_sign(
    msg: bytes,
    sk_seed: bytes,
    pk_seed: bytes,
    adrs: bytearray,
    idx: int,
    height: int,
    n: int,
    w: int,
) -> list[list[bytes]]:
    auth = []

    for j in range(height):
        start = ((idx // (1 << j)) ^ 1) * (1 << j)
        auth.append(tree_hash(sk_seed, pk_seed, adrs, start, j, n, w))

    wots_adrs = bytearray(adrs)

    _adrs_set_type(wots_adrs, TYPE_WOTS_HASH)
    _adrs_set_keypair(wots_adrs, idx)

    sig = wots_sign(msg, sk_seed, pk_seed, wots_adrs, n, w)

    return [sig, auth]


# Ref - algo. 10
def merkle_sig_to_pk(
    sig: list[list[bytes]],
    msg: bytes,
    pk_seed: bytes,
    adrs: bytearray,
    idx: int,
    n: int,
    w: int,
) -> bytes:
    wots_adrs = bytearray(adrs)

    _adrs_set_type(wots_adrs, TYPE_WOTS_HASH)
    _adrs_set_keypair(wots_adrs, idx)

    node = wots_sig_to_pk(sig[0], msg, pk_seed, wots_adrs, n, w)

    for k, j in enumerate(sig[1]):
        tree_adrs = bytearray(adrs)
        _adrs_set_type(tree_adrs, TYPE_TREE)
        _adrs_set_tree_height(tree_adrs, k + 1)
        _adrs_set_tree_idx(tree_adrs, idx >> (k + 1))

        if ((idx >> k) & 1) == 0:
            node = _h(pk_seed, tree_adrs, node, j)
        else:
            node = _h(pk_seed, tree_adrs, j, node)

    return node


def merkle_verify(
    sig: list[list[bytes]],
    msg: bytes,
    pk_seed: bytes,
    pk: bytes,
    adrs: bytearray,
    idx: int,
    n: int,
    w: int,
) -> bool:
    return merkle_sig_to_pk(sig, msg, pk_seed, adrs, idx, n, w) == pk

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
    _get_tree_idx,
    _get_tree_height,
    _set_keypair,
    _set_type,
    _set_tree_height,
    _set_tree_idx,
)

from .hash import _h
from . import wots


def _get_leaf_pk(
    sk_seed: bytes,
    pk_seed: bytes,
    adrs: bytearray,
    idx: int,
    n: int,
    w: int
) -> bytes:
    leaf_adrs = bytearray(adrs)

    _set_type(leaf_adrs, TYPE_WOTS_HASH)
    _set_keypair(leaf_adrs, idx)

    return wots.gen_pk(sk_seed, pk_seed, leaf_adrs, n, w)


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

        tree_adrs = bytearray(adrs)
        _set_type(tree_adrs, TYPE_TREE)
        _set_tree_height(tree_adrs, 1)
        _set_tree_idx(tree_adrs, start_idx + i)

        node_height = 0

        while stack and stack[-1][1] == node_height:
            _set_tree_idx(tree_adrs, (_get_tree_idx(tree_adrs) - 1) // 2)
            node = _h(pk_seed, tree_adrs, stack.pop()[0], node)
            _set_tree_height(tree_adrs, _get_tree_height(tree_adrs) + 1)
            node_height += 1

        stack.append([node, node_height])

    return stack.pop()[0]


def merkle_sign(
    msg: bytes,
    sk_seed: bytes,
    pk_seed: bytes,
    adrs: bytearray,
    idx: int,
    height: int,
    n: int,
    w: int,
) -> tuple[list[bytes], list[bytes]]:
    auth = []
    for j in range(height):
        k = (idx // (1 << j)) ^ 1
        auth.append(tree_hash(sk_seed, pk_seed, adrs, k * (1 << j), j, n, w))

    wots_adrs = bytearray(adrs)
    _set_type(wots_adrs, TYPE_WOTS_HASH)
    _set_keypair(wots_adrs, idx)
    wots_sig = wots.sign(msg, sk_seed, pk_seed, wots_adrs, n, w)

    return wots_sig, auth


def verify_root(
    wots_sig: list,
    msg: bytes,
    auth: list,
    pk_seed: bytes,
    adrs: bytearray,
    idx: int,
    n: int,
    w: int,
) -> bytes:
    wots_adrs = bytearray(adrs)
    _set_type(wots_adrs, TYPE_WOTS_HASH)
    _set_keypair(wots_adrs, idx)
    node = wots.sig_to_pk(wots_sig, msg, pk_seed, wots_adrs, n, w)

    tree_adrs = bytearray(adrs)
    _set_type(tree_adrs, TYPE_TREE)
    _set_tree_idx(tree_adrs, idx)

    for k, sibling in enumerate(auth):
        _set_tree_height(tree_adrs, k + 1)
        if (idx // (1 << k)) % 2 == 0:
            _set_tree_idx(tree_adrs, _get_tree_idx(tree_adrs) // 2)
            node = _h(pk_seed, tree_adrs, node, sibling)
        else:
            _set_tree_idx(tree_adrs, (_get_tree_idx(tree_adrs) - 1) // 2)
            node = _h(pk_seed, tree_adrs, sibling, node)

    return node

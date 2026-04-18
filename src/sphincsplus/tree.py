from .adrs import *
from .merkle import *


def hypertree_sign(
    msg: bytes,
    sk_seed: bytes,
    pk_seed: bytes,
    tree_idx: int,
    leaf_idx: int,
    h: int,
    d: int,
    n: int,
    w: int,
) -> list:
    height = h // d
    ht_sig = []

    curr_msg = msg
    curr_tree = tree_idx
    curr_leaf = leaf_idx

    for i in range(d):
        adrs = new()
        set_layer(adrs, i)
        set_tree(adrs, curr_tree)

        wots_sig, path = merkle_sign(
            curr_msg, sk_seed, pk_seed, adrs, curr_leaf, height, n, w)
        ht_sig.append((wots_sig, path))

        wots_adrs = copy_adrs(adrs)
        set_keypair(wots_adrs, curr_leaf)
        curr_msg = merkle_verify_root(
            wots_sig, curr_msg, path, pk_seed, wots_adrs, curr_leaf, n, w)
        curr_leaf = curr_tree & ((1 << height) - 1)
        curr_tree >>= height

    return ht_sig


def hypertree_verify(
    msg: bytes,
    ht_sig: list,
    pk_seed: bytes,
    pk_root: bytes,
    tree_idx: int,
    leaf_idx: int,
    h: int,
    d: int,
    n: int,
    w: int,
) -> bool:
    height = h // d

    curr_msg = msg
    curr_tree = tree_idx
    curr_leaf = leaf_idx

    for i in range(d):
        wots_sig, path = ht_sig[i]

        adrs = new()
        set_layer(adrs, i)
        set_tree(adrs, curr_tree)

        wots_adrs = copy_adrs(adrs)
        set_keypair(wots_adrs, curr_leaf)

        curr_msg = merkle_verify_root(
            wots_sig, curr_msg, path, pk_seed, wots_adrs, curr_leaf, n, w)
        curr_leaf = curr_tree & ((1 << height) - 1)
        curr_tree >>= height

    return curr_msg == pk_root


def calc_root(sk_seed: bytes, pk_seed: bytes, h: int, d: int, n: int, w: int) -> bytes:
    height = h // d
    adrs = new()
    set_layer(adrs, d - 1)
    set_tree(adrs, 0)
    return tree_hash(sk_seed, pk_seed, adrs, 0, height, n, w)

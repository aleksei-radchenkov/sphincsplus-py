from .adrs import (
    _adrs_new,
    _adrs_set_layer,
    _adrs_set_tree,
)

from .merkle import merkle_pk_gen, merkle_sig_to_pk, merkle_sign


# Generates the hypertree public key (hypertree root), which is used to generate all
# the WOTS+ private keys within the hypertree.
def hypertree_pk_gen(sk_seed: bytes, pk_seed: bytes, h: int, d: int, n: int, w: int,
                     merkle_cache: dict | None = None) -> bytes:
    adrs = _adrs_new()

    _adrs_set_layer(adrs, d - 1)
    _adrs_set_tree(adrs, 0)

    return merkle_pk_gen(sk_seed, pk_seed, adrs, h // d, n, w, merkle_cache)

# Generates the hypertree signature, made of (d) merkle signatures, each linking
# one layer of the hypertree from the bottom leaf up to the top root.


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
    merkle_cache: dict | None = None,
) -> list:
    height = h // d
    ht_sig = []

    adrs = _adrs_new()

    _adrs_set_layer(adrs, 0)
    _adrs_set_tree(adrs, tree_idx)

    # if d > 1, this first sign occurs at layer 0. Only cache if d = 1, i.e. top layer.
    sig = merkle_sign(msg, sk_seed,
                      pk_seed, adrs, leaf_idx,
                      height, n, w,
                      merkle_cache=merkle_cache if d == 1 else None)

    ht_sig.append(sig)

    root = merkle_sig_to_pk(sig, msg, pk_seed, adrs, leaf_idx, n, w)

    curr_tree = tree_idx
    curr_msg = root

    for i in range(1, d):
        curr_leaf = curr_tree & ((1 << height) - 1)
        curr_tree >>= height

        _adrs_set_layer(adrs, i)
        _adrs_set_tree(adrs, curr_tree)

        sig = merkle_sign(
            curr_msg, sk_seed,
            pk_seed, adrs,
            curr_leaf,
            height, n, w,
            merkle_cache=merkle_cache if i == d - 1 else None
        )

        ht_sig.append(sig)

        root = merkle_sig_to_pk(sig, curr_msg, pk_seed, adrs, curr_leaf, n, w)

        if i < d - 1:
            curr_msg = root

    return ht_sig


# Verifies the hyper tree signature by reconstructing the root node, by
# iteratively verifying the merkle signatures up to layer d-1.
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

    adrs = _adrs_new()

    wots_sig, auth_path = ht_sig[0]

    _adrs_set_layer(adrs, 0)
    _adrs_set_tree(adrs, tree_idx)

    node = merkle_sig_to_pk(
        [wots_sig, auth_path],
        msg,
        pk_seed,
        adrs,
        leaf_idx,
        n,
        w
    )

    for j in range(1, d):

        leaf_idx = tree_idx & ((1 << height) - 1)
        tree_idx = tree_idx >> height

        wots_sig, auth_path = ht_sig[j]

        _adrs_set_layer(adrs, j)
        _adrs_set_tree(adrs, tree_idx)

        node = merkle_sig_to_pk(
            [wots_sig, auth_path],
            node,
            pk_seed,
            adrs,
            leaf_idx,
            n,
            w
        )

    return node == pk_root

from .adrs import *
from .hash import *
from . import wots


def get_leaf_pk(
    sk_seed: bytes, pk_seed: bytes, adrs: bytearray, idx: int, n: int, w: int
) -> bytes:
    leaf_adrs = copy_adrs(adrs)

    set_type(leaf_adrs, TYPE_WOTS_HASH)
    set_keypair(leaf_adrs, idx)

    return wots.gen_pk(sk_seed, pk_seed, leaf_adrs, n, w)


def get_root(
    pk_seed: bytes,
    adrs: bytearray,
    leafs: list,
    adrs_type: int,
    start: int = 0,
) -> bytes:
    tree = list(leafs)
    base = copy_adrs(adrs)

    for i in range(1, len(leafs).bit_length()):
        parents = []

        for j in range(0, len(tree), 2):
            node_adrs = new_node_adrs(
                base, adrs_type, i, (start >> i) + j // 2)
            parent = h(pk_seed, adrs_to_bytes(
                node_adrs), tree[j] + tree[j + 1])
            parents.append(parent)

        tree = parents
    return tree[0]


def get_root_path(
    pk_seed: bytes,
    adrs: bytearray,
    leafs: list,
    idx: int,
    adrs_type: int,
) -> tuple[bytes, list[bytes]]:
    auth = []
    layer = list(leafs)
    height = len(leafs).bit_length() - 1
    j = idx

    for i in range(1, height + 1):
        auth.append(layer[j ^ 1])
        j //= 2

        layer = [
            h(pk_seed, adrs_to_bytes(new_node_adrs(
                adrs, adrs_type, i, m // 2)), layer[m] + layer[m + 1])
            for m in range(0, len(layer), 2)
        ]

    return layer[0], auth


def root_from_path(
    leaf: bytes,
    idx: int,
    auth: list,
    pk_seed: bytes,
    adrs: bytearray,
    adrs_type: int,
) -> bytes:
    node = leaf
    j = idx

    for i, sibling in enumerate(auth, start=1):
        adrs = new_node_adrs(adrs, adrs_type, i, j // 2)

        if (j & 1) == 0:
            node = h(pk_seed, adrs_to_bytes(adrs), node + sibling)
        else:
            node = h(pk_seed, adrs_to_bytes(adrs), sibling + node)

        j //= 2
    return node


def get_layer_root(
    sk_seed: bytes,
    pk_seed: bytes,
    adrs: bytearray,
    start_idx: int,
    height: int,
    n: int,
    w: int,
) -> bytes:
    leafs = [
        get_leaf_pk(sk_seed, pk_seed, adrs, start_idx + i, n, w)
        for i in range(1 << height)
    ]

    return get_root(pk_seed, adrs, leafs, TYPE_TREE, start_idx)


def get_merkle_path(
    sk_seed: bytes,
    pk_seed: bytes,
    adrs: bytearray,
    idx: int,
    height: int,
    n: int,
    w: int,
) -> tuple[bytes, list[bytes]]:
    leafs = [
        get_leaf_pk(sk_seed, pk_seed, adrs, i, n, w)
        for i in range(1 << height)
    ]

    return get_root_path(pk_seed, adrs, leafs, idx, TYPE_TREE)


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
    wots_adrs = copy_adrs(adrs)
    set_keypair(wots_adrs, idx)

    wots_sig = wots.sign(msg, sk_seed, pk_seed, wots_adrs, n, w)
    _, auth = get_merkle_path(sk_seed, pk_seed, adrs, idx, height, n, w)

    return wots_sig, auth


def merkle_verify_root(
    wots_sig: list,
    msg: bytes,
    auth: list,
    pk_seed: bytes,
    adrs: bytearray,
    idx: int,
    n: int,
    w: int,
) -> bytes:
    leaf_pk = wots.sig_to_pk(wots_sig, msg, pk_seed, adrs, n, w)

    return root_from_path(leaf_pk, idx, auth, pk_seed, adrs, TYPE_TREE)


def tree_hash(sk_seed: bytes, pk_seed: bytes, adrs: bytearray, start_idx: int,
              height: int, n: int, w: int) -> bytes:
    leafs = [
        get_leaf_pk(sk_seed, pk_seed, adrs, start_idx + i, n, w)
        for i in range(1 << height)
    ]

    return get_root(pk_seed, adrs, leafs, TYPE_TREE, start_idx)

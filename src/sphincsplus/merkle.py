# Extended Merkle Signature SCheme
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


# REturns the root node of a tree of height 'height' with the leftmost leaf
# being the WOTS+ pk at index 'start_idx'
def tree_hash(
    sk_seed: bytes,
    pk_seed: bytes,
    adrs: bytearray,
    start_idx: int,
    height: int,
    n: int,
    w: int,
    merkle_cache: dict | None = None,
) -> bytes:
    assert start_idx % (1 << height) == 0

    key = (start_idx, height)
    # cache is only passed in if layer = d - 1, so merkle_cache stays constant in other layers
    if merkle_cache and key in merkle_cache:
        return merkle_cache[key]

    stack = []

    for i in range(1 << height):
        leaf_adrs = bytearray(adrs)

        _adrs_set_type(leaf_adrs, TYPE_WOTS_HASH)
        _adrs_set_keypair(leaf_adrs, start_idx + i)

        node = wots_gen_pk(sk_seed, pk_seed, leaf_adrs, n, w)
        node_height = 0
        node_index = start_idx + i

        tree_adrs = bytearray(adrs)
        _adrs_set_type(tree_adrs, TYPE_TREE)
        _adrs_set_tree_height(tree_adrs, 1)
        _adrs_set_tree_idx(tree_adrs, node_index)

        # merge nodes on stack to get parent
        while stack and stack[-1][1] == node_height:
            left_node, _, _ = stack.pop()

            tree_adrs = bytearray(adrs)
            _adrs_set_type(tree_adrs, TYPE_TREE)
            _adrs_set_tree_height(tree_adrs, node_height + 1)
            node_index = (node_index - 1) // 2
            _adrs_set_tree_idx(tree_adrs, node_index)

            node = _h(pk_seed, tree_adrs, left_node, node)

            node_height += 1

        if merkle_cache is not None:
            leftmost = node_index << node_height
            merkle_cache[(leftmost, node_height)] = node

        stack.append((node, node_height, node_index))

    # only root must remain
    assert len(stack) == 1
    return stack[0][0]


# Calculates the root of  the binary hash tree
def merkle_pk_gen(sk_seed: bytes, pk_seed: bytes, adrs:  bytearray, height:
                  int, n: int, w: int, merkle_cache: dict | None = None) -> bytes:
    return tree_hash(sk_seed, pk_seed, adrs, 0, height, n, w, merkle_cache)


# Returns the Merkle (XMSS) signature
def merkle_sign(
    msg: bytes,
    sk_seed: bytes,
    pk_seed: bytes,
    adrs: bytearray,
    idx: int,
    height: int,
    n: int,
    w: int,
    merkle_cache: dict | None = None,
) -> list[list[bytes]]:

    wots_adrs = bytearray(adrs)
    _adrs_set_type(wots_adrs, TYPE_WOTS_HASH)
    _adrs_set_keypair(wots_adrs, idx)

    sig = wots_sign(msg, sk_seed, pk_seed, wots_adrs, n, w)

    auth = []

    # build auth path
    for j in range(height):
        k = (idx >> j) ^ 1
        start = k << j

        auth.append(
            tree_hash(
                sk_seed,
                pk_seed,
                adrs,
                start,
                j,
                n,
                w,
                merkle_cache=merkle_cache
            )
        )

    return [sig, auth]


# Calculates the public key (root of the tree) from merkle signature.
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

    curr_idx = idx

    tree_adrs = bytearray(adrs)

    _adrs_set_type(tree_adrs, TYPE_TREE)
    _adrs_set_tree_idx(tree_adrs, idx)

    for k, auth_node in enumerate(sig[1]):
        _adrs_set_tree_height(tree_adrs, k + 1)

        if curr_idx % 2 == 0:
            _adrs_set_tree_idx(tree_adrs, curr_idx // 2)
            node = _h(pk_seed, tree_adrs, node, auth_node)
        else:
            _adrs_set_tree_idx(tree_adrs, (curr_idx - 1) // 2)
            node = _h(pk_seed, tree_adrs, auth_node, node)

        curr_idx //= 2

    return node


# Verify the merkle signature with public key
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

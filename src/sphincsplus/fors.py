from .adrs import *
from .hash import *
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
    sk_adrs = copy_adrs(adrs)
    set_type(sk_adrs, TYPE_FORS_PRF)
    set_keypair(sk_adrs, tree_idx)
    set_tree_height(sk_adrs, 0)
    set_tree_index(sk_adrs, leaf_idx)
    sk_val = prf(sk_seed, adrs_to_bytes(sk_adrs))

    leaf_adrs = copy_adrs(adrs)
    set_type(leaf_adrs, TYPE_FORS_TREE)
    set_keypair(leaf_adrs, tree_idx)
    set_tree_height(leaf_adrs, 0)
    set_tree_index(leaf_adrs, leaf_idx)

    return f(pk_seed, adrs_to_bytes(leaf_adrs), sk_val)


def fors_leafs(sk_seed: bytes, pk_seed: bytes,
               adrs: bytearray, tree_idx: int, a: int, n: int) -> list:
    return [
        fors_leaf(sk_seed, pk_seed, adrs, tree_idx, i, n)
        for i in range(1 << a)
    ]


# def sign(msg_chunk: bytes, sk_seed: bytes, pk_seed: bytes,
#          adrs: bytearray, k: int, a: int, n: int) -> tuple:
#     indices = msg_to_indices(msg_chunk, k, a)
#     sig_leafs = []
#     sig_auth_paths = []

#     for tree_idx in range(k):
#         idx = indices[tree_idx]
#         leafs = fors_leafs(sk_seed, pk_seed, adrs, tree_idx, a, n)

#         sk_adrs = copy_adrs(adrs)
#         set_type(sk_adrs, TYPE_FORS_PRF)
#         set_keypair(sk_adrs, tree_idx)
#         set_tree_height(sk_adrs, 0)
#         set_tree_index(sk_adrs, idx)
#         sig_leafs.append(prf(sk_seed, adrs_to_bytes(sk_adrs)))

#         _, auth = get_root_path(pk_seed, adrs, leafs, idx, TYPE_FORS_TREE)
#         sig_auth_paths.append(auth)

#     return sig_leafs, sig_auth_paths

def fors_treehash(sk_seed: bytes, s: int, z: int,
                  pk_seed: bytes, adrs: bytearray, tree_idx: int, cache: dict | None = None):
    if s % (1 << z) != 0: return -1

    stack = []

    for i in range(1 << z):
        sk_adrs = copy_adrs(adrs)
        set_type(sk_adrs, TYPE_FORS_PRF)
        set_keypair(sk_adrs, tree_idx)
        set_tree_height(sk_adrs, 0)
        set_tree_index(sk_adrs, s + i)
        sk = prf(sk_seed, adrs_to_bytes(sk_adrs))

        leaf_adrs = copy_adrs(adrs)
        set_type(leaf_adrs, TYPE_FORS_TREE)
        set_keypair(leaf_adrs, tree_idx)
        set_tree_height(leaf_adrs, 0)
        set_tree_index(leaf_adrs, s + i)
        node = f(pk_seed, adrs_to_bytes(leaf_adrs), sk)

        height = 0

        # spec: top node on stack has same height as node
        while stack and stack[-1][1] == height:
            left, _ = stack.pop()

            parent_adrs = copy_adrs(adrs)
            set_type(parent_adrs, TYPE_FORS_TREE)
            set_tree_height(parent_adrs, height + 1)
            # compute parent node's index (horizontal position) at this tree level
            set_tree_index(parent_adrs, (s + i) >> (height + 1))

            node = h(pk_seed, adrs_to_bytes(parent_adrs), left + node)
            height += 1

        stack.append((node, height))

    return stack.pop()[0]


def sign(msg_chunk: bytes, sk_seed: bytes, pk_seed: bytes,
         adrs: bytearray, k: int, a: int, n: int, cache: dict | None = None) -> tuple:
    indices = msg_to_indices(msg_chunk, k, a)
    sig_leafs = []
    sig_auth_paths = []
    t = 1 << a

    for tree_idx in range(k):
        idx = indices[tree_idx]

        sk_adrs = copy_adrs(adrs)
        set_type(sk_adrs, TYPE_FORS_PRF)
        set_keypair(sk_adrs, tree_idx)
        set_tree_height(sk_adrs, 0)
        set_tree_index(sk_adrs, idx)
        sig_leafs.append(prf(sk_seed, adrs_to_bytes(sk_adrs)))

        auth = []
        for j in range(a):
            sibling = (idx >> j) ^ 1;
            # start at that corresponding subtree
            start = sibling * (1 << j)

            node = fors_treehash(sk_seed, start, j, pk_seed, adrs, tree_idx, cache=cache)
            auth.append(node)

        sig_auth_paths.append(auth)

    return sig_leafs, sig_auth_paths


def pk_from_sig(sig_leafs: list, sig_auth: list, indices: list,
                pk_seed: bytes, adrs: bytearray, k: int, a: int, n: int) -> bytes:
    roots = []
    for tree_idx in range(k):
        idx = indices[tree_idx]

        leaf_adrs = copy_adrs(adrs)
        set_type(leaf_adrs, TYPE_FORS_TREE)
        set_keypair(leaf_adrs, tree_idx)
        set_tree_height(leaf_adrs, 0)
        set_tree_index(leaf_adrs, idx)
        leaf = f(pk_seed, adrs_to_bytes(leaf_adrs), sig_leafs[tree_idx])

        root = root_from_path(leaf, idx, sig_auth[tree_idx],
                              pk_seed, adrs, TYPE_FORS_TREE)
        roots.append(root)

    pk_adrs = copy_adrs(adrs)
    set_type(pk_adrs, TYPE_FORS_ROOTS)
    set_keypair(pk_adrs, get_keypair(adrs))

    return th(pk_seed, adrs_to_bytes(pk_adrs), b"".join(roots))


# def gen_pk(sk_seed: bytes, pk_seed: bytes,
#            adrs: bytearray, k: int, a: int, n: int) -> bytes:
#     roots = []

#     # print("here")

#     for tree_idx in range(k):
#         leafs = fors_leafs(sk_seed, pk_seed, adrs, tree_idx, a, n)
#         root = get_root(pk_seed, adrs, leafs, TYPE_FORS_TREE)
#         roots.append(root)

#     pk_adrs = copy_adrs(adrs)
#     set_type(pk_adrs, TYPE_FORS_ROOTS)

#     # print(pk);

#     return th(pk_seed, adrs_to_bytes(pk_adrs), b"".join(roots))

def gen_pk(sk_seed: bytes, pk_seed: bytes,
           adrs: bytearray, k: int, a: int, n: int, cache: dict | None = None) -> bytes:
    roots = []
    t = 1 << a

    for tree_idx in range(k):
        root = fors_treehash(sk_seed, 0, a, pk_seed, adrs, tree_idx, cache=cache)
        roots.append(root)

    pk_adrs = copy_adrs(adrs)
    set_type(pk_adrs, TYPE_FORS_ROOTS)
    set_keypair(pk_adrs, get_keypair(adrs))

    return th(pk_seed, adrs_to_bytes(pk_adrs), b"".join(roots))

def verify(sig_leafs: list, sig_auth: list, msg_chunk: bytes,
           pk_seed: bytes, pk: bytes, adrs: bytearray,
           k: int, a: int, n: int) -> bool:
    indices = msg_to_indices(msg_chunk, k, a)

    return pk_from_sig(sig_leafs, sig_auth, indices, pk_seed, adrs, k, a, n) == pk

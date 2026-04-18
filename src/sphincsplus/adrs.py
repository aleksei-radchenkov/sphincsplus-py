# for context, this structure is taken directly from:
# https://sphincs.org/data/sphincs+-round2-specification.pdf
# page 11, 2.7.3
#
# in short, its defined there smth like:
#
# layer addr (4 bytes) -> tree addr(12 bytes) -> type (4 bytes) -> depending on type:
# 1. WOTS+ hash address : keypair -> chain -> hash
# 2/5. WOTS+ pub key and FORS roots : keypair -> padding
# 3/4. hash tree : padding, tree height, tree index (same with FORS tree)
#
# Hence the constants ->

TYPE_WOTS_HASH = 0
TYPE_WOTS_PK = 1
TYPE_TREE = 2
TYPE_FORS_TREE = 3
TYPE_FORS_ROOTS = 4
TYPE_FORS_PRF = 5


def set_layer(adrs: bytearray, layer: int) -> None:
    adrs[0:4] = layer.to_bytes(4, "big")


def set_tree(adrs: bytearray, tree: int) -> None:
    adrs[4:16] = tree.to_bytes(12, "big")


def set_type(adrs: bytearray, addr_type: int) -> None:
    adrs[16:20] = addr_type.to_bytes(4, "big")
    adrs[20:32] = bytes(12)


def set_keypair(adrs: bytearray, kp: int) -> None:
    adrs[20:24] = kp.to_bytes(4, "big")


def set_chain(adrs: bytearray, chain: int) -> None:
    adrs[24:28] = chain.to_bytes(4, "big")


def set_hash(adrs: bytearray, hash_idx: int) -> None:
    adrs[28:32] = hash_idx.to_bytes(4, "big")


def set_tree_height(adrs: bytearray, height: int) -> None:
    adrs[24:28] = height.to_bytes(4, "big")


def set_tree_index(adrs: bytearray, index: int) -> None:
    adrs[28:32] = index.to_bytes(4, "big")


def get_layer(adrs: bytearray) -> int:
    return int.from_bytes(adrs[0:4], "big")


def get_tree(adrs: bytearray) -> int:
    return int.from_bytes(adrs[4:16], "big")


def get_type(adrs: bytearray) -> int:
    return int.from_bytes(adrs[16:20], "big")


def get_keypair(adrs: bytearray) -> int:
    return int.from_bytes(adrs[20:24], "big")


def get_chain(adrs: bytearray) -> int:
    return int.from_bytes(adrs[24:28], "big")


def get_hash_idx(adrs: bytearray) -> int:
    return int.from_bytes(adrs[28:32], "big")


def new() -> bytearray:
    return bytearray(32)


def new_hash_adrs(
    layer: int, tree: int, keypair: int, chain: int, hash_idx: int
) -> bytearray:
    out = new()
    set_layer(out, layer)
    set_tree(out, tree)
    set_type(out, TYPE_WOTS_HASH)
    set_keypair(out, keypair)
    set_chain(out, chain)
    set_hash(out, hash_idx)

    return out


def new_pk_adrs(layer: int, tree: int, keypair: int) -> bytearray:
    out = new()
    set_layer(out, layer)
    set_tree(out, tree)
    set_type(out, TYPE_WOTS_PK)
    set_keypair(out, keypair)

    return out


def new_tree_adrs(layer: int, tree: int, height: int, index: int) -> bytearray:
    out = new()
    set_layer(out, layer)
    set_tree(out, tree)
    set_type(out, TYPE_TREE)
    set_tree_height(out, height)
    set_tree_index(out, index)

    return out


def new_fors_tree_adrs(
    layer: int, tree: int, keypair: int, height: int, index: int
) -> bytearray:
    out = new()
    set_layer(out, layer)
    set_tree(out, tree)
    set_type(out, TYPE_FORS_TREE)
    set_keypair(out, keypair)
    set_tree_height(out, height)
    set_tree_index(out, index)

    return out


def new_roots_adrs(layer: int, tree: int, keypair: int) -> bytearray:
    out = new()
    set_layer(out, layer)
    set_tree(out, tree)
    set_type(out, TYPE_FORS_ROOTS)
    set_keypair(out, keypair)

    return out


def new_node_adrs(
    adrs: bytearray, addr_type: int, height: int, index: int
) -> bytearray:
    out = copy_adrs(adrs)
    set_type(out, addr_type)
    set_tree_height(out, height)
    set_tree_index(out, index)

    return out


def copy_adrs(adrs: bytearray) -> bytearray:
    return bytearray(adrs)


def adrs_to_bytes(adrs: bytearray) -> bytes:
    return bytes(adrs)

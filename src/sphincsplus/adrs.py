# Hash Function Address Scheme (ADRS)
# (Defined in https://sphincs.org/data/sphincs+-round3-specification.pdf, 2.7.3
# pg. 11-13)
#
# ADRS is a 32-byte value that follows the following structure:
# layer (hypertree) address (4 bytes) -> tree address (12 bytes) -> type (4
# bytes) -> type-specific fields (12 bytes, each field is 4 bytes, padded if too small)
#
# WOTS_HASH -> keypair, chain, hash
# WOTS_PK -> keypair
# TREE -> height, index
# FORS_TREE -> keypair, height, index
# FORS_ROOTS -> keypair
#
# All values are in big-endian))


TYPE_WOTS_HASH = 0
TYPE_WOTS_PK = 1
TYPE_TREE = 2
TYPE_FORS_TREE = 3
TYPE_FORS_ROOTS = 4


def _set_layer(adrs: bytearray, layer: int) -> None:
    adrs[0:4] = layer.to_bytes(4, "big")


def _set_tree(adrs: bytearray, tree: int) -> None:
    adrs[4:16] = tree.to_bytes(12, "big")


def _set_type(adrs: bytearray, addr_type: int) -> None:
    adrs[16:20] = addr_type.to_bytes(4, "big")
    adrs[20:32] = bytes(12)


def _set_keypair(adrs: bytearray, kp: int) -> None:
    adrs[20:24] = kp.to_bytes(4, "big")


def _set_chain(adrs: bytearray, chain: int) -> None:
    adrs[24:28] = chain.to_bytes(4, "big")


def _set_hash(adrs: bytearray, hash_idx: int) -> None:
    adrs[28:32] = hash_idx.to_bytes(4, "big")


def _set_tree_height(adrs: bytearray, height: int) -> None:
    adrs[24:28] = height.to_bytes(4, "big")


def _set_tree_idx(adrs: bytearray, index: int) -> None:
    adrs[28:32] = index.to_bytes(4, "big")


def _get_layer(adrs: bytearray) -> int:
    return int.from_bytes(adrs[0:4], "big")


def _get_tree(adrs: bytearray) -> int:
    return int.from_bytes(adrs[4:16], "big")


def _get_type(adrs: bytearray) -> int:
    return int.from_bytes(adrs[16:20], "big")


def _get_keypair(adrs: bytearray) -> int:
    return int.from_bytes(adrs[20:24], "big")


def _get_chain(adrs: bytearray) -> int:
    return int.from_bytes(adrs[24:28], "big")


def _get_hash(adrs: bytearray) -> int:
    return int.from_bytes(adrs[28:32], "big")


def _get_tree_height(adrs: bytearray) -> int:
    return int.from_bytes(adrs[24:28], "big")


def _get_tree_idx(adrs: bytearray) -> int:
    return int.from_bytes(adrs[28:32], "big")


def _new() -> bytearray:
    return bytearray(32)


def _new_base_adrs(layer: int, tree: int, addr_type: int):
    out = _new()
    _set_layer(out, layer)
    _set_tree(out, tree)
    _set_type(out, addr_type)
    return out


def _new_hash_adrs(layer: int, tree: int, keypair: int, chain: int, hash_idx: int) -> bytearray:
    out = _new_base_adrs(layer, tree, TYPE_WOTS_HASH)
    _set_keypair(out, keypair)
    _set_chain(out, chain)
    _set_hash(out, hash_idx)
    return out


def _new_pk_adrs(layer: int, tree: int, keypair: int) -> bytearray:
    out = _new_base_adrs(layer, tree, TYPE_WOTS_PK)
    _set_keypair(out, keypair)
    return out


def _new_tree_adrs(layer: int, tree: int, height: int, index: int) -> bytearray:
    out = _new_base_adrs(layer, tree, TYPE_TREE)
    _set_tree_height(out, height)
    _set_tree_idx(out, index)

    return out


def _new_fors_tree_adrs(layer: int, tree: int, keypair: int, height: int, index: int) -> bytearray:
    out = _new_base_adrs(layer, tree, TYPE_FORS_TREE)
    _set_keypair(out, keypair)
    _set_tree_height(out, height)
    _set_tree_idx(out, index)
    return out


def _new_roots_adrs(layer: int, tree: int, keypair: int) -> bytearray:
    out = _new_base_adrs(layer, tree, TYPE_FORS_ROOTS)
    _set_keypair(out, keypair)
    return out


def _new_node_adrs(adrs: bytearray, addr_type: int, height: int, index: int) -> bytearray:
    out = bytearray(adrs)

    _set_type(out, addr_type)
    _set_tree_height(out, height)
    _set_tree_idx(out, index)

    return out

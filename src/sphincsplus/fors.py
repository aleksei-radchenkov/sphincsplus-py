from .adrs import (
    TYPE_FORS_ROOTS,
    TYPE_FORS_TREE,
    _adrs_set_tree_height,
    _adrs_set_tree_idx,
    _adrs_set_type,
    _adrs_get_tree_height,
    _adrs_get_tree_idx
)

from .hash import _f, _h, _prf, _tl


def _fors_sk_gen(sk_seed: bytes, adrs: bytearray, idx: int) -> bytes:
    adr = bytearray(adrs)
    _adrs_set_type(adr, TYPE_FORS_TREE)
    _adrs_set_tree_height(adr, 0)
    _adrs_set_tree_idx(adr, idx)
    return _prf(sk_seed, adr)


def _msg_to_indices(msg: bytes, k: int, a: int) -> list:
    bitlen = k * a
    val = int.from_bytes(msg, "big")

    idxs = []
    for i in range(k):
        shift = bitlen - (i + 1) * a
        idxs.append((val >> shift) & ((1 << a) - 1))

    return idxs


def fors_treehash(sk_seed: bytes, pk_seed: bytes, start: int, height: int, adrs: bytearray) -> bytes:
    assert start % (1 << height) == 0

    stack = []

    for i in range(1 << height):
        new_adrs = bytearray(adrs)

        _adrs_set_type(new_adrs, TYPE_FORS_TREE)

        _adrs_set_tree_height(new_adrs, 0)
        _adrs_set_tree_idx(new_adrs, start + i)

        sk = _prf(sk_seed, new_adrs)
        node = _f(pk_seed, new_adrs, sk)

        node_height = 0

        _adrs_set_tree_height(new_adrs, 1)
        _adrs_set_tree_idx(new_adrs, start + i)

        while stack and stack[-1][1] == node_height:
            g = stack.pop()[0]

            _adrs_set_tree_idx(new_adrs, (_adrs_get_tree_idx(new_adrs) - 1) // 2)

            node = _h(pk_seed, new_adrs, g, node)

            _adrs_set_tree_height(new_adrs, _adrs_get_tree_height(new_adrs) + 1)

            node_height += 1

        stack.append([node, node_height])

    return stack.pop()[0]


def fors_pk_gen(sk_seed: bytes, pk_seed: bytes, adrs: bytearray, k: int, a: int) -> bytes:
    pk_adrs = bytearray(adrs)
    roots = []

    for i in range(k):
        roots.append(
            fors_treehash(sk_seed, pk_seed, i * (1 << a), a, pk_adrs)
        )

    _adrs_set_type(pk_adrs, TYPE_FORS_ROOTS)

    return _tl(pk_seed, pk_adrs, b"".join(roots))


def fors_sign(
    msg: bytes,
    sk_seed: bytes,
    pk_seed: bytes,
    adrs: bytearray,
    k: int,
    a: int,
) -> tuple[list[bytes], list[list[bytes]]]:
    idxs = _msg_to_indices(msg, k, a)

    sig_sk = []
    sig_auth = []

    t = 1 << a

    for i in range(k):
        idx = idxs[i]
        base = i * t

        new_adrs = bytearray(adrs)

        _adrs_set_type(new_adrs, TYPE_FORS_TREE)
        _adrs_set_tree_height(new_adrs, 0)
        _adrs_set_tree_idx(new_adrs, base + idx)

        sk = _prf(sk_seed, new_adrs)
        sig_sk.append(sk)

        auth = []

        for j in range(a):
            s = (idx // (1 << j)) ^ 1

            auth.append(
                fors_treehash(
                    sk_seed,
                    pk_seed,
                    base + s * (1 << j),
                    j,
                    new_adrs,
                )
            )

        sig_auth.append(auth)

    return sig_sk, sig_auth


def fors_sig_to_pk(
    sig: tuple[list[bytes], list[list[bytes]]],
    msg: bytes,
    pk_seed: bytes,
    adrs: bytearray,
    k: int,
    a: int,
) -> bytes:
    idxs = _msg_to_indices(msg, k, a)

    roots = []

    for i in range(k):
        idx = idxs[i]
        base = i * (1 << a)

        adr = bytearray(adrs)
        _adrs_set_type(adr, TYPE_FORS_TREE)
        _adrs_set_tree_height(adr, 0)
        _adrs_set_tree_idx(adr, base + idx)

        node = _f(pk_seed, adr, sig[0][i])

        for j in range(a):
            adr_j = bytearray(adrs)
            _adrs_set_type(adr_j, TYPE_FORS_TREE)
            _adrs_set_tree_height(adr_j, j + 1)

            if ((idx >> j) & 1) == 0:
                _adrs_set_tree_idx(adr_j, (base + idx) // (2 ** (j + 1)))
                node = _h(pk_seed, adr_j, node, sig[1][i][j])
            else:
                _adrs_set_tree_idx(adr_j, (base + idx - 1) // (2 ** (j + 1)))
                node = _h(pk_seed, adr_j, sig[1][i][j], node)

        roots.append(node)

    pk_adrs = bytearray(adrs)
    _adrs_set_type(pk_adrs, TYPE_FORS_ROOTS)

    return _tl(pk_seed, pk_adrs, b"".join(roots))


def fors_verify(
    sig: tuple[list[bytes], list[list[bytes]]],
    msg: bytes,
    pk_seed: bytes,
    pk: bytes,
    adrs: bytearray,
    k: int,
    a: int,
) -> bool:
    return fors_sig_to_pk(sig, msg, pk_seed, adrs, k, a) == pk

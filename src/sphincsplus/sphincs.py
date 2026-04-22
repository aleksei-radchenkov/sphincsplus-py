import secrets

from . import adrs
from . import fors
from . import tree
from . import wots
from .hash import _h_msg, _prf_msg


def _parse_bits(data: bytes, bitlen: int) -> int:
    if bitlen == 0:
        return 0
    val = int.from_bytes(data, "big")
    excess = len(data) * 8 - bitlen
    if excess > 0:
        val >>= excess
    return val


def digest_to_fors_and_idx(digest: bytes, k: int, a: int, h: int, d: int) -> tuple:
    height = h // d
    ka = k * a

    md_bytes_len = (ka + 7) // 8
    idx_tree_bits = h - height
    idx_tree_bytes_len = (idx_tree_bits + 7) // 8
    idx_leaf_bytes_len = (height + 7) // 8

    off = 0
    tmp_md = digest[off:off + md_bytes_len]
    off += md_bytes_len

    tmp_idx_tree = digest[off:off + idx_tree_bytes_len]
    off += idx_tree_bytes_len

    tmp_idx_leaf = digest[off:off + idx_leaf_bytes_len]

    md_int = _parse_bits(tmp_md, ka)
    idx_tree = _parse_bits(tmp_idx_tree, idx_tree_bits)
    idx_leaf = _parse_bits(tmp_idx_leaf, height)

    pad = md_bytes_len * 8 - ka
    md = ((md_int << pad).to_bytes(md_bytes_len, "big")) if md_bytes_len else b""

    return md, idx_tree, idx_leaf


def idx_to_tree_leaf(idx: int, h: int, d: int) -> tuple:
    height = h // d
    tree_idx = idx >> height
    leaf_idx = idx & ((1 << height) - 1)
    return tree_idx, leaf_idx


def _digest_bytes_len(h: int, d: int, k: int, a: int) -> int:
    height = h // d
    ka = k * a
    return (ka + 7) // 8 + (h - height + 7) // 8 + (height + 7) // 8


def sig_bytes_len(n: int, h: int, d: int, a: int, k: int, w: int) -> int:
    height = h // d
    ell = wots.get_len(n, w)
    fors_part = k * (n + a * n)
    ht_part = d * (ell * n + height * n)
    return n + fors_part + ht_part


def keygen(n: int, h: int, d: int, a: int, k: int, w: int) -> tuple:
    sk_seed = secrets.token_bytes(n)
    sk_prf = secrets.token_bytes(n)
    pk_seed = secrets.token_bytes(n)
    pk_root = tree.hypertree_pk_gen(sk_seed, pk_seed, h, d, n, w)

    sk = sk_seed + sk_prf + pk_seed + pk_root
    pk = pk_seed + pk_root
    return sk, pk


def sign(
    msg: bytes,
    sk: bytes,
    n: int,
    h: int,
    d: int,
    a: int,
    k: int,
    w: int,
    rand: bool = True,
) -> bytes:
    m = _digest_bytes_len(h, d, k, a)

    sk_seed = sk[0:n]
    sk_prf = sk[n:2 * n]
    pk_seed = sk[2 * n:3 * n]
    pk_root = sk[3 * n:4 * n]

    if rand:
        opt_rand = secrets.token_bytes(n)
    else:
        opt_rand = bytes(n)

    r = _prf_msg(sk_prf, opt_rand, msg)
    digest = _h_msg(r, pk_seed, pk_root, msg, m)
    msg_chunk, tree_idx, leaf_idx = digest_to_fors_and_idx(digest, k, a, h, d)

    fors_adrs = adrs._adrs_new()
    adrs._adrs_set_layer(fors_adrs, 0)
    adrs._adrs_set_tree(fors_adrs, tree_idx)
    adrs._adrs_set_keypair(fors_adrs, leaf_idx)

    sig_leafs, sig_auth = fors.fors_sign(msg_chunk, sk_seed, pk_seed, fors_adrs, k, a)
    fors_pk = fors.fors_pk_gen(sk_seed, pk_seed, fors_adrs, k, a)

    ht_sig = tree.hypertree_sign(
        fors_pk, sk_seed, pk_seed, tree_idx, leaf_idx, h, d, n, w)

    body_f = bytearray()
    for i in range(k):
        body_f.extend(sig_leafs[i])
        for node in sig_auth[i]:
            body_f.extend(node)

    body_ht = bytearray()
    for wots_sig, path in ht_sig:
        for blk in wots_sig:
            body_ht.extend(blk)
        for node in path:
            body_ht.extend(node)

    body = bytes(body_f) + bytes(body_ht)
    return r + body


def verify(
    msg: bytes,
    sig: bytes,
    pk: bytes,
    n: int,
    h: int,
    d: int,
    a: int,
    k: int,
    w: int,
) -> bool:
    m = _digest_bytes_len(h, d, k, a)

    if len(pk) != 2 * n:
        return False

    if len(sig) != sig_bytes_len(n, h, d, a, k, w):
        return False

    pk_seed = pk[0:n]
    pk_root = pk[n:2 * n]

    r = sig[0:n]
    body = sig[n:]

    digest = _h_msg(r, pk_seed, pk_root, msg, m)
    msg_chunk, tree_idx, leaf_idx = digest_to_fors_and_idx(digest, k, a, h, d)

    height = h // d
    ell = wots.get_len(n, w)

    fors_part_len = k * (n + a * n)

    if len(body) != fors_part_len + d * (ell * n + height * n):
        return False

    fors_buf = body[:fors_part_len]
    ht_buf = body[fors_part_len:]

    need_f = k * (n + a * n)

    if len(fors_buf) < need_f:
        return False

    sig_leafs = []
    sig_auth = []

    o = 0

    for _ in range(k):
        sig_leafs.append(fors_buf[o:o + n])
        o += n
        path = []

        for _ in range(a):
            path.append(fors_buf[o:o + n])
            o += n

        sig_auth.append(path)

    if fors_buf[o:]:
        return False

    need_ht = d * (ell * n + height * n)

    if len(ht_buf) < need_ht:
        return False

    ht_sig = []
    o = 0

    for _ in range(d):
        wots_sig = []

        for _ in range(ell):
            wots_sig.append(ht_buf[o:o + n])
            o += n

        path = []

        for _ in range(height):
            path.append(ht_buf[o:o + n])
            o += n

        ht_sig.append((wots_sig, path))

    if ht_buf[o:]:
        return False

    fors_adrs = adrs._adrs_new()
    adrs._adrs_set_layer(fors_adrs, 0)
    adrs._adrs_set_tree(fors_adrs, tree_idx)
    adrs._adrs_set_keypair(fors_adrs, leaf_idx)

    fors_pk = fors.fors_sig_to_pk(
        (sig_leafs, sig_auth), msg_chunk, pk_seed, fors_adrs, k, a)

    return tree.hypertree_verify(
        fors_pk, ht_sig, pk_seed, pk_root, tree_idx, leaf_idx, h, d, n, w)

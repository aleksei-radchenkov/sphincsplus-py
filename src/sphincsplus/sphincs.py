import secrets

from . import adrs
from . import hash
from . import fors
from . import tree
from . import wots


def digest_to_fors_and_idx(digest: bytes, m: int, k: int, a: int, h: int) -> tuple:
    val = 0

    for b in digest:
        val = (val << 8) | b

    excess = len(digest) * 8 - m

    if excess:
        val >>= excess

    idx = val & ((1 << h) - 1)
    md = (val >> h) & ((1 << (k * a)) - 1)
    ka = k * a
    nbytes = (ka + 7) // 8
    pad = nbytes * 8 - ka
    msg_chunk = ((md << pad).to_bytes(nbytes, "big")) if nbytes else b""

    return msg_chunk, idx


def idx_to_tree_leaf(idx: int, h: int, d: int) -> tuple:
    height = h // d
    tree_idx = idx >> height
    leaf_idx = idx & ((1 << height) - 1)
    return tree_idx, leaf_idx


def sig_bytes_len(n: int, h: int, d: int, a: int, k: int, w: int, m: int) -> int:
    height = h // d
    ell = wots.get_len(n, w)
    fors_part = k * (n + a * n)
    ht_part = d * (ell * n + height * n)
    return n + fors_part + ht_part


def keygen(n: int, h: int, d: int, a: int, k: int, w: int, m: int) -> tuple:
    sk_seed = secrets.token_bytes(n)
    sk_prf = secrets.token_bytes(n)
    pk_seed = secrets.token_bytes(n)
    pk_root = tree.calc_root(sk_seed, pk_seed, h, d, n, w)

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
    m: int,
    rand: bool = True,
) -> bytes:
    sk_seed = sk[0:n]
    sk_prf = sk[n:2 * n]
    pk_seed = sk[2 * n:3 * n]
    pk_root = sk[3 * n:4 * n]

    if rand:
        opt_rand = secrets.token_bytes(n)
    else:
        opt_rand = bytes(n)

    r = hash.prf_msg(sk_prf, opt_rand, msg)
    digest = hash.h_msg(r, pk_seed, pk_root, msg, m)
    msg_chunk, idx = digest_to_fors_and_idx(digest, m, k, a, h)
    tree_idx, leaf_idx = idx_to_tree_leaf(idx, h, d)

    fors_adrs = adrs.new()
    adrs.set_layer(fors_adrs, 0)
    adrs.set_tree(fors_adrs, tree_idx)
    adrs.set_keypair(fors_adrs, leaf_idx)

    sig_leafs, sig_auth = fors.sign(msg_chunk, sk_seed, pk_seed, fors_adrs, k, a, n)
    fors_pk = fors.gen_pk(sk_seed, pk_seed, fors_adrs, k, a, n)

    ht_sig = tree.hypertree_sign(
        fors_pk, sk_seed, pk_seed, tree_idx, leaf_idx, h, d, n, w)

    body_f = bytearray()
    for i in range(k):
        body_f += sig_leafs[i]
        for node in sig_auth[i]:
            body_f += node

    body_ht = bytearray()
    for wots_sig, path in ht_sig:
        for blk in wots_sig:
            body_ht += blk
        for node in path:
            body_ht += node

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
    m: int,
) -> bool:
    if m != k * a + h:
        return False

    if len(pk) != 2 * n:
        return False

    if len(sig) != sig_bytes_len(n, h, d, a, k, w, m):
        return False

    pk_seed = pk[0:n]
    pk_root = pk[n:2 * n]

    r = sig[0:n]
    body = sig[n:]

    digest = hash.h_msg(r, pk_seed, pk_root, msg, m)
    msg_chunk, idx = digest_to_fors_and_idx(digest, m, k, a, h)
    tree_idx, leaf_idx = idx_to_tree_leaf(idx, h, d)

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

    fors_adrs = adrs.new()
    adrs.set_layer(fors_adrs, 0)
    adrs.set_tree(fors_adrs, tree_idx)
    adrs.set_keypair(fors_adrs, leaf_idx)

    indices = fors.msg_to_indices(msg_chunk, k, a)
    fors_pk = fors.pk_from_sig(
        sig_leafs, sig_auth, indices, pk_seed, fors_adrs, k, a, n)

    return tree.hypertree_verify(
        fors_pk, ht_sig, pk_seed, pk_root, tree_idx, leaf_idx, h, d, n, w)

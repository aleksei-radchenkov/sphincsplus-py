import secrets

from .adrs import (
    _adrs_new,
    _adrs_set_layer,
    _adrs_set_tree,
    _adrs_set_keypair,
)

from . import fors
from . import tree
from . import wots
from .hash import _h_msg, _prf_msg


def digest_to_fors_and_idx(digest: bytes, k: int, a: int, h: int, d: int):
    val = int.from_bytes(digest, "big")

    total_bits = len(digest) * 8
    used_bits = k * a + h

    if total_bits > used_bits:
        val >>= (total_bits - used_bits)

    idx_leaf_len = h // d
    idx_tree_len = h - idx_leaf_len
    md_len = k * a

    idx_leaf = val & ((1 << idx_leaf_len) - 1)
    val >>= idx_leaf_len

    idx_tree = val & ((1 << idx_tree_len) - 1)
    val >>= idx_tree_len

    md = val & ((1 << md_len) - 1)

    nbytes = (md_len + 7) // 8
    return md.to_bytes(nbytes, "big"), idx_tree, idx_leaf


def sig_bytes_len(n: int, h: int, d: int, a: int, k: int, w: int, m: int) -> int:
    height = h // d
    ell = wots.get_len(n, w)
    return n + k * (n + a * n) + d * (ell * n + height * n)


def keygen(n: int, h: int, d: int, a: int, k: int, w: int, m: int):
    sk_seed = secrets.token_bytes(n)
    sk_prf = secrets.token_bytes(n)
    pk_seed = secrets.token_bytes(n)

    pk_root = tree.hypertree_pk_gen(sk_seed, pk_seed, h, d, n, w)

    sk = sk_seed + sk_prf + pk_seed + pk_root
    pk = pk_seed + pk_root

    return sk, pk


def sign(msg: bytes, sk: bytes, n: int, h: int, d: int, a: int, k: int, w: int, m: int, rand: bool = True):

    sk_seed = sk[:n]
    sk_prf = sk[n:2 * n]
    pk_seed = sk[2 * n:3 * n]
    pk_root = sk[3 * n:4 * n]

    opt = secrets.token_bytes(n) if rand else bytes(n)
    r = _prf_msg(sk_prf, opt, msg)

    digest = _h_msg(r, pk_seed, pk_root, msg, m)
    md, idx_tree, idx_leaf = digest_to_fors_and_idx(digest, k, a, h, d)

    fors_adrs = _adrs_new()
    _adrs_set_layer(fors_adrs, 0)
    _adrs_set_tree(fors_adrs, idx_tree)
    _adrs_set_keypair(fors_adrs, idx_leaf)

    sig_fors = fors.fors_sign(md, sk_seed, pk_seed, fors_adrs, k, a)
    sig_leafs, sig_auth = sig_fors

    fors_pk = fors.fors_sig_to_pk(sig_fors, md, pk_seed, fors_adrs, k, a)

    ht_sig = tree.hypertree_sign(
        fors_pk,
        sk_seed,
        pk_seed,
        idx_tree,
        idx_leaf,
        h,
        d,
        n,
        w,
    )

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

    return r + bytes(body_f) + bytes(body_ht)


def verify(msg: bytes, sig: bytes, pk: bytes, n: int, h: int, d: int, a: int, k: int, w: int, m: int):

    if m != k * a + h or len(pk) != 2 * n:
        return False

    pk_seed = pk[:n]
    pk_root = pk[n:]

    r = sig[:n]
    body = sig[n:]

    digest = _h_msg(r, pk_seed, pk_root, msg, m)
    md, idx_tree, idx_leaf = digest_to_fors_and_idx(digest, k, a, h, d)

    height = h // d
    ell = wots.get_len(n, w)

    fors_len = k * (n + a * n)
    ht_len = d * (ell * n + height * n)

    if len(body) != fors_len + ht_len:
        return False

    fors_buf = body[:fors_len]
    ht_buf = body[fors_len:]

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

    fors_adrs = _adrs_new()
    _adrs_set_layer(fors_adrs, 0)
    _adrs_set_tree(fors_adrs, idx_tree)
    _adrs_set_keypair(fors_adrs, idx_leaf)

    sig_fors = [sig_leafs, sig_auth]

    fors_pk = fors_sig_to_pk(sig_fors, md, pk_seed, fors_adrs, k, a)

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

    return tree.hypertree_verify(
        fors_pk,
        ht_sig,
        pk_seed,
        pk_root,
        idx_tree,
        idx_leaf,
        h,
        d,
        n,
        w,
    )

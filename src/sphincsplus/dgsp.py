from hashlib import shake_256

from . import sphincs
from . import wots
from . import tree
from . import fors
from . import adrs
import secrets
from collections import namedtuple

SetupParameter = namedtuple('SetupParameter', ['h', 'd', 'k', 't'])
SecretKey = namedtuple('SecretKey', ['msk', 'sk'])
PublicParameter = namedtuple('PublicParameter', ['pk', 'rl'])

_state_m = {}
next_id = 0

# n: security parameter in bytes
# setup_param: a tuple of (h, d, k, t) where:
#   h: total height of the hypertree
#   d: number of layers in the hypertree
#   k: number of FORS trees
#   t: number of WOTS+ signatures per FORS tree
# returns: (sk, pp) where:
#   sk: managers secret key (msk, SK)
#  pp: public parameters (PK, RL)


def group_keygen(n: int, setup_param: SetupParameter) -> tuple[SecretKey, PublicParameter]:
    msk1, msk2 = secrets.token_bytes(n), secrets.token_bytes(n)
    msk = (msk1, msk2)
    sk, pk = sphincs.keygen(n, setup_param.h, setup_param.d, 0, setup_param.k, setup_param.t, 16)
    gsk = SecretKey(msk=msk, sk=sk)
    pp = PublicParameter(pk=pk, rl=[])

    return gsk, pp


def join(username: str, state_m, SK: SecretKey) -> (int, int, int):
    for k, v in state_m.items():
        if v['username'] == username:
            raise ValueError("Username already exists")
    id = next_id
    next_id += 1
    cred_id = shake_256(SK.msk[0] + id).digest()
    secret_id = shake_256(id + cred_id).digest()
    state_m[id] = {
        'username': username,
        'state': {'ctr_m': 0, 'flag_id': True}
    }  # flag id active

    # user is doing this stuff now, they should have id, secret_id
    id_seed = secrets.token_bytes(16)
    id_state = {"id": id, "secret_id": secret_id, "id_seed": id_seed, "ctr_user": 0, "ctr_m": 0, "R": [], "C": []}
    return id, id_state

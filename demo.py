#!/bin/python3

from sphincsplus import keygen, sign, verify

n, h, d, a, k, w, m = 16, 8, 2, 4, 4, 16, 24
sk, pk = keygen(n, h, d, a, k, w)

msg = b"Hello world!"

sig = sign(msg, sk, n, h, d, a, k, w)

if verify(msg, sig, pk, n, h, d, a, k, w):
    print("Verification successful, as expected!")
else:
    print("Verification failed, the package has an error!")

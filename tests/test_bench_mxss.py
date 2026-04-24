# this is probably the wrong library
# import pytest
# from XMSS import *


# @pytest.mark.comparison
# def test_xmss_keygen(benchmark, tc):
#     other = pytest.importorskip("otherlib")

#     messages = [bytearray(b'0e4575aa2c51') * 10_000]

#     height = int(log2(len(messages)))
#     msg_len = len(messages[0]) // 2
#     w = 16

#     benchmark.pedantic(
#         XMSS_keyGen,
#         args=(height, msg_len, w),
#         rounds=3,
#         warmup_rounds=1
#     )


# @pytest.mark.comparison
# def test_xmss_sign(benchmark, tc):
#     messages = [bytearray(b'0e4575aa2c51') * 10_000]

#     height = int(log2(len(messages)))
#     msg_len = len(messages[0]) // 2
#     w = 16

#     pk, sk = XMSS_keyGen(height, msg_len, w)

#     benchmark.pedantic(
#         XMSS_sign,
#         args=(messages[0], sk),
#         rounds=3,
#         warmup_rounds=1
#     )


# @pytest.mark.comparison
# def test_xmss_verify(benchmark, tc):
#     messages = [bytearray(b'0e4575aa2c51') * 10_000]

#     height = int(log2(len(messages)))
#     msg_len = len(messages[0]) // 2
#     w = 16

#     pk, sk = XMSS_keyGen(height, msg_len, w)

#     sig = XMSS_sign(messages[0], sk)

#     benchmark.pedantic(
#         XMSS_verify,
#         args=(messages[0], sig, pk),
#         rounds=10,
#         warmup_rounds=1
#     )

import random
import pytest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes


@pytest.mark.comparison
def test_classical_keygen(benchmark, tc):
    benchmark.pedantic(
        ec.generate_private_key,
        args=(ec.SECP256R1(),),
        rounds=10,
        iterations=100,
        warmup_rounds=5
    )


@pytest.mark.comparison
def test_classical_sign(benchmark, tc):
    private_key = ec.generate_private_key(ec.SECP256R1())
    message = random.randbytes(32)

    benchmark.pedantic(
        private_key.sign,
        args=(message, ec.ECDSA(hashes.SHA256())),
        rounds=10,
        iterations=100,
        warmup_rounds=5
    )


@pytest.mark.comparison
def test_classical_verify(benchmark, tc):
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    message = random.randbytes(32)
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    benchmark.pedantic(
        public_key.verify,
        args=(signature, message, ec.ECDSA(hashes.SHA256())),
        rounds=10,
        iterations=100,
        warmup_rounds=5
    )


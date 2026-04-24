import random
import pytest

# Comparison dependencies are optional unless --run-comparisons is used.
ec = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ec")
hashes = pytest.importorskip("cryptography.hazmat.primitives.hashes")


@pytest.mark.comparison
def test_classical_keygen(benchmark):
    benchmark.pedantic(
        ec.generate_private_key,
        args=(ec.SECP256R1(),),
        rounds=10,
        iterations=1000,
        warmup_rounds=5
    )


@pytest.mark.comparison
def test_classical_sign(benchmark):
    private_key = ec.generate_private_key(ec.SECP256R1())
    message = random.randbytes(32)

    benchmark.pedantic(
        private_key.sign,
        args=(message, ec.ECDSA(hashes.SHA256())),
        rounds=10,
        iterations=1000,
        warmup_rounds=5
    )


@pytest.mark.comparison
def test_classical_verify(benchmark):
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    message = random.randbytes(32)
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

    benchmark.pedantic(
        public_key.verify,
        args=(signature, message, ec.ECDSA(hashes.SHA256())),
        rounds=10,
        iterations=1000,
        warmup_rounds=5
    )


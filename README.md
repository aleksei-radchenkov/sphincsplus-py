# Sphincs+Py
A python implementation of the Sphincs+ post-quantum signature scheme.

The original paper can be found here: [The SPHINCS+ Signature Framework](https://eprint.iacr.org/2019/1086.pdf).

## Installation

Install [Docker](https://www.docker.com/get-started/).

## Usage

The key parameters are:
- `n`: the security parameter, controlling the length of hashes, seeds, and signature elements, etc (in bytes). A larger `n `increases security but also increases key and signature sizes.
- `w`: the Winternitz parameter, controlling the length of the hash chains in WOTS+, where a larger `w` reduces signature size at the cost of slower signing and verification.
- `h`: total height of the hypertree, which determines the maximum number of signatures that can be produced under a single keypair (`2^h`).
- `d`: number of layers the hypertree is split into, which trades off signing speed against key generation speed. A larger `d` means more layers to sign through but a shallower tree per layer.
- `k` and `a`:  the FORS parameters. `k` is the number of FORS trees and `a` is their height. These parameters control the security/size of the FORS component.
- `m`: the message digest length in bytes

The file [/sphincs.py](src/sphincsplus/sphincs.py) holds the main SPHINCS+ functions.

It is possible to run the program in two ways: through an interactive Python Console, and through a python script.

### Interactive Python Console

To start the console, use the following command:

```bash
docker build -t sphincsplus . && docker run -it sphincsplus
```

Once inside the console, you can run arbitrary Python code and inspect variables.

```
Interactive Sphincs+ Console.
>>> n, h, d, a, k, w, m = 16, 8, 2, 4, 4, 16, 24
>>> sk, pk = keygen(n, h, d, a, k, w, m)
>>> sig = sign(msg, sk, n, h, d, a, k, w, m, rand=False)
>>> verify(msg, sig, pk, n, h, d, a, k, w, m)
True
>>> print(pk)
b"9h\xefCCv\xa5\xd8\x19|'\x91M\xe11\xfd\xe6\xdd\xdbP\xfbK\xb7I\x03\xeb*\r\xe9\xd4j\x96"
```

### Python Script

You can also run code in [demo.py](/demo.py). After you finish writing the code, you can run it using the following command.

```bash
docker build -t sphincsplus . && docker run -it sphincsplus python3 demo.py
```

## Optimisation Notes

By default, the Python code will not include our first novel optimisation (caching) when run through `demo.py` or the Interactive Sphincs+ Console, as the `merkle_cache` parameter for `keygen` and `sign` in [/sphincs.py](src/sphincsplus/sphincs.py) defaults to `None`. You must initialise an empty cache hashmap and pass it as the the last argument of `keygen` and `sign`. This is already handled in the tests and the benchmarks. 

## Tests

Execute the following commands to run the tests:

```bash
docker build -t sphincsplus .
docker run --rm sphincsplus pytest tests/ -q
```

The status of the unit tests and linting on the main branch is currently
![CI Status](https://github.com/aleksei-radchenkov/sphincsplus-py/actions/workflows/ci.yml/badge.svg).

## Benchmarking

Execute the following command to perform benchmarking locally:

```bash
docker build -t sphincsplus .
docker run --rm sphincsplus pytest --benchmark-only
```

Use the following command to perform comparative benchmarking to other cryptographic schemes:
```bash
docker build --build-arg WITH_COMPARISON=1 -t sphincsplus .
docker run --rm sphincsplus pytest --benchmark-only --run-comparisons
```

At the moment we compare to 2 other cryptographic schemes:
1 A classical signature signing algorithm using eleptic curve cryptography built into Python's standard library
2. Annother post-quantum signature signing algorithm implementing XMSS, but which is stateful unlike Sphincs+.

The standard benchmarking also automatically runs on every push and PR, and it can be found in the _Test_ section of the _test_ job in each _ci_ workflow, and the recent runs can be found [here](https://github.com/aleksei-radchenkov/sphincsplus-py/actions/workflows/ci.yml).

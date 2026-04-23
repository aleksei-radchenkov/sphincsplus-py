# Sphincs+Py

A python implementation of the Sphincs+ post-quantum signature scheme.

The original paper can be found here: [The SPHINCS+ Signature Framework](https://eprint.iacr.org/2019/1086.pdf).

## Installation

Install [Docker](https://www.docker.com/get-started/).

## Usage

n : the security parameter in bytes.
w : the Winternitz parameter as defined in Section 3.1.
h : the height of the hypertree as defined in Section 4.2.1.
d : the number of layers in the hypertree as defined in Section 4.2.1.
k : the number of trees in FORS as defined in Section 5.1.
t : the number of leaves of a FORS tree as defined in Section 5.1
m : the message digest length in bytes

_TODO: Firstly explain the signatures of sphincs keygen, sign, and verify.
Do we need to expose any additional functions and explain them for usage? I think we should document all the functions in `__all__` in `__init__.py` (or remove them if we don't intend users to import them)._

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

## Tests

Execute the following commands to run the tests:

```bash
docker build -t sphincsplus .
docker run --rm sphincsplus pytest tests/ -q
```

## Benchmarking

Execute the following command to perform benchmarking locally:

```bash
docker build -t sphincsplus .
docker run --rm sphincsplus pytest --benchmark-only
```

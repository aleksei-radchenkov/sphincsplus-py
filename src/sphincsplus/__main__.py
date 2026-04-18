from .sphincs import keygen, sign, verify


def main():
    n, h, d, a, k, w, m = 16, 8, 2, 4, 4, 16, 24
    sk, pk = keygen(n, h, d, a, k, w, m)

    msg = b"hello world ? :p"

    sig = sign(msg, sk, n, h, d, a, k, w, m, rand=False)

    print("ok" if verify(msg, sig, pk, n, h, d,
                         a, k, w, m) else "cooked af")


if __name__ == "__main__":
    main()

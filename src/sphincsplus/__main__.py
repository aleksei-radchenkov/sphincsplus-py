import code

from .sphincs import keygen, sign, verify


def main():
    namespace = {
        "keygen": keygen,
        "sign": sign,
        "verify": verify,
    }
    code.interact(banner="Interactive Sphincs+ Console.", local=namespace)


if __name__ == "__main__":
    main()

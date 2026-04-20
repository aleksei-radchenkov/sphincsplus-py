from .sphincs import keygen, sign, verify
import code

def main():
    namespace = globals().copy()
    namespace.update(locals())
    code.interact(banner="Interactive Sphincs+ Console.", local=namespace)


if __name__ == "__main__":
    main()

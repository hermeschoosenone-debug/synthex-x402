"""`python3 -m synthex_x402` entrypoint."""
import sys

from . import _main

if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))

import os
import sys

from .cli import main as _main


def main():
    try:
        sys.exit(_main() or 0)
    except Exception:
        if os.getenv('PPROTECT_ENABLE_DEBUG'):
            import pdb
            pdb.post_mortem()
        raise


if __name__ == '__main__':
    main()

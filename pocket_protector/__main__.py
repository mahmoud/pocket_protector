import sys

from .cli import main as _main
from .file_keys import _env_flag


def main():
    try:
        sys.exit(_main() or 0)
    except Exception:
        if _env_flag('PPROTECT_ENABLE_DEBUG'):
            import pdb
            pdb.post_mortem()
        raise


if __name__ == '__main__':
    main()

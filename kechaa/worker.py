"""Private worker entry point, run only by the daemon in an isolated interpreter."""

import os
import sys
from pathlib import Path

# Resolve imports from the installed, administrator-owned application directory.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kechaa.bootstrap import configure
configure()

from kechaa.common import MAX_MESSAGE, KechaaError, decode


def main() -> int:
    if sys.platform != "linux":
        return 126
    from kechaa.backends.linux import worker
    try:
        config = decode(sys.stdin.buffer.read(MAX_MESSAGE + 1))
        return worker(config)
    except (KechaaError, OSError, KeyError, ValueError):
        # Do not serialize private grant contents or interpreter exception locals.
        return 126


if __name__ == "__main__":
    code = main()
    os._exit(code if code >= 0 else 128 - code)

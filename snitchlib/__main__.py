# -*- coding: utf-8 -*-
"""Allow ``python -m snitchlib`` as an alternative to ``python snitch.py``."""

import sys

from .cli import main


if __name__ == "__main__":
    sys.exit(main())

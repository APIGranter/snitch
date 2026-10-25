#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SNItch - network traffic analyzer (command-line entry point).

This file is intentionally tiny: the implementation lives in the
``snitchlib`` package.  Running ``python snitch.py`` keeps the 1.x command
line and output layout, and importing ``snitchlib`` is now possible for tests
and integrations.

    python snitch.py capture.pcapng --target example.com
    python snitch.py --live eth0 --duration 60 --open
    python snitch.py --help
"""

import os
import sys

# When the script is started through a symlink or from another working
# directory, make sure the package next to it is importable.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from snitchlib.cli import main  # noqa: E402  (path setup must run first)


if __name__ == "__main__":
    sys.exit(main())

#
#  Copyright 2026, Tony Cheng. All rights reserved.
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#

import sys
from pathlib import Path

REQUIRED_MAJOR = 3
REQUIRED_MINOR = 12

if sys.version_info < (REQUIRED_MAJOR, REQUIRED_MINOR):
    print(
        f"[ERROR] Python {REQUIRED_MAJOR}.{REQUIRED_MINOR}+ is required.\n"
        f"        You are using Python {sys.version_info.major}.{sys.version_info.minor}\n"
    )
    sys.exit(1)

if not (getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")):
    src_dir = Path(__file__).resolve().parents[1]
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))

from InsydeGerritCodeDownloader.core import main


if __name__ == "__main__":
    main()

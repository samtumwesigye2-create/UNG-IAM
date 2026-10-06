#!/usr/bin/env python3
"""JANUS production pre-deploy tasks.

Keep one explicit Railway pre-deploy entry while preserving each task's
independent fail-closed behavior.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> int:
    for script in ("reset_human_login.py", "seed_tax_service_identity.py"):
        subprocess.run([sys.executable, str(ROOT / script)], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

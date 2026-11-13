"""Maintenance commands: ``python -m src.cli <command>`` from the project directory.

    python -m src.cli encryption-key status     how many encrypted values each key holds
    python -m src.cli encryption-key rotate     add a new ENCRYPTION_KEY, re-encrypt everything, retire the old one

Reads the same configuration as main.py (``--config``, ``.env``, the environment). Safe to run while MCP Gate is
running; see src/encryption_rotation.py.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def parse_args(argv=None):
    parser = argparse.ArgumentParser(prog="python -m src.cli", description="MCP Gate maintenance commands")
    parser.add_argument("--config", default="config/config.yaml")
    sub = parser.add_subparsers(dest="command", required=True)
    enc = sub.add_parser("encryption-key", help="ENCRYPTION_KEY keyring: status and rotation")
    enc.add_argument("action", choices=["status", "rotate"])
    enc.add_argument("--settle-seconds", type=float, default=3.0,
                     help="how long to let a running server pick up a new key before checking again (default 3)")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    load_dotenv(PROJECT_ROOT / ".env")
    args = parse_args(argv)
    from src.config import Config

    Config.set_config(args.config)
    from db.database import make_session
    from src import encryption_rotation as rotation
    from src.utils.secrets_store import migrate_legacy_store

    migrate_legacy_store()
    db = make_session()
    try:
        if args.action == "status":
            print("Encrypted values by key:")
            print(rotation.describe(rotation.status(db)))
            return 0
        try:
            rotation.rotate(db, settle_seconds=args.settle_seconds)
        except rotation.RotationRefused as e:
            print(f"Refused: {e}", file=sys.stderr)
            return 2
        print("Encrypted values by key:")
        print(rotation.describe(rotation.status(db)))
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())

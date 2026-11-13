"""Split an MCP Gate 1.3 config/config.yaml into the five config files of 1.4.

    uv run python scripts/split_config.py                     # config/config.yaml -> config/ (refuses to overwrite)
    uv run python scripts/split_config.py --force             # replace the five committed files with your edits
    uv run python scripts/split_config.py --old old.yaml --out-dir /tmp/cfg

Each section is copied verbatim, with its comments and ${VAR} references, into the file that holds it. Values are
never printed. Afterwards both configurations are loaded (with this process's environment plus .env, as the
server does) and compared field by field; the script exits 1 if they differ. See docs/reference.md, "Upgrading
to 1.4".
"""

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402
from dotenv import dotenv_values  # noqa: E402

from src.config.layout import CONFIG_FILES  # noqa: E402
from src.config.manager import expand_env_vars, load_config_dir  # noqa: E402
from src.config.model import ConfigModel  # noqa: E402
from src.config.split import split_text, write_files  # noqa: E402


def compare(old_text: str, out_dir: Path) -> list:
    """Dotted paths whose value differs between the old file and the five new files (empty = identical)."""
    old = ConfigModel(**expand_env_vars(yaml.safe_load(old_text) or {})).model_dump()
    new = ConfigModel(**expand_env_vars(load_config_dir(out_dir))).model_dump()
    diffs = []

    def walk(a, b, path):
        if isinstance(a, dict) and isinstance(b, dict):
            for key in sorted(set(a) | set(b)):
                walk(a.get(key), b.get(key), f"{path}.{key}" if path else key)
        elif a != b:
            diffs.append(path)

    walk(old, new, "")
    return diffs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--old", default="config/config.yaml", help="the 1.3 config file to split")
    ap.add_argument("--out-dir", default="config", help="where the five files are written")
    ap.add_argument("--env-file", default=str(ROOT / ".env"),
                    help="the .env the server reads (used to expand ${VAR} for the check; '' = none)")
    ap.add_argument("--force", action="store_true", help="replace existing files")
    ap.add_argument("--no-check", action="store_true", help="skip the field-by-field comparison")
    args = ap.parse_args(argv)

    old_path, out_dir = Path(args.old), Path(args.out_dir)
    if not old_path.is_file():
        print(f"error: {old_path} not found", file=sys.stderr)
        return 2
    old_text = old_path.read_text(encoding="utf-8")
    try:
        files, unknown = split_text(old_text)
        write_files(files, out_dir, force=args.force)
    except (ValueError, FileExistsError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(f"Wrote {', '.join(CONFIG_FILES)} to {out_dir}/")
    for section in unknown:
        print(f"note: section '{section}' is not an MCP Gate setting and was left out")

    if args.no_check:
        return 0
    if args.env_file and Path(args.env_file).is_file():
        for key, value in dotenv_values(args.env_file).items():
            if value is not None:
                os.environ.setdefault(key, value)
    diffs = compare(old_text, out_dir)
    if diffs:
        print("CHECK FAILED: fields that differ from the old config: " + ", ".join(diffs))
        return 1
    print(f"Check passed: the five files equal {old_path} field by field. Move {old_path} away: it is no longer "
          "read, and MCP Gate logs an error while it is there.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

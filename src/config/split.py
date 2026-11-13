"""Split an MCP Gate 1.3 ``config/config.yaml`` into the five files of 1.4 (used by ``scripts/split_config.py``).

The split is textual: each top-level section is copied verbatim, with the comment lines directly above it, into
the file that holds it (``layout.FILE_SECTIONS``). ``${VAR}`` references and comments survive unchanged, and no
value is expanded or printed.
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple

import yaml

from src.config.layout import CONFIG_FILES, FILE_SECTIONS, file_for

_TOP_LEVEL_KEY = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:")

_HEADER = """# MCP Gate configuration ({name}), split from config.yaml by scripts/split_config.py.
# The configuration is five files in this directory, merged at startup; a key may be set in one file only.
"""


def split_text(text: str) -> Tuple[Dict[str, str], List[str]]:
    """Split the old file's text by section. Returns (file name -> content for all five files, unknown sections).

    Raises ValueError when the text is not a YAML mapping, or when a section appears twice."""
    data = yaml.safe_load(text)
    if data is not None and not isinstance(data, dict):
        raise ValueError("the old config file is not a mapping of settings")
    chunks: Dict[str, List[str]] = {name: [] for name in CONFIG_FILES}
    unknown: List[str] = []
    seen: set = set()
    pending: List[str] = []       # comment / blank lines waiting for the next section
    current: List[str] | None = None
    for line in text.splitlines():
        match = _TOP_LEVEL_KEY.match(line)
        if match:
            section = match.group(1)
            if section in seen:
                raise ValueError(f"section '{section}' appears twice in the old config file")
            seen.add(section)
            target = file_for(section)
            if target is None:
                unknown.append(section)
                current = None
                pending = []
                continue
            # Comments directly above the section belong to it; a blank line cuts them off (the file header)
            lead: List[str] = []
            for p in reversed(pending):
                if not p.strip():
                    break
                lead.insert(0, p)
            current = chunks[target]
            if current:
                current.append("")
            current.extend(lead)
            current.append(line)
            pending = []
        elif line.startswith((" ", "\t")) and line.strip() and current is not None:
            current.extend(pending)
            pending = []
            current.append(line)
        elif not line.strip() or line.lstrip().startswith("#"):
            pending.append(line)
        else:
            current = None
            pending = []
    files = {}
    for name in CONFIG_FILES:
        body = "\n".join(chunks[name]).strip("\n")
        sections = ", ".join(FILE_SECTIONS[name])
        files[name] = _HEADER.format(name=sections) + ("\n" + body + "\n" if body else "")
    return files, unknown


def write_files(files: Dict[str, str], out_dir: Path, *, force: bool = False) -> None:
    """Write the five files. Without ``force`` an existing file is an error (the committed templates are there
    after an upgrade, so replacing them is a deliberate choice)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    if not force:
        existing = [n for n in files if (out_dir / n).exists()]
        if existing:
            raise FileExistsError(f"{', '.join(existing)} already exist in {out_dir}: pass --force to replace them")
    for name, content in files.items():
        (out_dir / name).write_text(content, encoding="utf-8")


__all__ = ["split_text", "write_files"]

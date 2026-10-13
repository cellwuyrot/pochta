#!/usr/bin/env python3
"""Consistent SQLite snapshot / checked restore. Stop service before restore."""

import argparse
import os
import sqlite3
from pathlib import Path


def backup(source: Path, destination: Path):
    if not source.is_file():
        raise FileNotFoundError(source)
    if destination.exists():
        raise FileExistsError(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(f"file:{source.resolve()}?mode=ro", uri=True) as src:
        with sqlite3.connect(destination) as dst:
            src.backup(dst)
            if dst.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise RuntimeError("Backup failed integrity check")
    os.chmod(destination, 0o600)


def restore(source: Path, destination: Path):
    # Refuse to overwrite a live/existing DB; operators explicitly move the old DB aside.
    backup(source, destination)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["backup", "restore"])
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    (backup if args.operation == "backup" else restore)(args.source, args.destination)

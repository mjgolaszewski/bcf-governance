"""Relocate native venv launchers before atomic publication and bind cache custody."""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import stat
from pathlib import Path

from .interpreter_environment_plan import InterpreterEnvironmentError


def _records(venv: Path) -> list[Path]:
    return sorted(venv.glob("lib/python*/site-packages/*.dist-info/RECORD"))


def _launcher_paths(venv: Path) -> list[Path]:
    return [venv / "pyvenv.cfg", *sorted((venv / "bin").iterdir())]


def launcher_custody(venv: Path) -> str:
    """Bind generated launcher bytes, executable modes, links and installer records."""
    rows: list[tuple[str, int, str, str]] = []
    for path in [*_launcher_paths(venv), *_records(venv)]:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            kind, digest = "link", os.readlink(path)
        elif stat.S_ISREG(info.st_mode):
            kind = "file"
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            raise InterpreterEnvironmentError("project interpreter launcher is not a regular file or link")
        rows.append((path.relative_to(venv).as_posix(), stat.S_IMODE(info.st_mode), kind, digest))
    return hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()


def _refresh_records(venv: Path, changed: set[Path]) -> None:
    for record in _records(venv):
        rows = list(csv.reader(io.StringIO(record.read_text(encoding="utf-8"))))
        updated = False
        for row in rows:
            if len(row) != 3:
                raise InterpreterEnvironmentError("project interpreter installer record is invalid")
            path = (record.parent.parent / row[0]).absolute()
            # RECORD paths can contain ../; resolve only to match changed owned files.
            if path.resolve() not in changed:
                continue
            data = path.read_bytes()
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
            row[1:] = ["sha256=" + digest.decode("ascii"), str(len(data))]
            updated = True
        if updated:
            output = io.StringIO(newline="")
            csv.writer(output, lineterminator="\n").writerows(rows)
            record.write_text(output.getvalue(), encoding="utf-8")


def relocate_environment_launchers(staged: Path, published: Path) -> str:
    """Repair only generated venv launch surfaces while the staged tree is private."""
    old, new = os.fsencode(staged), os.fsencode(published)
    changed: set[Path] = set()
    for path in _launcher_paths(staged):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            link = os.readlink(path)
            if link == str(staged) or link.startswith(str(staged) + os.sep):
                path.unlink()
                path.symlink_to(str(published) + link[len(str(staged)):])
            continue
        if not stat.S_ISREG(info.st_mode):
            raise InterpreterEnvironmentError("project interpreter launcher is not a regular file or link")
        data = path.read_bytes()
        if old not in data:
            continue
        if b"\0" in data:
            raise InterpreterEnvironmentError("project interpreter binary embeds its temporary prefix")
        path.write_bytes(data.replace(old, new))
        changed.add(path.resolve())
    _refresh_records(staged, changed)
    return launcher_custody(staged)

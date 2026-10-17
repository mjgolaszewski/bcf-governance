"""Contradictory transport cannot authenticate an owned command terminal."""
from __future__ import annotations

import os
import sys
from types import SimpleNamespace

import pytest

from bcf_governance.tooling import evidence_process_supervisor as supervisor
from bcf_governance.tooling.evidence_execution import EvidenceProcessCleanupError, _run


def test_equality_compatible_readiness_pid_cannot_allocate_command(tmp_path, monkeypatch):
    original = supervisor._receive
    observed = []

    def contradictory(connection, deadline):
        message = original(connection, deadline)
        assert message['type'] == 'ready'
        observed.append(message['supervisor_pid'])
        return {**message, 'supervisor_pid': float(message['supervisor_pid'])}

    monkeypatch.setattr(supervisor, '_receive', contradictory)
    marker = tmp_path / 'unexpected-effect'
    with pytest.raises(EvidenceProcessCleanupError, match='cleanup'):
        _run([sys.executable, '-c', 'from pathlib import Path;Path("unexpected-effect").touch()'],
             cwd=tmp_path, timeout_seconds=1, cleanup_timeout_seconds=1)
    assert observed, 'fixture never observed actual readiness'
    assert not marker.exists(), 'contradictory readiness allocated the command'


def test_partial_trailing_frame_cannot_become_terminal_cleanup(tmp_path, monkeypatch):
    original = os.read
    observed = []

    def contradictory(fd, size):
        chunk = original(fd, size)
        if b'"type":"complete"' in chunk:
            observed.append(chunk)
            return chunk + b'partial-extra-frame'
        return chunk

    # Keep the fault local to this owner, not subprocess or unrelated readers.
    monkeypatch.setattr(supervisor, 'os', SimpleNamespace(**{**vars(os), 'read': contradictory}))
    with pytest.raises(EvidenceProcessCleanupError, match='cleanup'):
        _run([sys.executable, '-c', "print('ordinary-command')"],
             cwd=tmp_path, timeout_seconds=1, cleanup_timeout_seconds=1)
    assert observed, 'fixture never observed actual terminal transport'


def test_invalid_control_utf8_is_not_an_ordinary_output_decode_failure(tmp_path, monkeypatch):
    original = os.read
    observed = []

    def contradictory(fd, size):
        chunk = original(fd, size)
        if b'"type":"complete"' in chunk:
            observed.append(chunk)
            return bytes([255, 10])
        return chunk

    monkeypatch.setattr(supervisor, 'os', SimpleNamespace(**{**vars(os), 'read': contradictory}))
    with pytest.raises(EvidenceProcessCleanupError, match='cleanup'):
        _run([sys.executable, '-c', "print('ordinary-command')"],
             cwd=tmp_path, timeout_seconds=1, cleanup_timeout_seconds=1)
    assert observed, 'fixture never observed actual terminal transport'

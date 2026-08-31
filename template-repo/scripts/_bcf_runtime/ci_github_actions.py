"""Immutable GitHub-owned action pins used by generated workflows."""

from __future__ import annotations

from types import MappingProxyType


ACTION_PINS = MappingProxyType(
    {
        "checkout": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "setup-python": "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
        "upload-artifact": "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "download-artifact": "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
    }
)


def action_pin(action_id: str) -> str:
    """Return one closed, immutable action source identity."""

    try:
        return ACTION_PINS[action_id]
    except KeyError as exc:
        raise ValueError(f"unknown GitHub action pin: {action_id}") from exc

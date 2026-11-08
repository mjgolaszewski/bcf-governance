"""Immutable GitHub-owned action pins used by generated workflows."""

from __future__ import annotations

from types import MappingProxyType

ACTION_PINS = MappingProxyType(
    {
        "checkout": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "setup-python": "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
        "setup-node": "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
        "upload-artifact": "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "download-artifact": "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        "attest-build-provenance": "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
        "create-github-app-token": "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
    }
)


# Maintained adopter-only actions are supported without claiming framework use.
ADOPTER_ACTION_PINS = MappingProxyType({
    "setup-uv": "astral-sh/setup-uv@37802adc94f370d6bfd71619e3f0bf239e1f3b78",
})


# Additional maintained immutable identities are opt-in per component.
# Existing consumers retain the default map above.
ACTION_COMPATIBILITY_PINS = MappingProxyType({
    "checkout": frozenset({
        "actions/checkout@93cb6efe18208431cddfb8368fd83d5badbf9bfd",
    }),
    "upload-artifact": frozenset({
        "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f",
    }),
})

def action_pin(action_id: str, source_pin: str | None = None) -> str:
    """Return one closed, immutable action source identity."""

    try:
        default = (
            ACTION_PINS[action_id] if action_id in ACTION_PINS
            else ADOPTER_ACTION_PINS[action_id]
        )
        if source_pin is None or source_pin == default:
            return default
        if source_pin in ACTION_COMPATIBILITY_PINS.get(action_id, frozenset()):
            return source_pin
        raise ValueError(f"unregistered immutable source for action {action_id}")
    except KeyError as exc:
        raise ValueError(f"unknown GitHub action pin: {action_id}") from exc

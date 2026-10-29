"""The public CLI mode flags retain their behavior with private parser field names."""
from __future__ import annotations

import pytest

from bcf_governance.tooling.ci_commands import _parser


@pytest.mark.parametrize("arguments", [
    ["adopt", "github"],
    ["adopt", "trusted-controller", "--config", "controller.yml"],
    ["automation", "adopt", "github", "--producer", "dependabot", "--repository", "owner/repo"],
    ["pin-authority", "--definition-commit", "abc123"],
    ["sync-self-controller", "--pin", "pin.yml"],
])
@pytest.mark.parametrize("mode", ["apply", "check"])
def test_public_mode_flags_select_exactly_one_private_field(arguments: list[str], mode: str) -> None:
    parser = _parser()
    parsed = parser.parse_args([*arguments, "--" + mode])
    assert parsed.apply_requested is (mode == "apply")
    assert parsed.check_requested is (mode == "check")
    with pytest.raises(SystemExit) as error:
        parser.parse_args([*arguments, "--apply", "--check"])
    assert error.value.code == 2

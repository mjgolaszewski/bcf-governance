"""Existing native release owner and genuine installed provider fixtures; UNRUN."""
from pathlib import Path

import pytest

from bcf_governance.tooling.architecture_release_context import KEY, encode_release_inputs, released_native_membership
from bcf_governance.tooling.architecture_source_components import SourceComponentError
from bcf_governance.tooling.bootstrap.environment import scoped_execution_environment
from bcf_governance.tooling.ci_commands import _parser
from test_architecture_release_membership import installed_release
from test_install_release_custody import _Provider


class _Credentials:
    def token(self):
        return "closed-fixture-no-network"


@pytest.mark.parametrize("previous", [None, "previous-owner-inputs"])
def test_released_owner_restores_scoped_inputs_on_native_exception(installed_release, previous):
    root, assets, template, digests = installed_release
    values = {} if previous is None else {KEY: previous}
    original = dict(values)
    class ExpectedExit(Exception):
        pass
    with pytest.raises(ExpectedExit):
        with released_native_membership(root, assets_root=assets, template_root=template,
                provider_settings=_Credentials(), api=_Provider(digests),
                scoped_environment=scoped_execution_environment(values)) as inputs:
            assert values[KEY] == encode_release_inputs(inputs)
            assert "closed-fixture-no-network" not in values[KEY]
            raise ExpectedExit("native command interrupted")
    assert values == original


def test_existing_native_cli_parses_explicit_custody_inputs_before_command():
    args = _parser().parse_args(["local-pr", "--release-assets", "/explicit/assets",
                                "--release-template", "/explicit/template", "--", "make", "validate"])
    assert args.release_assets == Path("/explicit/assets")
    assert args.release_template == Path("/explicit/template")
    assert args.command == ["--", "make", "validate"]


@pytest.mark.parametrize("missing", ["assets", "template"])
def test_incomplete_explicit_native_owner_context_refuses_before_command(installed_release, missing):
    root, assets, template, _ = installed_release
    with pytest.raises(SourceComponentError, match="both explicit assets and template") as failure:
        with released_native_membership(root, assets_root=None if missing == "assets" else assets,
                template_root=None if missing == "template" else template):
            raise AssertionError("native body must not run")
    assert any(entry.name == "released_native_membership" for entry in failure.traceback)

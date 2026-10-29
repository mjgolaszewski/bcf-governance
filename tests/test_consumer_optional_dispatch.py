"""Ordinary-consumer optional producer capability remains typed and fail-closed."""

from pathlib import Path
from types import ModuleType
from typing import NoReturn

import pytest
from test_validate_governance_yaml import _instantiate_fixture_repo

from bcf_governance.tooling.governance_validation import runner


class _MalformedDispatch(ModuleType):
    validate_self_authority_documents: None = None


_PRODUCER_DOCUMENTS = (
    "self-overlays.yml",
    "product-parity.yml",
    "product-certification.yml",
)


def test_ordinary_consumer_does_not_need_producer_modules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")

    def refuse_optional_import(*args: object, **kwargs: object) -> NoReturn:
        raise AssertionError("ordinary consumer attempted producer import")

    monkeypatch.setattr(runner, "import_module", refuse_optional_import)
    runner.validate_repo_root(repo_root)


@pytest.mark.parametrize("document", _PRODUCER_DOCUMENTS)
def test_producer_document_without_capability_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, document: str
) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    (repo_root / "governance" / document).write_text("{}", encoding="utf-8")

    def missing_capability(name: str, *, package: str | None = None) -> NoReturn:
        assert name == ".self_authority_dispatch"
        assert package == runner.__package__
        raise ModuleNotFoundError("producer capability absent in ordinary consumer")

    monkeypatch.setattr(runner, "import_module", missing_capability)
    with pytest.raises(runner.GovernanceValidationError, match="require the self-authority runtime"):
        runner.validate_repo_root(repo_root)


@pytest.mark.parametrize("document", _PRODUCER_DOCUMENTS)
def test_malformed_producer_dispatch_is_not_silently_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, document: str
) -> None:
    repo_root = _instantiate_fixture_repo(tmp_path, "valid_repo")
    (repo_root / "governance" / document).write_text("{}", encoding="utf-8")
    malformed = _MalformedDispatch("malformed_self_authority_dispatch")

    def malformed_capability(name: str, *, package: str | None = None) -> ModuleType:
        assert name == ".self_authority_dispatch"
        assert package == runner.__package__
        return malformed

    monkeypatch.setattr(runner, "import_module", malformed_capability)
    with pytest.raises(runner.GovernanceValidationError, match="validator is unavailable"):
        runner.validate_repo_root(repo_root)

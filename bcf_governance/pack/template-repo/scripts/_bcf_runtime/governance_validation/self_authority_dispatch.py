"""Producer-only governance document dispatch, excluded from ordinary adopters."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .common import (
    GovernanceValidationError,
    _load_yaml,
    _validate_document_path,
    _validate_schema,
)


def validate_self_authority_documents(
    repo_root: Path, schema_cache: dict[str, dict[str, Any]]
) -> None:
    """Preserve all producer-only schema, path, and semantic validations."""
    overlay_path = repo_root / "governance/self-overlays.yml"
    if overlay_path.is_file():
        from .self_authority_overlays import (
            SelfAuthorityOverlayError,
            validate_self_authority_overlays,
        )

        overlays = _load_yaml(overlay_path)
        _validate_schema(
            repo_root,
            schema_cache,
            overlays,
            schema_name="self-authority-overlays.schema.json",
            context=str(overlay_path),
        )
        _validate_document_path(repo_root, overlays, overlay_path, context=str(overlay_path))
        try:
            validate_self_authority_overlays(repo_root)
        except SelfAuthorityOverlayError as exc:
            raise GovernanceValidationError(str(exc)) from exc
    parity_path = repo_root / "governance/product-parity.yml"
    if parity_path.is_file():
        from .product_parity import ProductParityError, validate_product_parity

        parity = _load_yaml(parity_path)
        _validate_schema(
            repo_root,
            schema_cache,
            parity,
            schema_name="product-parity.schema.json",
            context=str(parity_path),
        )
        _validate_document_path(repo_root, parity, parity_path, context=str(parity_path))
        try:
            validate_product_parity(repo_root, parity)
        except ProductParityError as exc:
            raise GovernanceValidationError(str(exc)) from exc
    certification_path = repo_root / "governance/product-certification.yml"
    if certification_path.is_file():
        from .product_certification import (
            ProductCertificationError,
            validate_product_certification,
        )

        certification = _load_yaml(certification_path)
        _validate_schema(
            repo_root,
            schema_cache,
            certification,
            schema_name="product-certification.schema.json",
            context=str(certification_path),
        )
        _validate_document_path(
            repo_root, certification, certification_path, context=str(certification_path)
        )
        try:
            validate_product_certification(repo_root, certification)
        except ProductCertificationError as exc:
            raise GovernanceValidationError(str(exc)) from exc

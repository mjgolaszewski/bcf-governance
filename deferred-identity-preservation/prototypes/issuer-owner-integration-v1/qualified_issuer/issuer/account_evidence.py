"""Canonical account DTOs and exact signed-token session readback; UNRUN.

The profile's generic 401 alone does not expose bearer_error_reason. A separate
trusted admin workbench must show the SAME signed-token sid became revoked while
its owning principal remains active. No invented response fields or audit access.
"""
from __future__ import annotations

import json

from chrysalis_identity.schemas_account_readmodels import AccountProfileResponse
from chrysalis_identity.schemas_admin_readmodels import AdminPrincipalSessionResponse

from .contracts import Refused


def _canonical_json(model, value):
    # Strict JSON mode preserves legitimate ISO datetimes while refusing bool,
    # string and number coercions. Canonical DTO remains the shape owner.
    return model.model_validate_json(json.dumps(value, allow_nan=False), strict=True)


def active_profile(value, *, principal_id: str, session_id: str,
                   subject: str, audience: str) -> None:
    try:
        profile = _canonical_json(AccountProfileResponse, value)
        matches = [row for row in profile.sessions if row.id == session_id]
        if (profile.principal_id != principal_id or profile.subject != subject
                or profile.current_audience != audience or profile.status != 'active'
                or len(matches) != 1 or matches[0].application_audience != audience
                or matches[0].status != 'active' or matches[0].revoked_at is not None
                or matches[0].is_current is not True):
            raise Refused()
    except Exception:
        raise Refused() from None


def revoked_session_witness(value, *, principal_id: str, session_id: str,
                            audience: str) -> None:
    try:
        if (type(value) is not dict or type(value.get('principal')) is not dict
                or value['principal'].get('id') != principal_id
                or value['principal'].get('status') != 'active'
                or value['principal'].get('is_deleted') is not False
                or type(value.get('sessions')) is not list
                or not all(type(row) is dict for row in value['sessions'])):
            raise Refused()
        rows = [row for row in value['sessions'] if row.get('id') == session_id]
        if len(rows) != 1:
            # The real workbench keeps only 12 recent sessions. Absence is
            # unknown, never proof that this session has been revoked.
            raise Refused()
        session = _canonical_json(AdminPrincipalSessionResponse, rows[0])
        if (session.application_audience != audience or session.status != 'revoked'
                or session.revoked_at is None):
            raise Refused()
    except Exception:
        raise Refused() from None

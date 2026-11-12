"""Partial Source-authored real-Git shadow tests; no SDK behavior qualification."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml

from bcf_governance.tooling import architecture_membership_compilation as compiler
from bcf_governance.tooling.architecture_source_components import SourceComponentError

REPO = Path(__file__).resolve().parents[1]
MEMBER = "src/domain/orders/rules.py"
SELECTOR = MEMBER + "::Observation.read_principal"
DECODER = """
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from src.domain.orders.owner import PrincipalOwner
class Observation:
    def read_principal(self, user: object) -> PrincipalOwner | None:
        if not isinstance(user, AuthenticatedUser):
            return None
        token = user.access_token
        tenant, subject = getattr(token, "tenant_id", None), getattr(token, "principal_id", None)
        if not isinstance(tenant, str) or not isinstance(subject, str):
            return None
        try:
            return PrincipalOwner(tenant, subject)
        except ValueError:
            return None
"""

def _git(root: Path, *arguments: str) -> None:
    # Preserve effective signing/hooks/filter policy; qualify the fixture profile
    # and register each disposable Git store before any execution grant.
    completed = subprocess.run(
        ["/usr/bin/git", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "-C", str(root), *arguments],
        capture_output=True, timeout=20, check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")

def _commit(root: Path) -> None:
    _git(root, "add", "-A")
    _git(root, "commit", "--quiet", "-m", "SDK decoder shadow fixture")

@pytest.fixture
def decoder_subject(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    document = yaml.safe_load((REPO / "template-repo/architecture-boundaries.yml").read_text())
    architecture = document["architecture"]
    architecture["source_roots"] = ["src"]
    architecture["layers"]["composition"] = {
        "path_tokens": ["bootstrap"], "required": False,
        "forbidden_import_prefixes": [], "forbidden_layer_imports": [], "forbidden_import_names": [],
    }
    architecture["package_metadata_ownership"] = [{
        "path": "src/bootstrap/__init__.py", "layer": "composition", "context": "bootstrap", "exports": ["__doc__"],
    }]
    (root / "architecture-boundaries.yml").write_text(json.dumps(document, indent=2) + "\n")
    (root / "schemas").mkdir()
    shutil.copyfile(REPO / "schemas/architecture-boundaries.schema.json", root / "schemas/architecture-boundaries.schema.json")
    for name, content in {
        "src/bootstrap/__init__.py": '"""Bootstrap composition package."""\n',
        MEMBER: DECODER,
        "src/domain/orders/owner.py": "class PrincipalOwner:\n    def __init__(self, tenant_id: str, sub: str) -> None:\n        self.tenant_id = tenant_id\n        self.sub = sub\n",
        "src/loose.py": "VALUE = 7\n",
    }.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    _git(root, "init", "--quiet")
    _git(root, "config", "user.email", "decoder-fixture@example.test")
    _git(root, "config", "user.name", "Decoder Fixture")
    _commit(root)
    return root

def _declare(root: Path) -> None:
    document = json.loads((root / "architecture-boundaries.yml").read_text())
    document["architecture"]["source_component_ownership"] = {
        "version": "1.2", "components": [{
            "id": "decoder-shadow", "layer": "domain", "context": "orders",
            "rationale": "Shape observation only; no authenticated SDK or operation witness",
            "members": {MEMBER: hashlib.sha256((root / MEMBER).read_bytes()).hexdigest()},
            "managed_pack": None,
            "context_authority": {"kind": "independently_inferred_inventory", "version": "1.0", "selector": "orders"},
            "function_contracts": [{
                "selector": SELECTOR, "profile": "sdk_principal_decoder.v1",
                "sdk_type": "external:mcp.server.auth.middleware.bearer_auth::AuthenticatedUser",
                "constructor": "src/domain/orders/owner.py::PrincipalOwner",
            }],
        }],
    }
    (root / "architecture-boundaries.yml").write_text(json.dumps(document, indent=2) + "\n")
    _commit(root)

def test_legacy_absent_retains_raw_findings(decoder_subject: Path) -> None:
    result = compiler.build_effective_inventory(decoder_subject)
    assert result.function_roles == ()
    assert any(row.path == "src/loose.py" for row in result.native.observation.violations)

def test_shape_observation_requires_independent_provenance(decoder_subject: Path) -> None:
    _declare(decoder_subject)
    result = compiler.build_effective_inventory(decoder_subject)
    assert len(result.function_roles) == 1
    role = result.function_roles[0]
    assert role.selector == SELECTOR
    assert role.qualification == "PROVENANCE_AND_OPERATION_WITNESS_REQUIRED"
    assert role.authority is False and role.raw_findings_retained is True

def test_layer_context_and_raw_observation_preserved(decoder_subject: Path) -> None:
    before = compiler.build_effective_inventory(decoder_subject)
    _declare(decoder_subject)
    after = compiler.build_effective_inventory(decoder_subject)
    assert before.native.observation == after.native.observation
    assert after.projection is not None
    assert after.projection.raw_observation is after.native.observation
    assert tuple((m.path, m.inferred_layers, m.inferred_contexts) for m in before.native.members) == tuple(
        (m.path, m.inferred_layers, m.inferred_contexts) for m in after.native.members
    )

def test_forged_cross_subject_cached_role_fact_refused(decoder_subject: Path) -> None:
    _declare(decoder_subject)
    result = compiler.build_effective_inventory(decoder_subject)
    forged = replace(result, function_roles=(replace(result.function_roles[0], authority=True),))
    with pytest.raises(SourceComponentError, match="cached ownership differs") as failure:
        compiler.reauthenticate_effective_inventory(decoder_subject, forged)
    assert any(entry.name == "reauthenticate_effective_inventory" for entry in failure.traceback)
    (decoder_subject / "src/loose.py").write_text("VALUE = 8\n")
    _commit(decoder_subject)
    with pytest.raises(SourceComponentError, match="cached ownership differs"):
        compiler.reauthenticate_effective_inventory(decoder_subject, result)

@pytest.mark.parametrize("original,replacement", [
    ("PrincipalOwner(tenant, subject)", "PrincipalOwner(subject, tenant)"),
    ("PrincipalOwner(tenant, subject)", "PrincipalOwner(tenant, subject, authority='local')"),
    ("getattr(token, \"tenant_id\", None)", "getattr(token, \"tenant_id\", 'fallback')"),
    ("        try:\n", "        if tenant == 'business-rule':\n            return None\n        try:\n"),
])
def test_closed_shape_rejects_changed_flow_or_extra_authority(
    decoder_subject: Path, original: str, replacement: str,
) -> None:
    path = decoder_subject / MEMBER
    assert original in DECODER
    path.write_text(DECODER.replace(original, replacement))
    _commit(decoder_subject)
    _declare(decoder_subject)
    with pytest.raises(SourceComponentError, match="function roles:") as failure:
        compiler.build_effective_inventory(decoder_subject)
    assert any(entry.name == "_derive_function_role_observations" for entry in failure.traceback)

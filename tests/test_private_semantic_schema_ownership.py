"""Private semantic schema consumers use their executing package resources."""
from pathlib import Path
import shutil

import pytest
import yaml

from bcf_governance.tooling.semantic_ownership_inventory import discover_python_source
from semantic_private_runtime_fixture import private_package_probe

CASES = ("candidate-missing", "candidate-permissive", "runtime-missing", "runtime-invalid")
ROOT = Path(__file__).parents[1]


def _schema_mutation(name, case):
    def mutate(project, runtime):
        if case != "candidate-missing":
            candidate = project / "schemas"
            candidate.mkdir()
            if case == "candidate-permissive":
                (candidate / name).write_text("{}")
            else:
                shutil.copy2(ROOT / "schemas" / name, candidate / name)
        actual = runtime / "resources/schemas" / name
        assert actual.is_file(), "canonical generator omitted private schema"
        if case == "runtime-missing":
            actual.unlink()
        elif case == "runtime-invalid":
            actual.write_text("{invalid-json")
    return mutate


@pytest.mark.parametrize("case", CASES)
def test_private_initialization_schema_has_no_candidate_fallback(tmp_path, case):
    source = tmp_path / "source"
    source.mkdir()
    path = source / "root.py"
    path.write_text("initialize()\ndef root():\n    pass\n")
    inventory = discover_python_source(source, files=[path], call_contracts_version="1.0", initialization_contracts_version="1.0")
    body = (
        "from _bcf_runtime.semantic_operation_effects import source_operation_call_population, SemanticOperationEffectError\n"
        "inventory=json.loads(Path('inventory.json').read_text())\n"
        "def accepted(value):\n"
        "    try:\n"
        "        source_operation_call_population('root.py::root', value, include_initialization=True)\n"
        "        return True\n"
        "    except SemanticOperationEffectError:\n"
        "        return False\n"
        "valid=accepted(inventory)\n"
        "inventory['module_initializers'][0]['authority']=True\n"
        "print(json.dumps({'valid_accepted':valid,'invalid_rejected':not accepted(inventory)}))\n"
    )
    result = private_package_probe(tmp_path, body, inventory=inventory,
        mutate=_schema_mutation("semantic-initialization-contracts.schema.json", case))
    if case.startswith("runtime-"):
        assert result["valid_accepted"] is False, "missing/corrupt private schema fell back to project schema"
    else:
        assert result["valid_accepted"] is True, "valid private schema depended on project schema"
        assert result["invalid_rejected"] is True, "project schema admitted invalid initialization facts"


def _operations():
    return dict(schema_version="1.0", document=dict(kind="application_operation_registry",
        id="example-operations", version="1.0.0", status="active", path="governance/application-operations.yml"),
        populations=[dict(id="cli", adapter="python_mapping", source="runtime.py", symbol="COMMANDS", public_only=True)],
        operations=[dict(id="example.work.v1", population="cli", population_key="work", family="example",
            bounded_context="example", entrypoints=["runtime.py::work"], semantic_kind="query",
            authoritative_read=True, authoritative_mutation=False, authority_conferral=False,
            produces_projection=False, model_callable=False, allowed_mutation_ports=[],
            allowed_authority_ports=[], non_authoritative_output_effects=[])], migrations=[])


@pytest.mark.parametrize("case", CASES)
def test_private_protected_registry_schema_has_no_candidate_fallback(tmp_path, case):
    def mutate(project, runtime):
        _schema_mutation("application-operations.schema.json", case)(project, runtime)
        registry = project / "governance/application-operations.yml"
        registry.parent.mkdir()
        registry.write_text(yaml.safe_dump(_operations(), sort_keys=False))
    body = (
        "import hashlib\nimport yaml\n"
        "from _bcf_runtime.semantic_authority_contracts import load_application_operations, SemanticAuthorityError\n"
        "registry=Path('governance/application-operations.yml')\n"
        "def accepted():\n"
        "    try:\n"
        "        load_application_operations(Path('.'), expected_sha256=hashlib.sha256(registry.read_bytes()).hexdigest())\n"
        "        return True\n"
        "    except SemanticAuthorityError:\n"
        "        return False\n"
        "valid=accepted()\n"
        "payload=yaml.safe_load(registry.read_text())\n"
        "payload['schema_version']='99.0'\n"
        "registry.write_text(yaml.safe_dump(payload, sort_keys=False))\n"
        "print(json.dumps({'valid_accepted':valid,'invalid_rejected':not accepted()}))\n"
    )
    result = private_package_probe(tmp_path, body, mutate=mutate)
    if case.startswith("runtime-"):
        assert result["valid_accepted"] is False, "missing/corrupt private schema fell back to project schema"
    else:
        assert result["valid_accepted"] is True, "valid private schema depended on project schema"
        assert result["invalid_rejected"] is True, "project schema admitted unsupported protected registry"

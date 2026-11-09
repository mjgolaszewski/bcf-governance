import pytest
import yaml

from bcf_governance.tooling.ci_graph_yaml import GraphYAMLError, load_yaml_bytes
from bcf_governance.tooling.preflight import PreflightError, _yaml_syntax_loader
from bcf_governance.tooling.semantic_yaml import SemanticYAMLError, load_unique_mapping


@pytest.mark.parametrize("reader", ["graph", "semantic", "preflight", "compose"])
@pytest.mark.parametrize("raw", [
    b'payload: !!python/object/apply:builtins.str ["unsafe-construction"]\n',
    b'payload: first\npayload: second\n',
])
def test_each_maintained_yaml_boundary_refuses_unsafe_tags_and_duplicate_keys(tmp_path, reader, raw):
    path = tmp_path / "input.yml"
    path.write_bytes(raw)
    with pytest.raises((yaml.YAMLError, GraphYAMLError, SemanticYAMLError, PreflightError)):
        if reader == "graph":
            load_yaml_bytes(raw, source="security-control")
        elif reader == "semantic":
            load_unique_mapping(path)
        else:
            loader = _yaml_syntax_loader("compose.yml" if reader == "compose" else "ordinary.yml")(raw)
            try:
                loader.get_single_data()
            finally:
                loader.dispose()


def test_graph_loader_keeps_yaml12_on_key_and_safe_booleans():
    assert load_yaml_bytes(b'on: {enabled: true, disabled: false}\n', source="workflow") == {
        "on": {"enabled": True, "disabled": False},
    }

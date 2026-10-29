from pathlib import Path
import pytest
from test_namespace_value_contracts import ORIGINAL, inventory, op
from bcf_governance.tooling.semantic_operation_effects import SemanticOperationEffectError, validate_operation_effects
@pytest.mark.parametrize('source', [
 ORIGINAL.replace('classes=classes).facts()', 'classes=classes).facts'),
 ORIGINAL.replace('classes=classes).facts()', 'classes=classes)'),
 ORIGINAL.replace('    def facts(self)', '    def expose(self):\n        return self\n\n    def facts(self)', 1),
 ORIGINAL.replace('    def facts(self)', '    def expose(self):\n        return self.locals\n\n    def facts(self)', 1),
])
def test_immediate_receiver_or_field_escape_refuses(tmp_path: Path, source: str) -> None:
 assert source != ORIGINAL
 found=inventory(tmp_path, source)
 assert found['namespace_value_contracts']['closed'] is False
 with pytest.raises(SemanticOperationEffectError):
  validate_operation_effects(op(), 'consumer.py::entry', found)

"""Qualify repository-bound source reconstruction in the installed private runtime."""
from __future__ import annotations

import inspect
import json
import subprocess

from test_ci_github_main_identity import Provider, _resolve
from test_installed_evidence_storage import (
    _environment, _record, installed_consumer, isolated_python,
)


def _probe_code() -> str:
    header = """import importlib.util, json, sys
from pathlib import Path
assert importlib.util.find_spec('bcf_governance') is None
sys.path.insert(0, str(Path('scripts').resolve()))
from _bcf_runtime.ci_github_identity import GitHubControllerError, resolve_main, resolve_run_subject
import _bcf_runtime.ci_github_identity as owner
assert Path(owner.__file__).resolve().is_relative_to(Path.cwd())
"""
    return header + inspect.getsource(Provider) + '\n' + inspect.getsource(_resolve) + """
positive = rejected = 0
for kind in ('default', 'run'):
    for name in ('owner/repo', 'Owner/Repo'):
        identity = _resolve(Provider(name), kind)
        assert identity.repository_id == '42' and identity.default_branch == 'main'
        assert identity.checkout_sha == 'a' * 40 and identity.tree_sha == 'b' * 40
        positive += 1
    for cause in ('wrong-owner', 'wrong-name', 'blank', 'missing', 'null', 'number', 'object'):
        values = {'wrong-owner': 'other/repo', 'wrong-name': 'owner/other', 'blank': '',
                  'missing': None, 'null': None, 'number': 42, 'object': {'full_name': 'owner/repo'}}
        provider = Provider(values[cause])
        if cause == 'missing':
            del provider.metadata['full_name']
        try:
            _resolve(provider, kind)
        except GitHubControllerError as exc:
            assert 'repository' in str(exc)
            assert provider.reads == [('repository', 'owner/repo')]
            rejected += 1
        else:
            raise AssertionError('unbound repository accepted: ' + cause + '/' + kind)
assert positive == 4 and rejected == 14
print(json.dumps({'authority': False, 'positive': positive, 'rejected': rejected,
                  'source_package_absent': True}, sort_keys=True))
"""


def test_installed_subject_resolvers_require_matching_repository_before_other_reads(
    installed_consumer, isolated_python,
):
    result = subprocess.run(
        [str(isolated_python), '-I', '-c', _probe_code()], cwd=installed_consumer,
        env=_environment(), capture_output=True, text=True,
    )
    assert result.returncode == 0, _record(result)
    assert json.loads(result.stdout) == {
        'authority': False, 'positive': 4, 'rejected': 14, 'source_package_absent': True,
    }

"""Existing directory names omitted by repository artifact discovery.

Consumers create separate mutable sets so their prior snapshot behavior stays intact.
This inventory does not govern the architecture production-source population.
"""

_SKIPPED_DIRECTORY_NAMES = frozenset({
    '.artifacts',
    '.git',
    '.hg',
    '.mypy_cache',
    '.pytest_cache',
    '.ruff_cache',
    '.tox',
    '.venv',
    '__pycache__',
    'artifacts',
    'build',
    'dist',
    'node_modules',
    'venv',
})

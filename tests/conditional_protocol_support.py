"""Source fixtures shared by the source and installed context coverage controls."""
from tests.test_independent_call_coverage import capture, work

SOURCES = {
    'truth': 'def work(value):\n    if value:\n        return 1\n    return 0\n',
    'operator': 'def work(value):\n    return value + 1\n',
    'for_iteration': 'def work(value):\n    for element in value:\n        pass\n    return 1\n',
    'star_iteration': 'def work(value):\n    return [*value]\n',
    'unpack_iteration': 'def work(value):\n    first, second = value\n    return 1\n',
    'yield_iteration': 'def work(value):\n    yield from value\n',
    'dict_collection': 'def work(value):\n    return {value: 1}\n',
    'set_collection': 'def work(value):\n    return {value}\n',
    'subscript': 'def work(value):\n    return value[0]\n',
    'format': 'def work(value):\n    return f"{value}"\n',
    'exception': 'def work(value):\n    raise value\n',
    'pattern': 'def work(value):\n    match value:\n        case [element]:\n            return 1\n    return 0\n',
}


def facts_for(root, mode, version='1.0'):
    return capture(root, SOURCES[mode] + "COMMANDS={'work':work}\n", version)


def erased(root, mode, version='1.0'):
    facts = facts_for(root, mode, version)
    rows = work(facts)['calls']
    assert len(rows) == 1 and 'implicit_protocol' in rows[0]
    rows.clear()
    return facts

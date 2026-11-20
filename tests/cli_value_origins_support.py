"""Exercise actual CLI/parser/value boundaries through a declared test port."""
import argparse
from contextlib import ExitStack
import os
from pathlib import Path
from unittest.mock import patch


def exercise(owner, mode):
    native_path = type(Path('/probe/adopter-python'))
    entries = []
    events = []
    expected = '/probe/adopter-python'
    argv = ['qualify-release', '--repository', 'fixture/framework', '--release-assets', '/probe/assets',
        '--release-build-manifest', '/probe/build.json', '--output', '/probe/output',
        '--adopter-python', 'fixture/adopter=' + expected, '--format', 'json']

    def terminal(*args, **kwargs):
        entries.append(kwargs)
        if mode == 'constructor':
            assert type(kwargs['adopter_pythons']['fixture/adopter']) is CallbackPath
            assert os.fspath(kwargs['adopter_pythons']['fixture/adopter']) == expected
        else:
            assert type(kwargs['adopter_pythons']) is dict
            assert all(type(key) is str and type(value) is native_path
                for key, value in kwargs['adopter_pythons'].items())
        return {'status': 'characterized'}

    class CallbackPath(native_path):
        def __fspath__(self):
            events.append('returned-object-fspath')
            return super().__fspath__()

    class RequestedPath:
        @staticmethod
        def cwd():
            return Path.cwd()

        def __new__(cls, value):
            if value == expected:
                events.append('requested-constructor')
                return CallbackPath(value)
            return Path(value)

    class Word(str):
        def partition(self, separator):
            events.append('parser-converter-partition')
            return super().partition(separator)

    native_add_argument = argparse.ArgumentParser.add_argument

    def converted_argument(parser, *args, **kwargs):
        if '--adopter-python' in args:
            kwargs['type'] = Word
        return native_add_argument(parser, *args, **kwargs)

    with ExitStack() as stack:
        stack.enter_context(patch.object(owner, 'qualify_release', terminal))
        if mode == 'constructor':
            stack.enter_context(patch.object(owner, 'Path', RequestedPath))
        elif mode == 'parser':
            stack.enter_context(patch.object(owner.argparse.ArgumentParser, 'add_argument', converted_argument))
        if mode == 'invalid':
            for value in ['missing-separator', '=' + expected, 'fixture/adopter=']:
                invalid = list(argv)
                invalid[invalid.index('--adopter-python') + 1] = value
                try:
                    owner.main(invalid)
                except SystemExit as error:
                    assert '--adopter-python requires unique' in str(error)
                else:
                    raise AssertionError('invalid mapping reached qualification')
            duplicate = argv + ['--adopter-python', 'fixture/adopter=/probe/other']
            try:
                owner.main(duplicate)
            except SystemExit as error:
                assert '--adopter-python requires unique' in str(error)
            else:
                raise AssertionError('duplicate mapping reached qualification')
            assert entries == [] and events == []
        elif mode == 'ownership':
            owner.main(list(argv))
            first = entries[-1]['adopter_pythons']
            first['fixture/foreign'] = Path('/probe/foreign')
            owner.main(tuple(argv))
            second = entries[-1]['adopter_pythons']
            assert first is not second and 'fixture/foreign' not in second
            assert events == []
        elif mode == 'parser':
            try:
                owner.main(tuple(argv))
            except SystemExit as error:
                assert '--adopter-python requires ordinary parsed strings' in str(error)
            else:
                raise AssertionError('parser-converted subclass reached qualification')
            assert entries == [] and events == []
        else:
            owner.main(tuple(argv))
            assert len(entries) == 1
            value = entries[0]['adopter_pythons']['fixture/adopter']
            assert str(value) == expected
            assert events == (['requested-constructor', 'returned-object-fspath'] if mode == 'constructor' else [])
    return {'mode': mode, 'qualification_port_calls': len(entries), 'events': events,
        'authority': False, 'runtime_context_qualified': False}

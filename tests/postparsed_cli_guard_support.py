"""Actual parsed collection behavior through the existing qualification port."""
import argparse
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

VALUE = 'fixture/adopter=/probe/first'


def exercise(owner, mode):
    events = []
    calls = []
    defaults = [VALUE]
    argv = ['qualify-release', '--repository', 'fixture/framework', '--release-assets', '/probe/assets',
        '--release-build-manifest', '/probe/build.json', '--output', '/probe/output', '--format', 'json']

    class Word(str):
        def __new__(cls, value):
            if mode == 'converter_effect':
                events.append('converter-new')
            return super().__new__(cls, value)

        def partition(self, separator):
            events.append('partition')
            return super().partition(separator)

    class Words(list):
        def __iter__(self):
            events.append('sequence-iteration')
            return super().__iter__()

        def __getitem__(self, key):
            events.append('sequence-index')
            return super().__getitem__(key)

    class WordTuple(tuple):
        def __iter__(self):
            events.append('sequence-iteration')
            return super().__iter__()

        def __getitem__(self, key):
            events.append('sequence-index')
            return super().__getitem__(key)

    original = argparse.ArgumentParser.add_argument

    def register(parser, *args, **kwargs):
        if '--adopter-python' in args:
            if mode in {'converter_word', 'converter_effect'}:
                kwargs['type'] = Word
            elif mode == 'default_word':
                kwargs['default'] = [Word(VALUE)]
            elif mode == 'custom_list':
                kwargs['default'] = Words(defaults)
            elif mode == 'custom_tuple':
                kwargs['default'] = WordTuple(defaults)
            elif mode == 'native_tuple':
                kwargs['default'] = tuple(defaults)
            else:
                kwargs['default'] = defaults
        return original(parser, *args, **kwargs)

    def terminal(*args, **kwargs):
        calls.append(dict(kwargs['adopter_pythons']))
        return {'status': 'postparse-guard-observed'}

    class MutatingPath:
        @staticmethod
        def cwd():
            return Path.cwd()

        def __new__(cls, value):
            if value == '/probe/first':
                events.append('constructor-mutated-source-list')
                defaults.append('fixture/other=/probe/second')
            return Path(value)

    rejected = mode in {'default_word', 'converter_word', 'converter_effect', 'custom_list', 'custom_tuple'}
    if mode in {'converter_word', 'converter_effect'}:
        argv.extend(['--adopter-python', VALUE])
    with ExitStack() as stack:
        stack.enter_context(patch.object(owner.argparse.ArgumentParser, 'add_argument', register))
        stack.enter_context(patch.object(owner, 'qualify_release', terminal))
        if mode == 'mutated_list':
            stack.enter_context(patch.object(owner, 'Path', MutatingPath))
        if rejected:
            try:
                owner.main(argv)
            except SystemExit as error:
                assert '--adopter-python requires ordinary parsed strings' in str(error)
            else:
                raise AssertionError('postparser value reached qualification: ' + repr(events))
            assert calls == []
            assert events == (['converter-new'] if mode == 'converter_effect' else [])
        else:
            owner.main(argv)
            assert len(calls) == 1
            assert set(calls[0]) == {'fixture/adopter'}, 'postparsed snapshot expanded'
            assert str(calls[0]['fixture/adopter']) == '/probe/first'
            if mode == 'mutated_list':
                assert defaults == [VALUE, 'fixture/other=/probe/second']
                assert events == ['constructor-mutated-source-list']
            else:
                assert events == []
    return {'mode': mode, 'rejected': rejected, 'events': events, 'qualification_port_calls': len(calls),
        'authority': False, 'runtime_context_qualified': False}

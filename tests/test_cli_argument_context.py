"""Native string argv is an enforced ingress fact, not a caller annotation."""
import argparse
from pathlib import Path
import sys

import pytest
import yaml

from bcf_governance import cli
from bcf_governance.tooling import ci_controller_builder, nested_cli_runtime as owner

ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINTS = [("package",cli.main),*sorted(cli.COMMANDS.items()),("controller-builder",ci_controller_builder.main)]


class Sequence:
    def __init__(self, events):
        self.events = events

    def __iter__(self):
        self.events.append("iteration")
        return iter(["--help"])

    def __getitem__(self, item):
        self.events.append("index")
        return ["--help"] if isinstance(item,slice) else "--help"


class ListSubclass(list):
    def __init__(self, events):
        super().__init__(["--help"])
        self.events = events

    def __iter__(self):
        self.events.append("iteration")
        return list.__iter__(self)

    def __getitem__(self, item):
        self.events.append("index")
        return list.__getitem__(self,item)


class TupleSubclass(tuple):
    def __new__(cls, events):
        value = tuple.__new__(cls,("--help",))
        value.events = events
        return value

    def __iter__(self):
        self.events.append("iteration")
        return tuple.__iter__(self)

    def __getitem__(self, item):
        self.events.append("index")
        return tuple.__getitem__(self,item)


class Word(str):
    def __new__(cls, events):
        value = str.__new__(cls,"--help")
        value.events = events
        return value

    def __hash__(self):
        self.events.append("hash")
        return str.__hash__(self)

    def __eq__(self, other):
        self.events.append("equality")
        return str.__eq__(self,other)

    def __getitem__(self, item):
        self.events.append("index")
        return str.__getitem__(self,item)


def test_existing_catalog_exactly_covers_declared_public_dispatchers():
    declared = yaml.safe_load((ROOT/"governance/application-operations.yml").read_text())
    assert len(declared["operations"]) == 21
    assert {row["population_key"] for row in declared["operations"]} == set(cli.COMMANDS)


@pytest.mark.parametrize("name,entry", ENTRYPOINTS, ids=[row[0] for row in ENTRYPOINTS])
@pytest.mark.parametrize("kind", [Sequence,ListSubclass,TupleSubclass])
def test_registered_entrypoint_rejects_custom_sequence_without_callbacks(name, entry, kind):
    events = []
    value = kind(events)
    with pytest.raises(TypeError,match="CLI arguments"):
        entry(value)
    assert events == []


@pytest.mark.parametrize("name,entry", ENTRYPOINTS, ids=[row[0] for row in ENTRYPOINTS])
def test_registered_entrypoint_rejects_string_subclass_without_callbacks(name, entry):
    events = []
    value = Word(events)
    with pytest.raises(TypeError,match="CLI arguments"):
        entry([value])
    assert events == []


@pytest.mark.parametrize("name,entry", ENTRYPOINTS, ids=[row[0] for row in ENTRYPOINTS])
def test_process_argv_is_validated_before_custom_slicing(name, entry, monkeypatch):
    events = []
    value = Sequence(events)
    with monkeypatch.context() as patch:
        patch.setattr(sys,"argv",value)
        with pytest.raises(TypeError,match="CLI arguments"):
            entry(None)
    assert events == []


@pytest.mark.parametrize("name,entry", ENTRYPOINTS, ids=[row[0] for row in ENTRYPOINTS])
def test_bad_argument_rejects_before_parser_setup(name, entry, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("parser allocated before argv admission")

    monkeypatch.setattr(argparse,"ArgumentParser",forbidden)
    with pytest.raises(TypeError,match="CLI arguments"):
        entry([object()])


@pytest.mark.parametrize("name,entry", ENTRYPOINTS, ids=[row[0] for row in ENTRYPOINTS])
def test_native_help_preserves_every_declared_entrypoint(name, entry):
    with pytest.raises(SystemExit) as stopped:
        entry(("--help",))
    assert stopped.value.code == 0


@pytest.mark.parametrize("values", [[],["ci"],["ci","--help"],(),("ci",),("ci","--help")])
def test_ordinary_native_snapshots_are_owned_exact_string_lists(values):
    result = owner.cli_arguments(values)
    assert type(result) is list and result == list(values)
    assert result is not values
    assert all(type(value) is str for value in result)


def test_list_snapshot_cannot_be_changed_by_later_caller_mutation():
    values = ["ci","--help"]
    result = owner.cli_arguments(values)
    values[:] = ["changed"]
    assert result == ["ci","--help"]


def test_default_process_snapshot_drops_only_the_program_name(monkeypatch):
    monkeypatch.setattr(sys,"argv",["program","ci","--help"])
    assert owner.cli_arguments() == ["ci","--help"]
    assert sys.argv == ["program","ci","--help"]


def test_type_admission_does_not_call_custom_metaclass_equality():
    events = []

    class Meta(type):
        def __eq__(cls, other):
            events.append("class-equality")
            return False

        def __repr__(cls):
            events.append("class-repr")
            return "custom"

    class Value(Sequence,metaclass=Meta):
        pass

    value = Value(events)
    with pytest.raises(TypeError,match="CLI arguments"):
        owner.cli_arguments(value)
    assert events == []


@pytest.mark.parametrize("values", [[1],[None],[b"--help"],"--help",b"--help",{"--help":True}])
def test_other_non_string_or_non_sequence_inputs_are_typed_blocks(values):
    with pytest.raises(TypeError,match="CLI arguments"):
        owner.cli_arguments(values)


@pytest.mark.parametrize("kind", [Sequence,ListSubclass,TupleSubclass])
def test_ordinary_python_consumer_independently_witnesses_iteration_callbacks(kind):
    events = []
    value = kind(events)
    assert list(value) == ["--help"]
    assert events == ["iteration"]


def test_ordinary_dictionary_consumer_witnesses_string_subclass_hook():
    events = []
    value = Word(events)
    assert {"--help":True}[value] is True
    assert "hash" in events


@pytest.mark.parametrize("kind", [Sequence,ListSubclass,TupleSubclass])
def test_nested_command_builder_rejects_non_native_members(kind):
    events = []
    value = kind(events)
    with pytest.raises(TypeError,match="CLI arguments"):
        owner.exact_nested_cli_command(value)
    assert events == []


def controller_source(tmp_path):
    import shutil
    import subprocess

    repo = tmp_path/"installed-controller-source"
    runtime = repo/"scripts/_bcf_runtime"
    runtime.mkdir(parents=True)
    (repo/"schemas").mkdir()
    (runtime/"__init__.py").write_text("")
    (runtime/"_version.py").write_text("__version__='0.0.0'\n")
    shutil.copyfile(ROOT/"bcf_governance/tooling/nested_cli_runtime.py",runtime/"nested_cli_runtime.py")
    for name in ["ci_commands","ci_github_commands"]:
        (runtime/(name+".py")).write_text("SEEN=[]\ndef main(argv):\n    SEEN.append(argv)\n")
    for args in [("init","--quiet"),("config","user.name","CLI context fixture"),
            ("config","user.email","fixture@example.invalid"),("add","."),("commit","--quiet","-m","Synthetic installed source")]:
        subprocess.run(["git","-c","core.hooksPath=/dev/null",*args],cwd=repo,
            capture_output=True,text=True,check=True)
    return ci_controller_builder._materialize_installed_source(repo,tmp_path/"generated")


@pytest.mark.parametrize("mode", ["explicit","process","native"])
def test_actual_generated_controller_dispatcher_uses_same_argument_context(tmp_path, mode):
    import subprocess

    source = controller_source(tmp_path)
    program = '''import sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from bcf_governance import cli
from bcf_governance.tooling import ci_commands
mode=sys.argv[2]
events=[]
class Value:
 def __iter__(self):
  events.append("iteration")
  return iter(["ci","--help"])
 def __getitem__(self,key):
  events.append("index")
  return ["ci","--help"]
if mode=="native":
 cli.main(("ci","--help"))
 assert ci_commands.SEEN==[["--help"]]
 assert all(type(item) is str for item in ci_commands.SEEN[0])
else:
 value=Value()
 if mode=="process":sys.argv=value
 try:cli.main(None if mode=="process" else value)
 except TypeError:pass
 else:raise AssertionError("generated controller consumed custom CLI arguments")
 assert events==[],"generated controller invoked custom argument hooks"
 assert ci_commands.SEEN==[]
print("generated-controller-argument-context-qualified")
'''
    result = subprocess.run([sys.executable,"-I","-B","-c",program,str(source),mode],
        cwd=tmp_path,capture_output=True,text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == "generated-controller-argument-context-qualified"


def test_default_process_context_does_not_accept_a_custom_program_token(monkeypatch):
    events = []
    program = Word(events)
    monkeypatch.setattr(sys,"argv",[program,"--help"])
    with pytest.raises(TypeError,match="CLI arguments"):
        owner.cli_arguments()
    assert events == []

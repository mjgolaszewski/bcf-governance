from pathlib import Path
import sys
import venv
import pytest
from bcf_governance.tooling.release_adopter_qualification import (
    ReleaseQualificationError, _isolated_project_python,
)

@pytest.mark.parametrize("kind", ["unrelated", "prefix", "escape", "executable", "symlink", "whitespace"])
def test_owned_path_projection_keeps_unrelated_hooks_rejected(tmp_path: Path, kind: str) -> None:
    workspace=tmp_path/"docker"; workspace.mkdir()
    source=workspace/"source"; destination=workspace/"candidate"
    source.mkdir();destination.mkdir();environment=source/".venv"
    venv.EnvBuilder(with_pip=False).create(environment)
    site=environment/"lib"/f"python{sys.version_info.major}.{sys.version_info.minor}"/"site-packages"
    hook=site/"project.pth"
    paths={
        "unrelated":"/home/unrelated/project/src",
        "prefix":str(destination)+"-unrelated/src",
        "escape":str(destination)+"/../outside/src",
        "executable":"import sys; sys.path.insert(0, " + repr(str(destination/"src")) + ")",
        "symlink":str(source/"src"),
        "whitespace":" " + str(destination/"src"),
    }
    hook.write_text(paths[kind]+"\n",encoding="utf-8")
    if kind=="symlink":
        target=site/"target.txt";hook.rename(target);hook.symlink_to(target)
    with pytest.raises(ReleaseQualificationError,match="unsafe path hooks|unrelated workspace path hook"):
        _isolated_project_python(source,environment/"bin/python",destination,tmp_path/"projected")

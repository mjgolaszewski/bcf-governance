"""Render trusted-controller installation without executable data interpolation."""

from __future__ import annotations

import shlex
from typing import Any


def controller_install_step(
    component: dict[str, Any], *, selected_python: str, condition: str | None
) -> dict[str, Any]:
    """Render controller inputs as environment data consumed by Python APIs."""

    environment = {
        "BCF_PYTHON": selected_python,
        "BCF_CONTROLLER_ARTIFACT_DIR": component["artifact_dir"],
        "BCF_CONTROLLER_INSTALL_ROOT": component["install_root"],
    }
    if "wheel_sha256" in component:
        expected_digest = repr(component["wheel_sha256"])
        digest_loader = ""
    else:
        environment["BCF_CONTROLLER_AUTHORITY_FILE"] = component[
            "wheel_sha256_file"
        ]
        expected_digest = "expected"
        digest_loader = (
            "authority=pathlib.Path(os.environ['BCF_CONTROLLER_AUTHORITY_FILE'])\n"
            "assert authority.is_file() and not authority.is_symlink()\n"
            "payload=json.loads(authority.read_text())\n"
        )
        if "wheel_sha256_keys" in component:
            digest_loader += (
                f"keys={component['wheel_sha256_keys']!r}\n"
                "expected=payload\n"
                "for key in keys:\n"
                " assert isinstance(expected,dict) and key in expected\n"
                " expected=expected[key]\n"
                "assert isinstance(expected,str) and re.fullmatch(r'[a-f0-9]{64}',expected)\n"
            )
        else:
            digest_loader += (
                f"key_paths={component['wheel_sha256_key_paths']!r}\n"
                "resolved=[]\n"
                "for keys in key_paths:\n"
                " value=payload\n"
                " for key in keys:\n"
                "  if not isinstance(value,dict) or key not in value:\n"
                "   value=None;break\n"
                "  value=value[key]\n"
                " if isinstance(value,str) and re.fullmatch(r'[a-f0-9]{64}',value):\n"
                "  resolved.append(value)\n"
                "assert len(resolved)==1\n"
                "expected=resolved[0]\n"
            )
    script = (
        "import hashlib,json,os,pathlib,re,subprocess,sys,venv\n"
        "source=pathlib.Path(os.environ['BCF_CONTROLLER_ARTIFACT_DIR'])\n"
        "target=pathlib.Path(os.environ['BCF_CONTROLLER_INSTALL_ROOT'])\n"
        + digest_loader
        + "inventory=source/'SHA256SUMS'\n"
        "assert inventory.is_file() and not inventory.is_symlink()\n"
        "declared={}\n"
        "for line in inventory.read_text().splitlines():\n"
        " digest,separator,name=line.partition('  ')\n"
        " assert separator and len(digest)==64 and name and name not in declared\n"
        " declared[name]=digest\n"
        "actual={path.name:path for path in source.iterdir() if path.name!='SHA256SUMS'}\n"
        "assert set(actual)==set(declared)\n"
        "assert all(path.is_file() and not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest()==declared[name] for name,path in actual.items())\n"
        "wheels=sorted(source.glob('bcf_governance-*.whl'))\n"
        "assert len(wheels)==1 and not wheels[0].is_symlink()\n"
        f"assert hashlib.sha256(wheels[0].read_bytes()).hexdigest()=={expected_digest}\n"
        "venv.EnvBuilder(with_pip=True,clear=True).create(target)\n"
        "subprocess.run([str(target/'bin/python'),'-m','pip','install','--no-index','--find-links',str(source),str(wheels[0])],check=True)\n"
        "subprocess.run([str(target/'bin/bcf'),'ci-github','--help'],check=True)\n"
    )
    step: dict[str, Any] = {
        "name": component["name"],
        "shell": "bash",
        "env": environment,
        "run": "set -euo pipefail\n\"$BCF_PYTHON\" -I -c " + shlex.quote(script),
    }
    if condition is not None:
        step["if"] = condition
    return step

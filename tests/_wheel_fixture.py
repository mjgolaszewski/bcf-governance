from __future__ import annotations

from pathlib import Path
import zipfile


def write_wheel(
    path: Path, *, name: str, version: str, requirements: tuple[str, ...] = ()
) -> None:
    distribution = name.replace("-", "_")
    metadata_root = f"{distribution}-{version}.dist-info"
    metadata = ["Metadata-Version: 2.3", f"Name: {name}", f"Version: {version}"]
    metadata.extend(f"Requires-Dist: {requirement}" for requirement in requirements)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"{distribution}/__init__.py", "")
        archive.writestr(f"{metadata_root}/METADATA", "\n".join(metadata) + "\n")
        archive.writestr(
            f"{metadata_root}/WHEEL",
            "Wheel-Version: 1.0\nGenerator: bcf-test\nRoot-Is-Purelib: true\n"
            "Tag: py3-none-any\n",
        )

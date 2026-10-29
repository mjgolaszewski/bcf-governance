"""Short private transport paths; repository inputs remain in owner staging."""
from pathlib import Path
from tempfile import TemporaryDirectory
from collections.abc import Iterator

import pytest


@pytest.fixture
def socket_root() -> Iterator[Path]:
    # Linux sockaddr_un is bounded to108 bytes. Only ephemeral transport inodes
    # use /tmp; no project source, credentials, fence or evidence moves here.
    with TemporaryDirectory(prefix="bcf239-owner-", dir="/tmp") as directory:
        yield Path(directory)

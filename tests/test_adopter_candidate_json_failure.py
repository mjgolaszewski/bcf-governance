"""Reuse the exact original subject fixture but corrupt only candidate JSON output."""
from pathlib import Path
import pytest
from tests import test_release_adopter_qualification as original


def test_exact_candidate_invocation_still_rejects_invalid_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class CorruptCandidateOutput:
        def setenv(self, *args, **kwargs):
            return monkeypatch.setenv(*args, **kwargs)

        def setattr(self, target, name, value):
            if target is original.qualification and name == "_run":
                actual_fixture = value
                def run(argv, **kwargs):
                    result = actual_fixture(argv, **kwargs)
                    if (len(argv) == 11 and argv[1:3] == ["-P", "-c"]
                            and argv[3] == original.qualification._CANDIDATE_QUALIFICATION_TRAIN):
                        return "not-json"
                    return result
                value = run
            return monkeypatch.setattr(target, name, value)

    with pytest.raises(original.ReleaseQualificationError, match="adopter qualification emitted invalid JSON"):
        original.test_release_subject_identity_cannot_be_replaced_by_adopter_iteration(tmp_path, CorruptCandidateOutput())

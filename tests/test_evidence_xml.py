from pathlib import Path
from xml.etree.ElementTree import ParseError

import pytest

from bcf_governance.tooling.evidence_xml import parse_evidence_xml, read_evidence_xml


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
@pytest.mark.parametrize("declaration", [
    '<!DOCTYPE testsuite [<!ENTITY expanded "untrusted">]>',
    '<!DOCTYPE testsuite SYSTEM "file:///nonexistent-bcf-xml-input">',
])
def test_evidence_xml_refuses_dtd_and_entities_in_real_encodings(encoding, declaration):
    raw = ('<?xml version="1.0" encoding="' + encoding + '"?>' + declaration
           + '<testsuite><testcase name="probe"/></testsuite>').encode(encoding)
    with pytest.raises(ParseError, match="forbidden XML declaration"):
        parse_evidence_xml(raw)


def test_evidence_xml_preserves_real_junit_structure_and_rejects_file_alias(tmp_path: Path):
    raw = b'<testsuites><testsuite tests="1"><testcase name="a" time="0.25"/></testsuite></testsuites>'
    path = tmp_path / "junit.xml"
    path.write_bytes(raw)
    assert read_evidence_xml(path).find(".//testcase").attrib == {"name": "a", "time": "0.25"}
    alias = tmp_path / "alias.xml"
    alias.symlink_to(path)
    with pytest.raises(OSError):
        read_evidence_xml(alias)


def test_evidence_xml_refuses_oversized_input_before_parsing():
    with pytest.raises(ParseError, match="bounded XML"):
        parse_evidence_xml(b"x" * (16 * 1024**2 + 1))

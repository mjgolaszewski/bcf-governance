"""Real native socket/HTTPResponse framing; no guessed Python-version waiver."""
from http.client import HTTPResponse
import socket

import pytest
from bcf_governance.tooling import ci_github_response as owner


class Case:
    def __init__(self, raw):
        self.raw = raw

    def consume(self, size=None):
        left, right = socket.socketpair()
        response = None
        try:
            right.sendall(self.raw)
            right.shutdown(socket.SHUT_WR)
            response = HTTPResponse(left)
            response.begin()
            with owner.provider_response_deadline(response, timeout=1) as bounded:
                if size is None:
                    return bounded.read()
                chunks = []
                while chunk := bounded.read(size):
                    chunks.append(chunk)
                return b"".join(chunks)
        finally:
            if response is not None:
                response.close()
            left.close()
            right.close()


@pytest.mark.parametrize("token", [b"+5", b"-5", b"0x5", b"5_0", b" 5", b"5 ", b"\xb2"])
def test_malformed_chunk_integer_cannot_be_consumed(token):
    raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + token + b"\r\nhello\r\n0\r\n\r\n"
    with pytest.raises(owner.ProviderResponseError, match="numeric framing"):
        Case(raw).consume()


@pytest.mark.parametrize("value", [b"+5", b"-5", b"0x5", b"5_0", b"5 0", b"", b"\xb2"])
def test_malformed_content_length_rejects_before_body_read(value):
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: " + value + b"\r\n\r\nhello"
    with pytest.raises(owner.ProviderResponseError, match="numeric framing"):
        Case(raw).consume()


@pytest.mark.parametrize("headers", [b"Content-Length: 5\r\nContent-Length: 5\r\n",
    b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n", b"Transfer-Encoding: gzip, chunked\r\n",
    b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n"])
def test_duplicate_or_unsupported_transfer_framing_cannot_be_consumed(headers):
    raw = b"HTTP/1.1 200 OK\r\n" + headers + b"\r\n5\r\nhello\r\n0\r\n\r\n"
    with pytest.raises(owner.ProviderResponseError, match="framing"):
        Case(raw).consume()


@pytest.mark.parametrize("size", [None, 1, 3])
@pytest.mark.parametrize("raw", [b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    b"HTTP/1.1 200 OK\r\nContent-Length: 5 \t\r\n\r\nhello",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n2;x=y\r\nhe\r\n3\r\nllo\r\n000\r\nTrailer: retained-semantics\r\n\r\n",
    b"HTTP/1.1 200 OK\r\n\r\nhello"])
def test_valid_body_ows_extensions_trailers_and_partial_reads_preserve_behavior(raw, size):
    assert Case(raw).consume(size) == b"hello"


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_invalid_body_framing_is_not_retried_even_after_possible_mutation(method):
    from bcf_governance.tooling.ci_github_transport import GitHubTransportError, request_json
    left, right = socket.socketpair()
    response = None
    calls = []
    try:
        right.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n+2\r\n{}\r\n0\r\n\r\n")
        right.shutdown(socket.SHUT_WR)
        response = HTTPResponse(left)
        response.begin()
        def opened(request, *, timeout):
            calls.append(request.get_method())
            return response
        with pytest.raises(GitHubTransportError):
            request_json(method=method, api_url="https://api.github.com", path="/fixture", token="fixture",
                         payload=None, not_found_none=False, opener=opened, observations=[])
        assert calls == [method]
    finally:
        if response is not None:
            response.close()
        left.close()
        right.close()

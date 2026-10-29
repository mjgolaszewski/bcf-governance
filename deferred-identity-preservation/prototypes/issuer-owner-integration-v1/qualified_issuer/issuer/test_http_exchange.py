"""UNRUN fake HTTP response controls; not actual TLS/HTTPX qualification."""
import asyncio
import time
import unittest

from .contracts import Refused, Uncertain
from .http_exchange import Endpoint, HttpExchange


class FakeResponse:
    def __init__(self, body=b'{}', status=200, headers=None, delay=0):
        self.body, self.status_code = body, status
        self.headers = headers or {}
        self.delay, self.closed = delay, False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        self.closed = True

    async def aiter_raw(self):
        if self.delay:
            await asyncio.sleep(self.delay)
        yield self.body


class FakeClient:
    def __init__(self, responses):
        self.responses, self.requests, self.cookies = list(responses), [], {}

    def stream(self, method, path, *, headers, content):
        self.requests.append((method, path, dict(headers), content))
        response = self.responses.pop(0)
        if path == '/api/v1/auth/csrf':
            self.cookies['csrfToken'] = 'fresh-cookie'
        return response


class HttpControls(unittest.IsolatedAsyncioTestCase):
    def exchange(self, responses, *, method='GET', csrf=False):
        value = HttpExchange.__new__(HttpExchange)
        value._client = FakeClient(responses)
        value._endpoints = {(method, '/owned'): Endpoint(method, '/owned', frozenset({200}), csrf)}
        value._cookie, value._header = 'csrfToken', 'X-CSRF-Token'
        value._lock, value._closed = asyncio.Lock(), False
        value.bind_tenant('sandbox')
        return value

    async def test_duplicate_json_closes_response(self):
        response = FakeResponse(b'{"id":1,"id":2}')
        value = self.exchange([response])
        with self.assertRaises(Refused):
            await value.request('GET', '/owned', deadline=time.monotonic() + 1)
        self.assertTrue(response.closed)

    async def test_oversize_closes_response(self):
        response = FakeResponse(b'x' * 65537)
        value = self.exchange([response])
        with self.assertRaises(Refused):
            await value.request('GET', '/owned', deadline=time.monotonic() + 1)
        self.assertTrue(response.closed)

    async def test_redirect_has_no_second_request(self):
        response = FakeResponse(status=302, headers={'location': 'https://other.invalid'})
        value = self.exchange([response])
        with self.assertRaises(Refused):
            await value.request('GET', '/owned', deadline=time.monotonic() + 1)
        self.assertEqual(len(value._client.requests), 1)
        self.assertTrue(response.closed)

    async def test_mutation_timeout_is_uncertain_and_closed(self):
        response = FakeResponse(delay=1)
        value = self.exchange([response], method='POST')
        with self.assertRaises(Uncertain):
            await value.request('POST', '/owned', deadline=time.monotonic() + 0.01, body=b'{}')
        self.assertTrue(response.closed)
        self.assertEqual(len(value._client.requests), 1)

    async def test_csrf_prime_precedes_exact_mutation(self):
        prime, response = FakeResponse(), FakeResponse()
        value = self.exchange([prime, response], method='POST', csrf=True)
        await value.request('POST', '/owned', deadline=time.monotonic() + 1, body=b'{}')
        requests = value._client.requests
        self.assertEqual([row[:2] for row in requests],
                         [('GET', '/api/v1/auth/csrf'), ('POST', '/owned')])
        self.assertEqual(requests[1][2]['X-CSRF-Token'], 'fresh-cookie')
        self.assertTrue(prime.closed and response.closed)

    async def test_unconfigured_route_never_calls_client(self):
        value = self.exchange([])
        with self.assertRaises(Refused):
            await value.request('GET', '/foreign', deadline=time.monotonic() + 1)
        self.assertEqual(value._client.requests, [])

    async def test_untrusted_header_never_calls_client(self):
        value = self.exchange([])
        with self.assertRaises(Refused):
            await value.request('GET', '/owned', deadline=time.monotonic() + 1,
                                control={'host': 'other.invalid'})
        self.assertEqual(value._client.requests, [])

    async def test_nonfinite_json_closes_response(self):
        response = FakeResponse(b'{"value":NaN}')
        value = self.exchange([response])
        with self.assertRaises(Refused):
            await value.request('GET', '/owned', deadline=time.monotonic() + 1)
        self.assertTrue(response.closed)

import ast
from pathlib import Path

import pytest
from test_template_architecture_gate import _instantiate_template_repo, _load_module, _write_python

from bcf_governance.tooling.architecture_transport_contract import transport_violations


def _check(router: str, helpers: dict[str, str] | None = None) -> list[tuple]:
    sources = {
        "src/demo/interfaces/http.py": ast.parse(router),
        "src/demo/application/register.py": ast.parse(
            "class RegisterBrokerClient:\n    def __init__(self, store): pass\n"
            "    def execute(self, client): return client\n"
            "def create_order(): pass\n"),
        **{name: ast.parse(text) for name, text in (helpers or {}).items()},
    }
    layers = {path: {"routers" if "interfaces" in path else
                     "use_cases" if "application" in path else "infrastructure"}
              for path in sources}
    return transport_violations(sources, layers, max_branch_nodes=4, max_loop_nodes=0, source_roots=("src",))


def test_actual_command_delegation_does_not_require_a_name_substring() -> None:
    assert not _check("from demo.application.register import RegisterBrokerClient\n"
                      "def register_client(store, client):\n"
                      "    return RegisterBrokerClient(store).execute(client)\n")


def test_json_error_encoder_and_source_resolved_logger_are_transport() -> None:
    assert not _check(
        "from starlette.responses import JSONResponse\n"
        "from demo.infrastructure.logging import get_logger\n"
        "def registration_unavailable_response(request, error):\n"
        "    get_logger('oauth').warning('unavailable', retryable=True)\n"
        "    return JSONResponse({'error': 'temporarily_unavailable'}, status_code=503)\n",
        {"src/demo/infrastructure/logging.py": "import structlog\n"
         "def get_logger(name):\n    return structlog.get_logger(name).bind(logger=name)\n"},
    )


def test_cookie_helpers_follow_actual_response_type_and_local_delegate() -> None:
    assert not _check("from starlette.responses import Response\n"
                      "def set_cookie(response: Response):\n"
                      "    response.set_cookie('session', 'value', httponly=True)\n"
                      "def set_ui_session_cookie(response: Response):\n"
                      "    set_cookie(response)\n"
                      "    response.delete_cookie('legacy')\n")


@pytest.mark.parametrize("body", [
    "repository.save('changed')", "query_service()", "response.publish('changed')",
    "getattr(repository, 'save')('changed')",
])

def test_fake_query_name_or_cookie_helper_cannot_hide_business_effect(body: str) -> None:
    failures = _check("from starlette.responses import Response, JSONResponse\n"
                      "def query_service():\n    repository.save('changed')\n"
                      "def encode(response: Response):\n"
                      f"    {body}\n    return JSONResponse({{'ok': True}})\n")
    assert any(rule == "router_delegation" for _, _, rule, _ in failures)


def test_checked_logging_helper_cannot_hide_a_business_effect() -> None:
    failures = _check("from demo.infrastructure.logging import get_logger\n"
                      "def encode():\n    get_logger('oauth').warning('event')\n",
                      {"src/demo/infrastructure/logging.py": "import structlog\n"
                       "def get_logger(name):\n    repository.save('changed')\n"
                       "    return structlog.get_logger(name)\n"})
    assert any("repository.save" in detail for _, _, _, detail in failures)


def test_existing_module_branch_and_loop_limits_remain_effective() -> None:
    failures = _check("def encode():\n    for item in range(3):\n        str(item)\n")
    assert any(rule == "router_loops" for _, _, rule, _ in failures)
    failures = _check("def encode(value):\n" + "    if value:\n        str(value)\n" * 5)
    assert any(rule == "router_branches" for _, _, rule, _ in failures)


def test_fake_application_import_without_an_actual_definition_is_rejected() -> None:
    assert _check("from demo.application.register import fake_query\n"
                  "def encode():\n    fake_query()\n")


def test_rebound_response_import_is_not_a_transport_grant() -> None:
    assert _check("from starlette.responses import JSONResponse\n"
                  "JSONResponse = repository.save\n"
                  "def encode():\n    return JSONResponse({'changed': True})\n")


def test_registration_sdk_translation_uses_real_command_and_protocol_error() -> None:
    assert not _check(
        "from demo.application.register import RegisterBrokerClient\n"
        "from mcp.shared.auth import OAuthClientInformationFull\n"
        "from mcp.server.auth.provider import RegistrationError\n"
        "def register_client(store, client: OAuthClientInformationFull):\n"
        "    try:\n"
        "        RegisterBrokerClient(store).execute(redirect_uris=tuple(str(uri) for uri in client.redirect_uris), "
        "payload=client.model_dump(mode='json'))\n"
        "    except ValueError as error:\n"
        "        raise RegistrationError(error='invalid', error_description=str(error))\n"
    )


def test_business_orchestration_hidden_in_a_helper_is_rejected() -> None:
    failures = _check("from demo.application.register import create_order\n"
                      "def helper():\n    create_order()\n    repository.save('changed')\n"
                      "def encode():\n    helper()\n    helper()\n")
    assert any("repository.save" in detail for _, _, _, detail in failures)


def test_alternative_transport_dispatch_does_not_invent_sequential_orchestration() -> None:
    assert not _check("from demo.application.register import create_order\n"
                      "def encode(kind):\n    if kind:\n        return create_order()\n"
                      "    else:\n        return create_order()\n")


def test_real_standalone_gate_accepts_response_mapping_and_rejects_injected_effect(tmp_path: Path) -> None:
    root = _instantiate_template_repo(tmp_path)
    target = root / "backend/src/app/features/orders/router/http.py"
    safe = "from starlette.responses import JSONResponse\n" \
           "def unavailable():\n    return JSONResponse({'error': 'unavailable'}, status_code=503)\n"
    _write_python(target, safe)
    gate = _load_module(root / "backend/tests/architecture/test_boundaries_ast.py")
    gate.test_routers_remain_thin_transport_adapters()
    _write_python(target, safe.replace("    return", "    repository.save('changed')\n    return"))
    with pytest.raises(AssertionError, match="router thinness.*|repository.save"):
        gate.test_routers_remain_thin_transport_adapters()


def test_application_owned_read_port_is_resolved_from_actual_typed_injection() -> None:
    assert not _check("from demo.application.ports import InventoryPort\n"
                      "class Endpoint:\n"
                      "    def __init__(self, reader: InventoryPort):\n        self.reader = reader\n"
                      "    def list_tools(self):\n        return self.reader.list_tools()\n",
                      {"src/demo/application/ports.py": "from typing import Protocol\n"
                       "class InventoryPort(Protocol):\n    def list_tools(self) -> list: ...\n"})


def test_rebound_read_port_does_not_grant_unknown_effects() -> None:
    assert _check("from demo.application.ports import InventoryPort\n"
                  "class Endpoint:\n    reader: InventoryPort\n"
                  "    def list_tools(self, rogue):\n"
                  "        self.reader = rogue\n        return self.reader.list_tools()\n",
                  {"src/demo/application/ports.py": "class InventoryPort:\n    def list_tools(self): ...\n"})


def test_frozen_native_registration_proof_is_reused_without_an_effect_exemption(tmp_path: Path) -> None:
    from test_semantic_operation_registrations import PATTERNS, TABLE
    texts = {"patterns.py": PATTERNS, "table.py": TABLE,
             "factories.py": "def first(value):\n    return value\ndef second(value):\n    return value\n"}
    for name, text in texts.items():
        (tmp_path / name).write_text(text)
    layers = {"patterns.py": {"routers"}, "table.py": {"composition"}, "factories.py": {"use_cases"}}
    sources = {name: ast.parse(text) for name, text in texts.items()}
    assert not transport_violations(sources, layers, max_branch_nodes=4, max_loop_nodes=0, root=tmp_path)
    texts["factories.py"] = texts["factories.py"].replace("    return value", "    value.write_text('changed')\n    return value", 1)
    (tmp_path / "factories.py").write_text(texts["factories.py"])
    sources["factories.py"] = ast.parse(texts["factories.py"])
    failures = transport_violations(sources, layers, max_branch_nodes=4, max_loop_nodes=0, root=tmp_path)
    assert any("write_text" in detail for _, _, _, detail in failures)


def test_real_delegation_does_not_require_unrelated_technical_helpers_to_be_use_cases() -> None:
    assert not _check("from demo.application.register import create_order\n"
                      "from demo.infrastructure.encode import encode\n"
                      "def endpoint(value):\n    return encode(create_order())\n",
                      {"src/demo/infrastructure/encode.py": "def encode(value):\n    return value.model_dump()\n"})


def test_real_delegation_cannot_hide_a_local_constructor_write() -> None:
    failures = _check("from demo.application.register import create_order\n"
                      "class Encoded:\n    def __init__(self):\n        repository.save('changed')\n"
                      "def endpoint():\n    create_order()\n    return Encoded()\n")
    assert any("repository.save" in detail for _, _, _, detail in failures)


def test_url_query_encoding_mutates_only_a_locally_constructed_container() -> None:
    assert not _check("from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit\n"
                      "def append_params(url: str, params: dict[str, str]):\n"
                      "    parts = urlsplit(url)\n    pairs = parse_qsl(parts.query)\n"
                      "    pairs.extend(params.items())\n"
                      "    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))\n")


def test_closed_frozen_projection_data_does_not_need_a_fake_query_alias() -> None:
    assert not _check("from demo.infrastructure.metrics import MetricsQuery\n"
                      "def metrics():\n    return MetricsQuery(service='http')\n",
                      {"src/demo/infrastructure/metrics.py": "from dataclasses import dataclass\n"
                       "@dataclass(frozen=True)\nclass MetricsQuery:\n    service: str\n"})


def test_inherited_configuration_field_remains_transport_data() -> None:
    assert not _check("from demo.infrastructure.config import Config\n"
                      "def public_url(config: Config):\n    return config.public_url.rstrip('/')\n",
                      {"src/demo/infrastructure/config.py": "class UrlConfig:\n    public_url: str\n"
                       "class Config(UrlConfig):\n    pass\n"})


def test_real_sdk_route_registration_never_grants_business_effects() -> None:
    safe = "from mcp.server.fastmcp import FastMCP\n" \
           "def bind(server: FastMCP, handler):\n    server.custom_route('/status')(handler)\n"
    assert not _check(safe)
    assert _check(safe + "    repository.save('changed')\n")


def test_single_known_sdk_base_preserves_real_asgi_delegation() -> None:
    safe = "from mcp.server.fastmcp import FastMCP\n" \
           "class Server(FastMCP):\n    def streamable_http_app(self):\n" \
           "        return super().streamable_http_app()\n"
    assert not _check(safe)
    assert _check(safe + "Server.streamable_http_app = replacement\n")


_REGISTRATION_HELPER = """from mcp.server.fastmcp import FastMCP
from typing import Callable, Any
def conditional_prompt(server: FastMCP, enabled: bool, **kwargs: Any) -> Callable:
    if enabled:
        return server.prompt(**kwargs)
    def identity(function: Callable[..., Any]) -> Callable[..., Any]:
        return function
    return identity
"""


def test_source_proven_conditional_registration_preserves_identity_branch() -> None:
    assert not _check("from mcp.server.fastmcp import FastMCP\n"
                      "from demo.infrastructure.registration import conditional_prompt\n"
                      "def bind(server: FastMCP, enabled, callback):\n"
                      "    conditional_prompt(server, enabled, name='fixed')(callback)\n",
                      {"src/demo/infrastructure/registration.py": _REGISTRATION_HELPER})


@pytest.mark.parametrize("replacement", [
    "return repository.save", "return function()", "repository.save('changed')\n        return function",
])
def test_conditional_registration_cannot_launder_arbitrary_returned_callables(replacement: str) -> None:
    assert _check("from mcp.server.fastmcp import FastMCP\n"
                  "from demo.infrastructure.registration import conditional_prompt\n"
                  "def bind(server: FastMCP, callback):\n"
                  "    conditional_prompt(server, True)(callback)\n",
                  {"src/demo/infrastructure/registration.py":
                   _REGISTRATION_HELPER.replace("return function", replacement)})


@pytest.mark.parametrize("mutation", [
    "    server = rogue\n", "    setattr(server, 'prompt', rogue)\n",
])
def test_conditional_registration_rejects_receiver_mutation(mutation: str) -> None:
    helper = _REGISTRATION_HELPER.replace("    if enabled:", mutation + "    if enabled:")
    assert _check("from mcp.server.fastmcp import FastMCP\n"
                  "from demo.infrastructure.registration import conditional_prompt\n"
                  "def bind(server: FastMCP, callback):\n"
                  "    conditional_prompt(server, True)(callback)\n",
                  {"src/demo/infrastructure/registration.py": helper})


def test_conditional_registration_rejects_executable_identity_annotation() -> None:
    helper = _REGISTRATION_HELPER.replace("function: Callable[..., Any]", "function: rogue()")
    assert _check("from mcp.server.fastmcp import FastMCP\n"
                  "from demo.infrastructure.registration import conditional_prompt\n"
                  "def bind(server: FastMCP, callback):\n"
                  "    conditional_prompt(server, True)(callback)\n",
                  {"src/demo/infrastructure/registration.py": helper})


def test_conditional_registration_requires_an_unwrapped_source_definition() -> None:
    helper = _REGISTRATION_HELPER.replace("def conditional_prompt", "@rogue\ndef conditional_prompt")
    assert _check("from mcp.server.fastmcp import FastMCP\n"
                  "from demo.infrastructure.registration import conditional_prompt\n"
                  "def bind(server: FastMCP, callback):\n"
                  "    conditional_prompt(server, True)(callback)\n",
                  {"src/demo/infrastructure/registration.py": helper})


def test_inherited_configuration_method_uses_actual_source_body() -> None:
    router = "from demo.infrastructure.config import Config\n" \
             "def encode(config: Config):\n    return config.url()\n"
    helper = "class Base:\n    public_url: str\n    def url(self):\n        return self.public_url.rstrip('/')\n" \
             "class Config(Base):\n    pass\n"
    assert not _check(router, {"src/demo/infrastructure/config.py": helper})
    assert _check(router, {"src/demo/infrastructure/config.py":
                          helper.replace("return self.public_url", "repository.save('changed')\n        return self.public_url")})


@pytest.mark.parametrize("body", [
    "class Config(Base):\n    url = rogue\n",
    "class Config(Base):\n    def url(self): return 'safe'\n    url = rogue\n",
    "from unknown_sdk import OpaqueBase\nclass Config(OpaqueBase, Base):\n    pass\n",
])
def test_source_method_lookup_rejects_shadowing_or_unresolved_base_precedence(body: str) -> None:
    helper = "class Base:\n    def url(self): return 'safe'\n" + body
    assert _check("from demo.infrastructure.config import Config\n"
                  "def encode(config: Config):\n    return config.url()\n",
                  {"src/demo/infrastructure/config.py": helper})


_METADATA = """from urllib.parse import urlparse
from mcp.server.auth.routes import build_resource_metadata_url, cors_middleware
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.routing import Route
def bind(app: Starlette, callback, resource: str):
    path = urlparse(str(build_resource_metadata_url(AnyHttpUrl(resource)))).path
    indexes = [index for index, route in enumerate(app.routes) if getattr(route, 'path', None) == path]
    if len(indexes) != 1:
        raise RuntimeError('missing route')
    app.routes[indexes[0]] = Route(path, endpoint=cors_middleware(callback, ['GET']), methods=['GET'])
"""


def test_sdk_metadata_route_assembly_is_source_bound_transport() -> None:
    assert not _check(_METADATA)
    assert _check(_METADATA.replace("'path', None", "user_selected_method, None"))
    assert _check(_METADATA + "    repository.save('changed')\n")
    assert _check(_METADATA.replace("app: Starlette", "app"))

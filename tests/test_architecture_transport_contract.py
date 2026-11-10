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
                      "def helper():\n    create_order()\n"
                      "def encode():\n    helper()\n    helper()\n")
    assert any("application orchestrator" in detail for _, _, _, detail in failures)


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

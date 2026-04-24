from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path
from typing import Any

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_REPO_ROOT = REPO_ROOT / "template-repo"


def _load_module(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("test_boundaries_ast", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load architecture gate module from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_python(path: Path, source: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def _instantiate_template_repo(tmp_path: Path) -> Path:
    repo_root = tmp_path / "repo"
    shutil.copytree(TEMPLATE_REPO_ROOT, repo_root)
    return repo_root


def _seed_valid_cqrs_lite_slice(repo_root: Path) -> None:
    _write_python(
        repo_root / "backend/src/app/domain/orders/rules.py",
        "class OrderRules:\n    pass\n",
    )
    _write_python(
        repo_root / "backend/src/app/features/orders/create_order/ports/order_repository.py",
        "from typing import Protocol\n\n"
        "from app.domain.orders.rules import OrderRules\n\n"
        "class OrderRepository(Protocol):\n"
        "    def save(self, rules: OrderRules) -> None: ...\n",
    )
    _write_python(
        repo_root / "backend/src/app/features/orders/create_order/commands/create_order.py",
        "from app.domain.orders.rules import OrderRules\n"
        "from app.features.orders.create_order.ports.order_repository import OrderRepository\n\n"
        "def create_order(repo: OrderRepository) -> OrderRules:\n"
        "    rules = OrderRules()\n"
        "    repo.save(rules)\n"
        "    return rules\n",
    )
    _write_python(
        repo_root / "backend/src/app/features/orders/create_order/router/http.py",
        "from fastapi import APIRouter\n"
        "from app.features.orders.create_order.commands.create_order import create_order\n\n"
        "router = APIRouter()\n",
    )
    _write_python(
        repo_root / "backend/src/app/infrastructure/orders/sqlalchemy_repository.py",
        "from sqlalchemy import select\n"
        "from app.features.orders.create_order.ports.order_repository import OrderRepository\n",
    )


def test_template_architecture_gate_accepts_valid_sample_slice(tmp_path: Path) -> None:
    repo_root = _instantiate_template_repo(tmp_path)
    _seed_valid_cqrs_lite_slice(repo_root)
    module = _load_module(repo_root / "backend/tests/architecture/test_boundaries_ast.py")

    module.test_cqrs_lite_architecture_gate_has_files_to_check()
    module.test_domain_layer_does_not_import_frameworks_clients_or_outer_layers()
    module.test_use_cases_do_not_import_http_objects_or_infrastructure_clients()
    module.test_ports_do_not_import_sqlalchemy_or_concrete_adapters()
    module.test_routers_do_not_import_persistence_models_or_external_clients_directly()


def test_template_architecture_gate_rejects_use_case_http_objects(tmp_path: Path) -> None:
    repo_root = _instantiate_template_repo(tmp_path)
    _seed_valid_cqrs_lite_slice(repo_root)
    _write_python(
        repo_root / "backend/src/app/features/orders/create_order/commands/create_order.py",
        "from fastapi import Request\n\n"
        "def create_order(request: Request) -> None:\n"
        "    return None\n",
    )
    module = _load_module(repo_root / "backend/tests/architecture/test_boundaries_ast.py")

    with pytest.raises(AssertionError) as excinfo:
        module.test_use_cases_do_not_import_http_objects_or_infrastructure_clients()
    assert "fastapi.Request" in str(excinfo.value)

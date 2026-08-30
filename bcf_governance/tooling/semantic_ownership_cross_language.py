"""Deterministic Python/TypeScript endpoint trace construction.

Copyright 2026 Michael Golaszewski.
Licensed under the MIT License.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable


def _inside(path: str, roots: tuple[str, ...]) -> bool:
    return any(path == root or path.startswith(root.rstrip("/") + "/") for root in roots)


def build_endpoint_traces(
    python_inventory: dict[str, Any],
    typescript_inventory: dict[str, Any],
    *,
    browser_contract_roots: Iterable[str],
) -> list[dict[str, Any]]:
    """Join exact server routes to generated contracts, transports, and decoders."""
    roots = tuple(sorted(set(browser_contract_roots)))
    fetches = typescript_inventory.get("fetches", [])
    decoder_calls = typescript_inventory.get("decoder_calls", [])
    decoders_by_caller: dict[str, list[str]] = defaultdict(list)
    for decoder in decoder_calls:
        if isinstance(decoder, dict):
            decoders_by_caller[str(decoder.get("caller"))].append(
                str(decoder.get("symbol"))
            )
    contracts = {
        (str(contract.get("method")), str(contract.get("endpoint"))): contract
        for contract in typescript_inventory.get("endpoint_contracts", [])
        if isinstance(contract, dict)
    }
    decoder_entrypoints = sorted(
        {
            str(decoder.get("symbol"))
            for decoder in decoder_calls
            if isinstance(decoder, dict)
            and "responseDecoderForEndpoint" in str(decoder.get("symbol"))
        }
    )
    traces: list[dict[str, Any]] = []
    for endpoint in python_inventory.get("endpoints", []):
        if not isinstance(endpoint, dict):
            continue
        server_method = str(endpoint.get("method"))
        declared_path = str(endpoint.get("path"))
        generated_contract = contracts.get((server_method, declared_path))
        route_resolution = "exact"
        if generated_contract is None:
            suffix_candidates = [
                contract
                for (method, contract_path), contract in contracts.items()
                if method == server_method
                and declared_path.startswith("/")
                and contract_path.endswith(declared_path)
            ]
            if len(suffix_candidates) == 1:
                generated_contract = suffix_candidates[0]
                route_resolution = "unique_generated_contract_suffix"
        server_path = (
            str(generated_contract.get("endpoint"))
            if generated_contract is not None
            else declared_path
        )
        matched = [
            fetch
            for fetch in fetches
            if isinstance(fetch, dict)
            and str(fetch.get("endpoint", "")).split("?", 1)[0] == server_path
        ]
        server_symbol = str(endpoint.get("symbol", ""))
        required = _inside(server_symbol.split("::", 1)[0], roots)
        traces.append(
            {
                "server_path": server_path,
                "declared_server_path": declared_path,
                "route_resolution": route_resolution,
                "server_method": server_method,
                "response_model": endpoint.get("response_model"),
                "server_symbol": endpoint.get("symbol"),
                "browser_contract_required": required,
                "generated_browser_contract": generated_contract,
                "browser_decoder_entrypoints": decoder_entrypoints,
                "browser_consumers": [
                    {
                        "symbol": fetch.get("caller"),
                        "decoders": sorted(
                            set(decoders_by_caller.get(str(fetch.get("caller")), []))
                        ),
                        "transports": [str(fetch.get("transport_symbol"))],
                    }
                    for fetch in matched
                ],
                "decoder_coverage": bool(
                    generated_contract
                    and decoder_entrypoints
                    and all(
                        decoders_by_caller.get(str(fetch.get("caller")))
                        for fetch in matched
                    )
                ),
            }
        )
    return traces

from __future__ import annotations

import ast
import hashlib
import json
from builtins import BaseExceptionGroup
from dataclasses import fields
from pathlib import Path

import pytest

import app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_implementation_readiness as module
from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_readiness import (
    DOCUMENT_TYPE as STEP226_DOCUMENT_TYPE,
)
from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_readiness import (
    PROFILE as STEP226_PROFILE,
)
from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_readiness import (
    SOURCE as STEP226_SOURCE,
)
from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_readiness import (
    STEP225_PACKAGE_MANIFEST_SHA256,
)

ADAPTER_FILE = (
    Path(__file__).parents[1]
    / "app/security/authentication_entra_calling_client_msal_browser_zero_retry_network_client.mjs"
)


def _step226_document() -> bytes:
    return json.dumps(
        {
            "document_type": STEP226_DOCUMENT_TYPE,
            "schema_version": 1,
            "source": STEP226_SOURCE,
            "approved_step225_package_manifest_sha256": STEP225_PACKAGE_MANIFEST_SHA256,
            "override_profile": STEP226_PROFILE,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _document(**updates: object) -> bytes:
    value: dict[str, object] = {
        "document_type": module.DOCUMENT_TYPE,
        "schema_version": 1,
        "source": module.SOURCE,
        "approved_step226_package_manifest_sha256": (
            module.STEP226_PACKAGE_MANIFEST_SHA256
        ),
        "approved_adapter_sha256": module.ADAPTER_SHA256,
        "implementation_profile": module.PROFILE,
    }
    value.update(updates)
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _adapter() -> bytes:
    return ADAPTER_FILE.read_bytes()


def _receipt():
    return module.load_entra_calling_client_msal_zero_retry_network_client_implementation_readiness(
        _document(), _step226_document(), _adapter()
    )


def _unsafe_clone(receipt, field_name: str, value: object):
    clone = object.__new__(type(receipt))
    for field in fields(receipt):
        object.__setattr__(
            clone,
            field.name,
            value if field.name == field_name else getattr(receipt, field.name),
        )
    return clone


def _framed(domain: str, value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()
    return hashlib.sha256(
        b"Engineer4Me-Step227-v1\x00" + domain.encode() + b"\x00" + payload
    ).hexdigest()


def test_exact_adapter_file_identity_and_static_structure() -> None:
    adapter = _adapter()
    text = adapter.decode("utf-8")
    assert len(adapter) == 8_007 == module.ADAPTER_BYTES
    assert hashlib.sha256(adapter).hexdigest() == module.ADAPTER_SHA256
    assert module.ADAPTER_PATH.endswith(
        "authentication_entra_calling_client_msal_browser_zero_retry_network_client.mjs"
    )
    assert text.count("this.#fetchImplementation(url, {") == 1
    assert text.count("setTimeout(") == 1
    assert text.count("clearTimeout(") == 1
    assert "console." not in text
    assert "XMLHttpRequest" not in text
    assert "TOKEN_POST_ATTEMPTS = 1" in text
    assert "TOKEN_POST_RETRIES = 0" in text


def test_valid_receipt_binds_source_without_runtime_overclaim() -> None:
    receipt = _receipt()
    assert receipt.adapter_source_implemented is True
    assert receipt.exact_adapter_source_identity_bound is True
    assert receipt.token_post_attempt_count == 1
    assert receipt.token_post_retry_count == 0
    assert receipt.step216_zero_retry_policy_preserved is True
    assert receipt.step225_default_retry_rejection_preserved is True
    assert receipt.node_syntax_checked_by_contract is False
    assert receipt.sealed_fake_fetch_behavior_executed is False
    assert receipt.browser_fetch_behavior_checked is False
    assert receipt.package_selection_approved is False


def test_profile_digests_are_independently_recomputed() -> None:
    receipt = _receipt()
    expected = {
        "adapter_interface_profile_sha256": _framed(
            "interface",
            {
                "class": "Engineer4MeMSALZeroRetryNetworkClient",
                "methods": ["sendGetRequestAsync", "sendPostRequestAsync"],
                "configuration_key": "system.networkClient",
            },
        ),
        "token_post_profile_sha256": _framed(
            "token-post",
            {
                "target": "exact_step216_derived_token_endpoint",
                "attempts": 1,
                "retries": 0,
                "body_replay": False,
            },
        ),
        "fetch_options_profile_sha256": _framed(
            "fetch",
            {
                "mode": "cors",
                "credentials": "omit",
                "redirect": "error",
                "cache": "no-store",
                "referrerPolicy": "no-referrer",
                "timeout_ms": 10_000,
            },
        ),
        "request_header_profile_sha256": _framed(
            "request-headers",
            [
                "authorization",
                "connection",
                "content-length",
                "cookie",
                "host",
                "proxy-authorization",
                "transfer-encoding",
            ],
        ),
        "response_profile_sha256": _framed(
            "response",
            {
                "maximum_bytes": 1_048_576,
                "utf8_fatal": True,
                "json_object": True,
                "projection": ["headers", "body", "status"],
            },
        ),
        "successor_execution_gate_sha256": _framed(
            "successor",
            {
                "node_syntax": True,
                "sealed_fake_fetch_execution": True,
                "attempt_count_matrix": True,
                "browser_integration": True,
                "package_selection_approved": False,
            },
        ),
    }
    assert {name: getattr(receipt, name) for name in expected} == expected
    assert len(set(expected.values())) == len(expected)


def test_step226_is_rerun_before_adapter_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False
    original = module.load_entra_calling_client_msal_zero_retry_network_client_readiness

    def tracked(value: object):
        nonlocal called
        called = True
        return original(value)

    monkeypatch.setattr(
        module,
        "load_entra_calling_client_msal_zero_retry_network_client_readiness",
        tracked,
    )
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessError
    ):
        module.load_entra_calling_client_msal_zero_retry_network_client_implementation_readiness(
            _document(), _step226_document(), b"wrong"
        )
    assert called is True


@pytest.mark.parametrize(
    "updates",
    [
        {"document_type": "wrong"},
        {"schema_version": 2},
        {"schema_version": True},
        {"source": "wrong"},
        {"approved_step226_package_manifest_sha256": "0" * 64},
        {"approved_adapter_sha256": "0" * 64},
        {"implementation_profile": "wrong"},
        {"extra": True},
    ],
)
def test_document_tampering_fails(updates: dict[str, object]) -> None:
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessError
    ):
        module.load_entra_calling_client_msal_zero_retry_network_client_implementation_readiness(
            _document(**updates), _step226_document(), _adapter()
        )


@pytest.mark.parametrize("mutation", [b"x", b"\n", b"\x00"])
def test_adapter_byte_tampering_fails(mutation: bytes) -> None:
    adapter = _adapter()
    candidate = adapter + mutation if mutation == b"\n" else adapter[:-1] + mutation
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessError
    ):
        module.load_entra_calling_client_msal_zero_retry_network_client_implementation_readiness(
            _document(), _step226_document(), candidate
        )


@pytest.mark.parametrize("index", [0, 5, 50, 500, 4_000, 8_006])
def test_same_size_adapter_tampering_fails(index: int) -> None:
    candidate = bytearray(_adapter())
    candidate[index] ^= 1
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessError
    ):
        module.load_entra_calling_client_msal_zero_retry_network_client_implementation_readiness(
            _document(), _step226_document(), bytes(candidate)
        )


@pytest.mark.parametrize("position", [0, 1, 2])
def test_public_api_requires_exact_bytes(position: int) -> None:
    values: list[object] = [_document(), _step226_document(), _adapter()]
    values[position] = bytearray(values[position])  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="input is invalid"):
        module.load_entra_calling_client_msal_zero_retry_network_client_implementation_readiness(
            *values
        )


def test_public_api_rejects_aliasing_before_prerequisite_use() -> None:
    shared = _document()
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessError
    ):
        module.load_entra_calling_client_msal_zero_retry_network_client_implementation_readiness(
            shared, shared, _adapter()
        )


def test_every_receipt_field_is_guarded() -> None:
    receipt = _receipt()
    flexible = {"implementation_document_sha256", "step226_receipt_sha256"}
    for field in fields(receipt):
        current = getattr(receipt, field.name)
        if field.name in flexible:
            invalid: object = "x"
        elif type(current) is bool:
            invalid = not current
        elif type(current) is int:
            invalid = True
        else:
            invalid = "0" * 64 if current != "0" * 64 else "1" * 64
        clone = _unsafe_clone(receipt, field.name, invalid)
        with pytest.raises(ValueError):
            clone.__post_init__()


def test_boolean_partition_is_complete_and_disjoint() -> None:
    receipt = _receipt()
    bool_names = {field.name for field in fields(receipt) if field.type == "bool"}
    true_names = {name for name in bool_names if getattr(receipt, name) is True}
    false_names = {name for name in bool_names if getattr(receipt, name) is False}
    assert len(true_names) == 20
    assert len(false_names) == 18
    assert true_names.isdisjoint(false_names)
    assert true_names | false_names == bool_names


def test_renderer_is_canonical_and_exact() -> None:
    receipt = _receipt()
    rendered = module.render_entra_calling_client_msal_zero_retry_network_client_implementation_readiness_receipt(
        receipt
    )
    assert rendered == json.dumps(
        json.loads(rendered), sort_keys=True, separators=(",", ":")
    )
    assert set(json.loads(rendered)) == set(receipt.__dataclass_fields__)
    assert "\n" not in rendered


def test_renderer_requires_exact_receipt() -> None:
    with pytest.raises(TypeError, match="exact zero-retry"):
        module.render_entra_calling_client_msal_zero_retry_network_client_implementation_readiness_receipt(
            object()  # type: ignore[arg-type]
        )


def test_nested_control_flow_is_preserved_and_private_evidence_is_detached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child = ValueError("private-adapter-marker")
    group = BaseExceptionGroup(
        "private-group-marker",
        [SystemExit("private-exit"), KeyboardInterrupt("private-interrupt"), child],
    )

    def fail(*_: object) -> None:
        raise group

    monkeypatch.setattr(module, "_load_internal", fail)
    with pytest.raises(KeyboardInterrupt) as caught:
        module.load_entra_calling_client_msal_zero_retry_network_client_implementation_readiness(
            _document(), _step226_document(), _adapter()
        )
    assert "private" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert child.args == ()
    assert child.__traceback__ is None


def test_module_has_no_filesystem_process_or_network_imports() -> None:
    source = Path(module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert not imported & {
        "asyncio",
        "httpx",
        "os",
        "pathlib",
        "requests",
        "socket",
        "ssl",
        "subprocess",
        "tempfile",
        "urllib",
    }


def test_public_export_set_is_exact_and_unique() -> None:
    assert len(module.__all__) == len(set(module.__all__))
    assert set(module.__all__) == {
        "ADAPTER_BYTES",
        "ADAPTER_PATH",
        "ADAPTER_SHA256",
        "DOCUMENT_TYPE",
        "EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessError",
        "EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessReceipt",
        "PROFILE",
        "RECEIPT_TYPE",
        "SOURCE",
        "STATUS",
        "STEP226_PACKAGE_MANIFEST_SHA256",
        "load_entra_calling_client_msal_zero_retry_network_client_implementation_readiness",
        "render_entra_calling_client_msal_zero_retry_network_client_implementation_readiness_receipt",
    }

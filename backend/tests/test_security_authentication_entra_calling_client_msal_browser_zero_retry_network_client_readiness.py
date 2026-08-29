from __future__ import annotations

import ast
import hashlib
import json
from builtins import BaseExceptionGroup
from dataclasses import fields
from pathlib import Path

import pytest

import app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_readiness as module


def _document(**updates: object) -> bytes:
    value: dict[str, object] = {
        "document_type": module.DOCUMENT_TYPE,
        "schema_version": 1,
        "source": module.SOURCE,
        "approved_step225_package_manifest_sha256": (
            module.STEP225_PACKAGE_MANIFEST_SHA256
        ),
        "override_profile": module.PROFILE,
    }
    value.update(updates)
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _receipt():
    return module.load_entra_calling_client_msal_zero_retry_network_client_readiness(
        _document()
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
        b"Engineer4Me-Step226-v1\x00" + domain.encode() + b"\x00" + payload
    ).hexdigest()


def test_valid_receipt_binds_exact_zero_retry_override_plan() -> None:
    receipt = _receipt()
    assert receipt.browser_package_name == "@azure/msal-browser"
    assert receipt.browser_version == "5.18.0"
    assert receipt.common_package_name == "@azure/msal-common"
    assert receipt.common_version == "16.12.0"
    assert receipt.network_client_configuration_key == "system.networkClient"
    assert receipt.get_method_name == "sendGetRequestAsync"
    assert receipt.post_method_name == "sendPostRequestAsync"
    assert receipt.token_post_attempt_count == 1
    assert receipt.token_post_retry_count == 0
    assert receipt.request_timeout_milliseconds == 10_000
    assert receipt.maximum_response_bytes == 1_048_576


def test_exact_reviewed_compiled_identities_are_public_constants() -> None:
    assert module.CONFIGURATION_PATH == "package/dist/config/Configuration.mjs"
    assert module.CONFIGURATION_SHA256 == (
        "896222cbb1d12b93afe9852548170e892eb0983c8f93e626f571335de9638b2e"
    )
    assert module.CONFIGURATION_BYTES == 5_877
    assert module.FETCH_CLIENT_PATH == "package/dist/network/FetchClient.mjs"
    assert module.FETCH_CLIENT_SHA256 == (
        "abf75690801b45b64347873bb5483774aab1b70f1cf261021aa4e6b5181e9704"
    )


def test_profile_digests_are_independently_recomputed() -> None:
    receipt = _receipt()
    expected = {
        "override_interface_profile_sha256": _framed(
            "interface",
            {
                "configuration_key": "system.networkClient",
                "methods": ["sendGetRequestAsync", "sendPostRequestAsync"],
                "response": ["headers", "body", "status"],
            },
        ),
        "token_post_policy_sha256": _framed(
            "token-post",
            {
                "target": "exact_step216_derived_token_endpoint",
                "attempts": 1,
                "retries": 0,
                "loops": False,
                "recursive_calls": False,
                "backoff_timers": False,
                "body_replay": False,
            },
        ),
        "fetch_security_profile_sha256": _framed(
            "fetch",
            {
                "mode": "cors",
                "credentials": "omit",
                "redirect": "error",
                "cache": "no-store",
                "referrerPolicy": "no-referrer",
                "timeout_ms": 10_000,
                "forbidden_headers": [
                    "authorization",
                    "connection",
                    "content-length",
                    "cookie",
                    "host",
                    "proxy-authorization",
                    "transfer-encoding",
                ],
            },
        ),
        "response_projection_profile_sha256": _framed(
            "response",
            {
                "maximum_bytes": 1_048_576,
                "json_once": True,
                "status": True,
                "normalized_headers": True,
                "token_logging": False,
            },
        ),
        "failure_handling_profile_sha256": _framed(
            "failures",
            {
                "transport": "sanitized_once_no_retry",
                "abort": "sanitized_no_retry",
                "timeout": "abort_then_sanitized_no_retry",
                "http": "return_response_no_retry",
                "json": "sanitized_no_retry",
                "oauth": "return_response_no_retry",
            },
        ),
        "successor_implementation_gate_sha256": _framed(
            "successor",
            {
                "typescript_source_required": True,
                "compiled_identity_required": True,
                "sealed_fake_fetch_matrix_required": True,
                "browser_integration_required": True,
                "exact_token_endpoint_required": True,
                "package_selection_approved": False,
            },
        ),
    }
    assert {name: getattr(receipt, name) for name in expected} == expected
    assert len(set(expected.values())) == len(expected)


def test_readiness_document_digest_binds_canonical_document() -> None:
    receipt = _receipt()
    canonical = json.dumps(
        json.loads(_document()), sort_keys=True, separators=(",", ":")
    ).encode()
    assert receipt.readiness_document_sha256 == hashlib.sha256(canonical).hexdigest()


def test_true_and_deferred_boolean_partitions_are_exact() -> None:
    receipt = _receipt()
    true_names = {
        "step225_package_manifest_digest_bound",
        "exact_msal_browser_and_common_versions_bound",
        "exact_configuration_and_fetch_client_identities_bound",
        "system_network_client_override_supported_declared",
        "exact_get_and_post_interface_required",
        "exact_token_endpoint_post_target_required",
        "exactly_one_token_post_attempt_required",
        "zero_token_post_retries_required",
        "retry_loop_timer_and_recursion_forbidden",
        "request_body_reuse_or_replay_forbidden",
        "credentials_omit_required",
        "cors_mode_required",
        "redirects_rejected_required",
        "browser_cache_bypass_required",
        "no_referrer_required",
        "abort_controller_timeout_required",
        "timeout_abort_must_not_retry",
        "bounded_response_required",
        "response_status_headers_and_json_projection_required",
        "authorization_cookie_and_proxy_headers_forbidden",
        "sensitive_body_or_token_logging_forbidden",
        "normalized_sanitized_error_required",
        "step216_zero_retry_requirement_satisfied_by_plan",
        "step225_retry_rejection_preserved",
        "no_version_downgrade_required",
        "offline_override_readiness_validated",
    }
    deferred_names = {
        "step225_rendered_receipt_accepted_as_provenance",
        "compiled_configuration_rescanned",
        "adapter_source_implemented",
        "adapter_compiled",
        "adapter_behavior_executed",
        "browser_fetch_behavior_checked",
        "exact_token_endpoint_cors_checked",
        "dns_tls_http_checked",
        "real_oauth_values_processed",
        "runtime_pkce_or_token_exchange_executed",
        "library_compatibility_approved",
        "package_selection_approved",
        "dependency_installed_or_locked",
        "frontend_framework_selected",
        "application_configuration_mutation_performed",
        "application_activation_performed",
    }
    bool_names = {field.name for field in fields(receipt) if field.type == "bool"}
    assert true_names | deferred_names == bool_names
    assert true_names.isdisjoint(deferred_names)
    assert all(getattr(receipt, name) is True for name in true_names)
    assert all(getattr(receipt, name) is False for name in deferred_names)


@pytest.mark.parametrize(
    "updates",
    [
        {"document_type": "wrong"},
        {"schema_version": 2},
        {"schema_version": True},
        {"source": "wrong"},
        {"approved_step225_package_manifest_sha256": "0" * 64},
        {"override_profile": "wrong"},
        {"extra": True},
    ],
)
def test_document_semantic_tampering_fails(updates: dict[str, object]) -> None:
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryNetworkClientReadinessError
    ):
        module.load_entra_calling_client_msal_zero_retry_network_client_readiness(
            _document(**updates)
        )


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"null",
        b"[]",
        b"{",
        b'{"schema_version":NaN}',
        b'{"schema_version":1,"schema_version":1}',
        b"\xff",
        b" " * 4_097,
    ],
)
def test_malformed_documents_fail_with_sanitized_error(payload: bytes) -> None:
    with pytest.raises(
        module.EntraCallingClientMSALZeroRetryNetworkClientReadinessError
    ) as caught:
        module.load_entra_calling_client_msal_zero_retry_network_client_readiness(
            payload
        )
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


@pytest.mark.parametrize("value", [None, "x", bytearray(b"x"), memoryview(b"x")])
def test_public_loader_requires_exact_bytes(value: object) -> None:
    with pytest.raises(TypeError, match="input is invalid"):
        module.load_entra_calling_client_msal_zero_retry_network_client_readiness(value)


def test_keyboard_interrupt_and_system_exit_are_preserved_and_detached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for injected, expected in (
        (KeyboardInterrupt("private"), KeyboardInterrupt),
        (SystemExit("private"), SystemExit),
    ):

        def fail(_: object, error: BaseException = injected):
            raise error

        monkeypatch.setattr(module, "_load_internal", fail)
        with pytest.raises(expected) as caught:
            module.load_entra_calling_client_msal_zero_retry_network_client_readiness(
                _document()
            )
        assert "private" not in str(caught.value)
        assert caught.value.__cause__ is None
        assert caught.value.__context__ is None


def test_nested_exception_group_is_sanitized_and_keyboard_interrupt_wins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child = ValueError("private-document-marker")
    group = BaseExceptionGroup(
        "private-group-marker",
        [SystemExit("private-exit"), KeyboardInterrupt("private-interrupt"), child],
    )

    def fail(_: object) -> None:
        raise group

    monkeypatch.setattr(module, "_load_internal", fail)
    with pytest.raises(KeyboardInterrupt) as caught:
        module.load_entra_calling_client_msal_zero_retry_network_client_readiness(
            _document()
        )
    assert "private" not in str(caught.value)
    assert child.args == ()
    assert child.__traceback__ is None


def test_renderer_is_canonical_and_round_trips_every_field() -> None:
    receipt = _receipt()
    rendered = module.render_entra_calling_client_msal_zero_retry_network_client_readiness_receipt(
        receipt
    )
    assert rendered == json.dumps(
        json.loads(rendered), sort_keys=True, separators=(",", ":")
    )
    assert set(json.loads(rendered)) == set(receipt.__dataclass_fields__)
    assert " " not in rendered
    assert "\n" not in rendered


def test_renderer_requires_exact_receipt() -> None:
    for value in (None, {}, object()):
        with pytest.raises(TypeError, match="exact MSAL zero-retry readiness receipt"):
            module.render_entra_calling_client_msal_zero_retry_network_client_readiness_receipt(
                value  # type: ignore[arg-type]
            )


def test_every_constant_boolean_and_profile_digest_is_post_init_guarded() -> None:
    receipt = _receipt()
    flexible = {"readiness_document_sha256"}
    for field in fields(receipt):
        if field.name in flexible:
            invalid: object = "x"
        else:
            current = getattr(receipt, field.name)
            if type(current) is bool:
                invalid = not current
            elif type(current) is int:
                invalid = True
            else:
                invalid = "0" * 64 if current != "0" * 64 else "1" * 64
        clone = _unsafe_clone(receipt, field.name, invalid)
        with pytest.raises(ValueError):
            clone.__post_init__()


def test_module_import_surface_is_offline_and_has_no_filesystem_io() -> None:
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
        "urllib",
    }
    calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not calls & {"open", "exec", "eval", "compile"}


def test_public_export_set_is_exact_and_unique() -> None:
    assert len(module.__all__) == len(set(module.__all__))
    assert set(module.__all__) == {
        "BROWSER_PACKAGE_NAME",
        "BROWSER_VERSION",
        "CONFIGURATION_PATH",
        "CONFIGURATION_SHA256",
        "DOCUMENT_TYPE",
        "EntraCallingClientMSALZeroRetryNetworkClientReadinessError",
        "EntraCallingClientMSALZeroRetryNetworkClientReadinessReceipt",
        "FETCH_CLIENT_PATH",
        "FETCH_CLIENT_SHA256",
        "NETWORK_CLIENT_CONFIGURATION_KEY",
        "PROFILE",
        "RECEIPT_TYPE",
        "SOURCE",
        "STATUS",
        "STEP225_PACKAGE_MANIFEST_SHA256",
        "load_entra_calling_client_msal_zero_retry_network_client_readiness",
        "render_entra_calling_client_msal_zero_retry_network_client_readiness_receipt",
    }

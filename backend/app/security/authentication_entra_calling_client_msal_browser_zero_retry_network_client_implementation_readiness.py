"""Offline exact-source readiness for the MSAL Browser zero-retry adapter."""

from __future__ import annotations

import hashlib
import json
from builtins import BaseExceptionGroup
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import model_validator

from app.security.authentication_entra_calling_client_msal_browser_zero_retry_network_client_readiness import (
    EntraCallingClientMSALZeroRetryNetworkClientReadinessReceipt,
    load_entra_calling_client_msal_zero_retry_network_client_readiness,
    render_entra_calling_client_msal_zero_retry_network_client_readiness_receipt,
)
from app.security.identity_models import SecurityModel

DOCUMENT_TYPE = "engineer4me_microsoft_entra_calling_client_msal_zero_retry_network_client_implementation_readiness"
RECEIPT_TYPE = DOCUMENT_TYPE + "_receipt"
SCHEMA_VERSION = 1
SOURCE = "engineer4me_reviewed_exact_zero_retry_network_client_source"
SCOPE = "offline_exact_source_static_implementation_readiness"
PROFILE = "engineer4me_msal_browser_5_18_0_zero_retry_network_client_source_v1"
STATUS = "source_bound_but_not_compiled_executed_integrated_or_selected"
STEP226_PACKAGE_MANIFEST_SHA256 = (
    "4989f1a514d2f159a602fc7e3e4b7513cb34f08fa619390e2b57d16b7235a4b5"
)
ADAPTER_PATH = (
    "backend/app/security/"
    "authentication_entra_calling_client_msal_browser_zero_retry_network_client.mjs"
)
ADAPTER_SHA256 = "c36e718f4893959be94e4b51f6cfa76e0ac34da7c310151d23e446a3794f7a73"
ADAPTER_BYTES = 8_007
TOKEN_POST_ATTEMPTS = 1
TOKEN_POST_RETRIES = 0
REQUEST_TIMEOUT_MILLISECONDS = 10_000
MAXIMUM_RESPONSE_BYTES = 1_048_576
MAX_DOCUMENT_BYTES = 4_096


class EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessError(
    ValueError
):
    """Sanitized Step 227 implementation-readiness failure."""


class _ArgumentTypeError(TypeError):
    """Private marker for invalid public input types."""


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def _framed(domain: str, value: object) -> str:
    return hashlib.sha256(
        b"Engineer4Me-Step227-v1\x00" + domain.encode() + b"\x00" + _canonical(value)
    ).hexdigest()


def _profiles() -> dict[str, str]:
    return {
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
                "attempts": TOKEN_POST_ATTEMPTS,
                "retries": TOKEN_POST_RETRIES,
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
                "timeout_ms": REQUEST_TIMEOUT_MILLISECONDS,
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
                "maximum_bytes": MAXIMUM_RESPONSE_BYTES,
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


class EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessDocument(
    SecurityModel
):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_zero_retry_network_client_implementation_readiness"
    ]
    schema_version: Literal[1]
    source: Literal["engineer4me_reviewed_exact_zero_retry_network_client_source"]
    approved_step226_package_manifest_sha256: str
    approved_adapter_sha256: str
    implementation_profile: Literal[
        "engineer4me_msal_browser_5_18_0_zero_retry_network_client_source_v1"
    ]

    @model_validator(mode="before")
    @classmethod
    def validate_exact_wire_types(cls, value: object) -> object:
        if type(value) is not dict:
            raise ValueError(
                "implementation-readiness document must be an exact object"
            )
        expected = {
            "document_type": str,
            "schema_version": int,
            "source": str,
            "approved_step226_package_manifest_sha256": str,
            "approved_adapter_sha256": str,
            "implementation_profile": str,
        }
        if set(value) != set(expected):
            raise ValueError("implementation-readiness document keys are not exact")
        if any(
            type(value[name]) is not expected_type
            for name, expected_type in expected.items()
        ):
            raise ValueError("implementation-readiness document types are not exact")
        return value

    @model_validator(mode="after")
    def validate_approved_identities(
        self,
    ) -> EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessDocument:
        if (
            self.approved_step226_package_manifest_sha256
            != STEP226_PACKAGE_MANIFEST_SHA256
        ):
            raise ValueError("approved Step 226 package manifest is not exact")
        if self.approved_adapter_sha256 != ADAPTER_SHA256:
            raise ValueError("approved adapter source is not exact")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    implementation_profile: str
    readiness_status: str
    adapter_path: str
    approved_step226_package_manifest_sha256: str
    implementation_document_sha256: str
    step226_receipt_sha256: str
    adapter_sha256: str
    adapter_interface_profile_sha256: str
    token_post_profile_sha256: str
    fetch_options_profile_sha256: str
    request_header_profile_sha256: str
    response_profile_sha256: str
    successor_execution_gate_sha256: str
    adapter_bytes: int
    token_post_attempt_count: int
    token_post_retry_count: int
    request_timeout_milliseconds: int
    maximum_response_bytes: int
    step226_source_document_rerun: bool
    step226_rendered_receipt_accepted_as_provenance: bool
    step226_package_manifest_digest_bound: bool
    exact_adapter_source_identity_bound: bool
    adapter_source_implemented: bool
    exact_network_client_interface_implemented: bool
    exact_token_endpoint_post_confinement_implemented: bool
    exactly_one_fetch_invocation_structure_implemented: bool
    zero_retry_loop_structure_implemented: bool
    no_request_body_replay_structure_implemented: bool
    fixed_fetch_security_options_implemented: bool
    abort_controller_timeout_implemented: bool
    bounded_streaming_response_implemented: bool
    normalized_response_projection_implemented: bool
    forbidden_request_headers_implemented: bool
    sanitized_error_surface_implemented: bool
    no_logging_calls_implemented: bool
    step216_zero_retry_policy_preserved: bool
    step225_default_retry_rejection_preserved: bool
    no_version_downgrade_performed: bool
    offline_static_implementation_readiness_validated: bool
    node_syntax_checked_by_contract: bool
    adapter_compiled_or_bundled: bool
    sealed_fake_fetch_behavior_executed: bool
    token_post_attempt_count_dynamically_observed: bool
    timeout_abort_dynamically_observed: bool
    response_bound_dynamically_observed: bool
    browser_fetch_behavior_checked: bool
    token_endpoint_cors_checked: bool
    msal_runtime_compatibility_approved: bool
    frontend_import_graph_checked: bool
    package_selection_approved: bool
    dependency_installed_or_locked: bool
    real_oauth_values_processed: bool
    runtime_pkce_or_token_exchange_executed: bool
    network_or_provider_io_performed: bool
    application_configuration_mutation_performed: bool
    application_activation_performed: bool

    def __post_init__(self) -> None:
        constants: dict[str, object] = {
            "receipt_type": RECEIPT_TYPE,
            "schema_version": SCHEMA_VERSION,
            "source": SOURCE,
            "validation_scope": SCOPE,
            "implementation_profile": PROFILE,
            "readiness_status": STATUS,
            "adapter_path": ADAPTER_PATH,
            "approved_step226_package_manifest_sha256": STEP226_PACKAGE_MANIFEST_SHA256,
            "adapter_sha256": ADAPTER_SHA256,
            "adapter_bytes": ADAPTER_BYTES,
            "token_post_attempt_count": TOKEN_POST_ATTEMPTS,
            "token_post_retry_count": TOKEN_POST_RETRIES,
            "request_timeout_milliseconds": REQUEST_TIMEOUT_MILLISECONDS,
            "maximum_response_bytes": MAXIMUM_RESPONSE_BYTES,
        }
        for name, expected in constants.items():
            actual = getattr(self, name)
            if type(actual) is not type(expected) or actual != expected:
                raise ValueError("implementation-readiness constant is invalid")
        for name in ("implementation_document_sha256", "step226_receipt_sha256"):
            if not _is_sha256(getattr(self, name)):
                raise ValueError("implementation-readiness evidence digest is invalid")
        for name, expected in _profiles().items():
            if type(getattr(self, name)) is not str or getattr(self, name) != expected:
                raise ValueError("implementation-readiness profile digest is invalid")
        true_names = (
            "step226_source_document_rerun",
            "step226_package_manifest_digest_bound",
            "exact_adapter_source_identity_bound",
            "adapter_source_implemented",
            "exact_network_client_interface_implemented",
            "exact_token_endpoint_post_confinement_implemented",
            "exactly_one_fetch_invocation_structure_implemented",
            "zero_retry_loop_structure_implemented",
            "no_request_body_replay_structure_implemented",
            "fixed_fetch_security_options_implemented",
            "abort_controller_timeout_implemented",
            "bounded_streaming_response_implemented",
            "normalized_response_projection_implemented",
            "forbidden_request_headers_implemented",
            "sanitized_error_surface_implemented",
            "no_logging_calls_implemented",
            "step216_zero_retry_policy_preserved",
            "step225_default_retry_rejection_preserved",
            "no_version_downgrade_performed",
            "offline_static_implementation_readiness_validated",
        )
        false_names = (
            "step226_rendered_receipt_accepted_as_provenance",
            "node_syntax_checked_by_contract",
            "adapter_compiled_or_bundled",
            "sealed_fake_fetch_behavior_executed",
            "token_post_attempt_count_dynamically_observed",
            "timeout_abort_dynamically_observed",
            "response_bound_dynamically_observed",
            "browser_fetch_behavior_checked",
            "token_endpoint_cors_checked",
            "msal_runtime_compatibility_approved",
            "frontend_import_graph_checked",
            "package_selection_approved",
            "dependency_installed_or_locked",
            "real_oauth_values_processed",
            "runtime_pkce_or_token_exchange_executed",
            "network_or_provider_io_performed",
            "application_configuration_mutation_performed",
            "application_activation_performed",
        )
        for name in true_names:
            if type(getattr(self, name)) is not bool or not getattr(self, name):
                raise ValueError("required implementation-readiness fact is false")
        for name in false_names:
            if type(getattr(self, name)) is not bool or getattr(self, name):
                raise ValueError("deferred implementation-readiness fact is true")


def _parse_document(
    value: bytes,
) -> EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessDocument:
    if not value or len(value) > MAX_DOCUMENT_BYTES:
        raise ValueError("implementation-readiness document size is invalid")
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(
            "implementation-readiness document encoding is invalid"
        ) from None
    try:
        raw = json.loads(text, object_pairs_hook=_pairs)
    except (json.JSONDecodeError, ValueError):
        raise ValueError("implementation-readiness document JSON is invalid") from None
    return EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessDocument.model_validate(
        raw
    )


def _load_internal(
    document_bytes: object,
    step226_document_bytes: object,
    adapter_bytes: object,
) -> EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessReceipt:
    if (
        type(document_bytes) is not bytes
        or type(step226_document_bytes) is not bytes
        or type(adapter_bytes) is not bytes
    ):
        raise _ArgumentTypeError("exact source document and adapter bytes are required")
    if document_bytes is step226_document_bytes or document_bytes is adapter_bytes:
        raise ValueError("implementation-readiness inputs must be distinct objects")
    step226_receipt = (
        load_entra_calling_client_msal_zero_retry_network_client_readiness(
            step226_document_bytes
        )
    )
    if (
        type(step226_receipt)
        is not EntraCallingClientMSALZeroRetryNetworkClientReadinessReceipt
        or not step226_receipt.offline_override_readiness_validated
        or step226_receipt.package_selection_approved
    ):
        raise ValueError("Step 226 prerequisite receipt is invalid")
    document = _parse_document(document_bytes)
    if len(adapter_bytes) != ADAPTER_BYTES:
        raise ValueError("adapter source size is not exact")
    if hashlib.sha256(adapter_bytes).hexdigest() != ADAPTER_SHA256:
        raise ValueError("adapter source hash is not exact")
    step226_rendered = (
        render_entra_calling_client_msal_zero_retry_network_client_readiness_receipt(
            step226_receipt
        ).encode()
    )
    canonical_document = _canonical(document.model_dump(mode="json"))
    true_values = {
        name: True
        for name in (
            "step226_source_document_rerun",
            "step226_package_manifest_digest_bound",
            "exact_adapter_source_identity_bound",
            "adapter_source_implemented",
            "exact_network_client_interface_implemented",
            "exact_token_endpoint_post_confinement_implemented",
            "exactly_one_fetch_invocation_structure_implemented",
            "zero_retry_loop_structure_implemented",
            "no_request_body_replay_structure_implemented",
            "fixed_fetch_security_options_implemented",
            "abort_controller_timeout_implemented",
            "bounded_streaming_response_implemented",
            "normalized_response_projection_implemented",
            "forbidden_request_headers_implemented",
            "sanitized_error_surface_implemented",
            "no_logging_calls_implemented",
            "step216_zero_retry_policy_preserved",
            "step225_default_retry_rejection_preserved",
            "no_version_downgrade_performed",
            "offline_static_implementation_readiness_validated",
        )
    }
    false_values = {
        name: False
        for name in (
            "step226_rendered_receipt_accepted_as_provenance",
            "node_syntax_checked_by_contract",
            "adapter_compiled_or_bundled",
            "sealed_fake_fetch_behavior_executed",
            "token_post_attempt_count_dynamically_observed",
            "timeout_abort_dynamically_observed",
            "response_bound_dynamically_observed",
            "browser_fetch_behavior_checked",
            "token_endpoint_cors_checked",
            "msal_runtime_compatibility_approved",
            "frontend_import_graph_checked",
            "package_selection_approved",
            "dependency_installed_or_locked",
            "real_oauth_values_processed",
            "runtime_pkce_or_token_exchange_executed",
            "network_or_provider_io_performed",
            "application_configuration_mutation_performed",
            "application_activation_performed",
        )
    }
    return EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessReceipt(
        receipt_type=RECEIPT_TYPE,
        schema_version=SCHEMA_VERSION,
        source=SOURCE,
        validation_scope=SCOPE,
        implementation_profile=PROFILE,
        readiness_status=STATUS,
        adapter_path=ADAPTER_PATH,
        approved_step226_package_manifest_sha256=STEP226_PACKAGE_MANIFEST_SHA256,
        implementation_document_sha256=hashlib.sha256(canonical_document).hexdigest(),
        step226_receipt_sha256=hashlib.sha256(step226_rendered).hexdigest(),
        adapter_sha256=ADAPTER_SHA256,
        adapter_bytes=ADAPTER_BYTES,
        token_post_attempt_count=TOKEN_POST_ATTEMPTS,
        token_post_retry_count=TOKEN_POST_RETRIES,
        request_timeout_milliseconds=REQUEST_TIMEOUT_MILLISECONDS,
        maximum_response_bytes=MAXIMUM_RESPONSE_BYTES,
        **_profiles(),
        **true_values,
        **false_values,
    )


def _scrub(error: BaseException) -> tuple[bool, bool]:
    pending = [error]
    seen: set[int] = set()
    interrupted = False
    terminated = False
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        interrupted |= isinstance(current, KeyboardInterrupt)
        terminated |= isinstance(current, SystemExit)
        if isinstance(current, BaseExceptionGroup):
            pending.extend(current.exceptions)
        pending.extend(
            linked
            for linked in (current.__context__, current.__cause__)
            if isinstance(linked, BaseException)
        )
        try:
            current.args = ()
            current.__traceback__ = None
            current.__context__ = None
            current.__cause__ = None
        except BaseException:  # noqa: BLE001, S110
            pass
    return interrupted, terminated


def load_entra_calling_client_msal_zero_retry_network_client_implementation_readiness(
    document_bytes: object,
    step226_document_bytes: object,
    adapter_bytes: object,
) -> EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessReceipt:
    """Return one sanitized offline Step 227 source-readiness receipt."""

    result = None
    error = None
    invalid = False
    interrupted = False
    terminated = False
    try:
        result = _load_internal(document_bytes, step226_document_bytes, adapter_bytes)
    except _ArgumentTypeError as caught:
        error = caught
        invalid = True
    except BaseException as caught:  # noqa: BLE001
        error = caught
    finally:
        document_bytes = None
        step226_document_bytes = None
        adapter_bytes = None
        if error is not None:
            interrupted, terminated = _scrub(error)
        error = None
    if interrupted:
        raise KeyboardInterrupt("MSAL zero-retry implementation readiness interrupted")
    if terminated:
        raise SystemExit("MSAL zero-retry implementation readiness terminated")
    if invalid:
        raise TypeError("MSAL zero-retry implementation readiness input is invalid")
    if result is None:
        raise EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessError(
            "MSAL zero-retry implementation readiness validation failed"
        )
    return result


def render_entra_calling_client_msal_zero_retry_network_client_implementation_readiness_receipt(
    receipt: EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessReceipt,
) -> str:
    """Render canonical privacy-minimized Step 227 evidence."""

    if (
        type(receipt)
        is not EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessReceipt
    ):
        raise TypeError("exact zero-retry implementation-readiness receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {name: getattr(receipt, name) for name in receipt.__dataclass_fields__},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "ADAPTER_BYTES",
    "ADAPTER_PATH",
    "ADAPTER_SHA256",
    "DOCUMENT_TYPE",
    "PROFILE",
    "RECEIPT_TYPE",
    "SOURCE",
    "STATUS",
    "STEP226_PACKAGE_MANIFEST_SHA256",
    "EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessError",
    "EntraCallingClientMSALZeroRetryNetworkClientImplementationReadinessReceipt",
    "load_entra_calling_client_msal_zero_retry_network_client_implementation_readiness",
    "render_entra_calling_client_msal_zero_retry_network_client_implementation_readiness_receipt",
]

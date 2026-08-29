"""Offline compiled POST call-site and retry-exception decision readiness.

This module performs no filesystem, registry, process, browser, OAuth, DNS,
TLS, HTTP, Graph, Entra, npm, or other provider I/O. It binds the exact
MSAL Browser 5.18.0 and MSAL Common 16.12.0 compiled call-site review while
keeping the Step 216 zero-retry requirement and fail-closed selection state.
"""

from __future__ import annotations

import hashlib
import json
from builtins import BaseExceptionGroup
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import model_validator

from app.security.identity_models import SecurityModel

DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_msal_retry_exception_decision_readiness"
)
RECEIPT_TYPE = DOCUMENT_TYPE + "_receipt"
SCHEMA_VERSION = 1
SOURCE = "engineer4me_reviewed_msal_5_18_0_compiled_post_call_site_confinement"
SCOPE = "offline_compiled_post_call_site_confinement_and_retry_exception_decision"
PROFILE = "engineer4me_msal_5_18_0_retry_exception_decision_readiness_v1"
STATUS = "call_site_confinement_declared_but_retry_exception_remains_unapproved"

STEP223_PACKAGE_MANIFEST_SHA256 = (
    "3d810f2f3bcd294acaef2c4066b5fef20f95de2c053ad03cfe4f3bc6e5a485f1"
)
BROWSER_PACKAGE_NAME = "@azure/msal-browser"
BROWSER_VERSION = "5.18.0"
COMMON_PACKAGE_NAME = "@azure/msal-common"
COMMON_VERSION = "16.12.0"

FETCH_CLIENT_PATH = "package/dist/network/FetchClient.mjs"
FETCH_CLIENT_SHA256 = "abf75690801b45b64347873bb5483774aab1b70f1cf261021aa4e6b5181e9704"
FETCH_CLIENT_BYTES = 5_560
TOKEN_CALL_SITE_PATH = "package/dist/protocol/Token.mjs"
TOKEN_CALL_SITE_SHA256 = (
    "fbfdf312c1553f87e721fd444814fe81640774b0b0ffa71f607d31c158072b63"
)
TOKEN_CALL_SITE_BYTES = 6_019
CLIENT_CONFIGURATION_STUB_PATH = "package/dist/config/ClientConfiguration.mjs"
CLIENT_CONFIGURATION_STUB_SHA256 = (
    "ee30e9c1c7d4e3fe92c76eb35364f45ecb6f257c3f01c058e81c9748a28eba19"
)
CLIENT_CONFIGURATION_STUB_BYTES = 4_404
NETWORK_INTERFACE_PATH = "package/dist/network/INetworkModule.mjs"
NETWORK_INTERFACE_SHA256 = (
    "24f42ae4d9ebe378d695531822ff50806be7f5bba27359760b73ab6f4cf083e1"
)
NETWORK_INTERFACE_BYTES = 743

COMPILED_OCCURRENCE_FILE_COUNT = 4
COMPILED_REAL_INVOCATION_COUNT = 1
COMPILED_IMPLEMENTATION_COUNT = 1
COMPILED_STUB_COUNT = 1
COMPILED_INTERFACE_COUNT = 1
MAXIMUM_RETRY_COUNT = 1
MAXIMUM_ATTEMPT_COUNT = 2
BACKOFF_MILLISECONDS = 100
MAX_DOCUMENT_BYTES = 4_096
MAX_JSON_DEPTH = 16


class EntraCallingClientMSALRetryExceptionDecisionReadinessError(ValueError):
    """Sanitized Step 224 decision-readiness failure."""


class _ArgumentTypeError(TypeError):
    """Private marker for invalid public argument types."""


class EntraCallingClientMSALRetryExceptionDecisionReadinessDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_retry_exception_decision_readiness"
    ]
    schema_version: Literal[1]
    source: Literal[
        "engineer4me_reviewed_msal_5_18_0_compiled_post_call_site_confinement"
    ]
    approved_step223_package_manifest_sha256: str
    decision_profile: Literal[
        "engineer4me_msal_5_18_0_retry_exception_decision_readiness_v1"
    ]

    @model_validator(mode="after")
    def validate_manifest(
        self,
    ) -> EntraCallingClientMSALRetryExceptionDecisionReadinessDocument:
        if (
            self.approved_step223_package_manifest_sha256
            != STEP223_PACKAGE_MANIFEST_SHA256
        ):
            raise ValueError("approved Step 223 package manifest is not exact")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALRetryExceptionDecisionReadinessReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    decision_profile: str
    readiness_status: str
    browser_package_name: str
    browser_version: str
    common_package_name: str
    common_version: str
    fetch_client_path: str
    token_call_site_path: str
    client_configuration_stub_path: str
    network_interface_path: str
    approved_step223_package_manifest_sha256: str
    decision_document_sha256: str
    fetch_client_sha256: str
    token_call_site_sha256: str
    client_configuration_stub_sha256: str
    network_interface_sha256: str
    call_site_inventory_sha256: str
    confinement_finding_sha256: str
    response_loss_risk_sha256: str
    fail_closed_decision_sha256: str
    fetch_client_bytes: int
    token_call_site_bytes: int
    client_configuration_stub_bytes: int
    network_interface_bytes: int
    compiled_occurrence_file_count: int
    compiled_real_invocation_count: int
    compiled_implementation_count: int
    compiled_stub_count: int
    compiled_interface_count: int
    maximum_retry_count: int
    maximum_attempt_count: int
    backoff_milliseconds: int
    step223_package_manifest_digest_bound: bool
    exact_browser_and_common_versions_bound: bool
    exact_compiled_file_identities_bound: bool
    exact_distribution_occurrence_inventory_declared: bool
    one_real_compiled_invocation_declared: bool
    real_invocation_uses_token_endpoint_parameter_declared: bool
    implementation_remains_url_agnostic: bool
    standard_public_client_call_site_confinement_declared: bool
    step216_zero_retry_requirement_preserved: bool
    lost_response_code_consumption_ambiguity_preserved: bool
    explicit_risk_decision_required: bool
    offline_decision_readiness_validated: bool
    step223_rendered_receipt_accepted_as_provenance: bool
    artifact_bytes_loaded_or_scanned: bool
    registry_or_network_io_performed: bool
    browser_or_node_execution_performed: bool
    real_oauth_values_processed: bool
    application_integration_import_graph_checked: bool
    application_network_client_override_checked: bool
    source_to_distribution_reproducibility_checked: bool
    package_advisories_checked: bool
    registry_freshness_checked: bool
    retry_exception_approved: bool
    library_compatibility_approved: bool
    package_selection_approved: bool
    dependency_installed_or_locked: bool
    application_configuration_mutation_performed: bool
    application_activation_performed: bool
    runtime_pkce_or_token_exchange_executed: bool

    def __post_init__(self) -> None:
        constants: dict[str, object] = {
            "receipt_type": RECEIPT_TYPE,
            "schema_version": SCHEMA_VERSION,
            "source": SOURCE,
            "validation_scope": SCOPE,
            "decision_profile": PROFILE,
            "readiness_status": STATUS,
            "browser_package_name": BROWSER_PACKAGE_NAME,
            "browser_version": BROWSER_VERSION,
            "common_package_name": COMMON_PACKAGE_NAME,
            "common_version": COMMON_VERSION,
            "fetch_client_path": FETCH_CLIENT_PATH,
            "token_call_site_path": TOKEN_CALL_SITE_PATH,
            "client_configuration_stub_path": CLIENT_CONFIGURATION_STUB_PATH,
            "network_interface_path": NETWORK_INTERFACE_PATH,
            "approved_step223_package_manifest_sha256": STEP223_PACKAGE_MANIFEST_SHA256,
            "fetch_client_sha256": FETCH_CLIENT_SHA256,
            "token_call_site_sha256": TOKEN_CALL_SITE_SHA256,
            "client_configuration_stub_sha256": CLIENT_CONFIGURATION_STUB_SHA256,
            "network_interface_sha256": NETWORK_INTERFACE_SHA256,
            "fetch_client_bytes": FETCH_CLIENT_BYTES,
            "token_call_site_bytes": TOKEN_CALL_SITE_BYTES,
            "client_configuration_stub_bytes": CLIENT_CONFIGURATION_STUB_BYTES,
            "network_interface_bytes": NETWORK_INTERFACE_BYTES,
            "compiled_occurrence_file_count": COMPILED_OCCURRENCE_FILE_COUNT,
            "compiled_real_invocation_count": COMPILED_REAL_INVOCATION_COUNT,
            "compiled_implementation_count": COMPILED_IMPLEMENTATION_COUNT,
            "compiled_stub_count": COMPILED_STUB_COUNT,
            "compiled_interface_count": COMPILED_INTERFACE_COUNT,
            "maximum_retry_count": MAXIMUM_RETRY_COUNT,
            "maximum_attempt_count": MAXIMUM_ATTEMPT_COUNT,
            "backoff_milliseconds": BACKOFF_MILLISECONDS,
        }
        for name, expected in constants.items():
            actual = getattr(self, name)
            if type(actual) is not type(expected) or actual != expected:
                raise ValueError("retry decision readiness receipt constant is invalid")

        digest_names = (
            "decision_document_sha256",
            "call_site_inventory_sha256",
            "confinement_finding_sha256",
            "response_loss_risk_sha256",
            "fail_closed_decision_sha256",
        )
        if any(not _is_sha256(getattr(self, name)) for name in digest_names):
            raise ValueError("retry decision readiness digest is invalid")

        true_names = (
            "step223_package_manifest_digest_bound",
            "exact_browser_and_common_versions_bound",
            "exact_compiled_file_identities_bound",
            "exact_distribution_occurrence_inventory_declared",
            "one_real_compiled_invocation_declared",
            "real_invocation_uses_token_endpoint_parameter_declared",
            "implementation_remains_url_agnostic",
            "standard_public_client_call_site_confinement_declared",
            "step216_zero_retry_requirement_preserved",
            "lost_response_code_consumption_ambiguity_preserved",
            "explicit_risk_decision_required",
            "offline_decision_readiness_validated",
        )
        false_names = (
            "step223_rendered_receipt_accepted_as_provenance",
            "artifact_bytes_loaded_or_scanned",
            "registry_or_network_io_performed",
            "browser_or_node_execution_performed",
            "real_oauth_values_processed",
            "application_integration_import_graph_checked",
            "application_network_client_override_checked",
            "source_to_distribution_reproducibility_checked",
            "package_advisories_checked",
            "registry_freshness_checked",
            "retry_exception_approved",
            "library_compatibility_approved",
            "package_selection_approved",
            "dependency_installed_or_locked",
            "application_configuration_mutation_performed",
            "application_activation_performed",
            "runtime_pkce_or_token_exchange_executed",
        )
        for name in true_names:
            if type(getattr(self, name)) is not bool or not getattr(self, name):
                raise ValueError("required retry decision readiness fact is false")
        for name in false_names:
            if type(getattr(self, name)) is not bool or getattr(self, name):
                raise ValueError("deferred retry decision readiness fact is true")


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


def _depth(value: Any, current: int = 1) -> int:
    if current > MAX_JSON_DEPTH:
        raise ValueError("JSON nesting is excessive")
    if isinstance(value, dict):
        for child in value.values():
            _depth(child, current + 1)
    elif isinstance(value, list):
        for child in value:
            _depth(child, current + 1)
    return current


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _framed(domain: str, value: object) -> str:
    payload = _canonical(value)
    frame = b"Engineer4Me-Step224-v1\x00" + domain.encode("ascii") + b"\x00" + payload
    return hashlib.sha256(frame).hexdigest()


def _scrub(error: BaseException) -> tuple[bool, bool]:
    interrupted = False
    terminated = False
    stack = [error]
    seen: set[int] = set()
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        interrupted = interrupted or isinstance(current, KeyboardInterrupt)
        terminated = terminated or isinstance(current, SystemExit)
        cause = current.__cause__
        context = current.__context__
        children = (
            list(current.exceptions) if isinstance(current, BaseExceptionGroup) else []
        )
        if cause is not None:
            stack.append(cause)
        if context is not None:
            stack.append(context)
        stack.extend(children)
        try:
            current.args = ()
        except BaseException:  # noqa: BLE001, S110
            pass
        current.__cause__ = None
        current.__context__ = None
        current.__traceback__ = None
    return interrupted, terminated


def _load_internal(
    document_bytes: object,
) -> EntraCallingClientMSALRetryExceptionDecisionReadinessReceipt:
    if type(document_bytes) is not bytes:
        raise _ArgumentTypeError("document must be exact bytes")
    if not document_bytes or len(document_bytes) > MAX_DOCUMENT_BYTES:
        raise ValueError("document size is invalid")
    try:
        text = document_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("document encoding is invalid") from None
    try:
        raw = json.loads(text, object_pairs_hook=_pairs)
    except (json.JSONDecodeError, ValueError):
        raise ValueError("document JSON is invalid") from None
    _depth(raw)
    document = (
        EntraCallingClientMSALRetryExceptionDecisionReadinessDocument.model_validate(
            raw
        )
    )
    canonical_document = _canonical(document.model_dump(mode="json"))
    inventory = [
        [
            BROWSER_PACKAGE_NAME,
            BROWSER_VERSION,
            FETCH_CLIENT_PATH,
            FETCH_CLIENT_SHA256,
            FETCH_CLIENT_BYTES,
            "implementation",
        ],
        [
            COMMON_PACKAGE_NAME,
            COMMON_VERSION,
            TOKEN_CALL_SITE_PATH,
            TOKEN_CALL_SITE_SHA256,
            TOKEN_CALL_SITE_BYTES,
            "real_token_endpoint_invocation",
        ],
        [
            COMMON_PACKAGE_NAME,
            COMMON_VERSION,
            CLIENT_CONFIGURATION_STUB_PATH,
            CLIENT_CONFIGURATION_STUB_SHA256,
            CLIENT_CONFIGURATION_STUB_BYTES,
            "stub",
        ],
        [
            COMMON_PACKAGE_NAME,
            COMMON_VERSION,
            NETWORK_INTERFACE_PATH,
            NETWORK_INTERFACE_SHA256,
            NETWORK_INTERFACE_BYTES,
            "interface",
        ],
    ]
    confinement = {
        "real_invocation_count": 1,
        "real_invocation_argument": "tokenEndpoint",
        "method_url_guard": False,
        "standard_public_client_call_site_scope": "token_protocol",
    }
    risk = {
        "first_response_may_be_lost": True,
        "authorization_code_may_have_been_consumed": True,
        "retry_may_return_invalid_grant": True,
        "successful_recovery_guaranteed": False,
    }
    decision = {
        "step216_zero_retry_authoritative": True,
        "exception_approved": False,
        "compatibility_approved": False,
        "selection_approved": False,
        "live_artifact_call_graph_scan_required": True,
        "application_import_and_override_review_required": True,
    }
    true_values = {
        "step223_package_manifest_digest_bound": True,
        "exact_browser_and_common_versions_bound": True,
        "exact_compiled_file_identities_bound": True,
        "exact_distribution_occurrence_inventory_declared": True,
        "one_real_compiled_invocation_declared": True,
        "real_invocation_uses_token_endpoint_parameter_declared": True,
        "implementation_remains_url_agnostic": True,
        "standard_public_client_call_site_confinement_declared": True,
        "step216_zero_retry_requirement_preserved": True,
        "lost_response_code_consumption_ambiguity_preserved": True,
        "explicit_risk_decision_required": True,
        "offline_decision_readiness_validated": True,
    }
    false_values = {
        "step223_rendered_receipt_accepted_as_provenance": False,
        "artifact_bytes_loaded_or_scanned": False,
        "registry_or_network_io_performed": False,
        "browser_or_node_execution_performed": False,
        "real_oauth_values_processed": False,
        "application_integration_import_graph_checked": False,
        "application_network_client_override_checked": False,
        "source_to_distribution_reproducibility_checked": False,
        "package_advisories_checked": False,
        "registry_freshness_checked": False,
        "retry_exception_approved": False,
        "library_compatibility_approved": False,
        "package_selection_approved": False,
        "dependency_installed_or_locked": False,
        "application_configuration_mutation_performed": False,
        "application_activation_performed": False,
        "runtime_pkce_or_token_exchange_executed": False,
    }
    return EntraCallingClientMSALRetryExceptionDecisionReadinessReceipt(
        receipt_type=RECEIPT_TYPE,
        schema_version=SCHEMA_VERSION,
        source=SOURCE,
        validation_scope=SCOPE,
        decision_profile=PROFILE,
        readiness_status=STATUS,
        browser_package_name=BROWSER_PACKAGE_NAME,
        browser_version=BROWSER_VERSION,
        common_package_name=COMMON_PACKAGE_NAME,
        common_version=COMMON_VERSION,
        fetch_client_path=FETCH_CLIENT_PATH,
        token_call_site_path=TOKEN_CALL_SITE_PATH,
        client_configuration_stub_path=CLIENT_CONFIGURATION_STUB_PATH,
        network_interface_path=NETWORK_INTERFACE_PATH,
        approved_step223_package_manifest_sha256=STEP223_PACKAGE_MANIFEST_SHA256,
        decision_document_sha256=hashlib.sha256(canonical_document).hexdigest(),
        fetch_client_sha256=FETCH_CLIENT_SHA256,
        token_call_site_sha256=TOKEN_CALL_SITE_SHA256,
        client_configuration_stub_sha256=CLIENT_CONFIGURATION_STUB_SHA256,
        network_interface_sha256=NETWORK_INTERFACE_SHA256,
        call_site_inventory_sha256=_framed("call-sites", inventory),
        confinement_finding_sha256=_framed("confinement", confinement),
        response_loss_risk_sha256=_framed("risk", risk),
        fail_closed_decision_sha256=_framed("decision", decision),
        fetch_client_bytes=FETCH_CLIENT_BYTES,
        token_call_site_bytes=TOKEN_CALL_SITE_BYTES,
        client_configuration_stub_bytes=CLIENT_CONFIGURATION_STUB_BYTES,
        network_interface_bytes=NETWORK_INTERFACE_BYTES,
        compiled_occurrence_file_count=COMPILED_OCCURRENCE_FILE_COUNT,
        compiled_real_invocation_count=COMPILED_REAL_INVOCATION_COUNT,
        compiled_implementation_count=COMPILED_IMPLEMENTATION_COUNT,
        compiled_stub_count=COMPILED_STUB_COUNT,
        compiled_interface_count=COMPILED_INTERFACE_COUNT,
        maximum_retry_count=MAXIMUM_RETRY_COUNT,
        maximum_attempt_count=MAXIMUM_ATTEMPT_COUNT,
        backoff_milliseconds=BACKOFF_MILLISECONDS,
        **true_values,
        **false_values,
    )


def load_entra_calling_client_msal_retry_exception_decision_readiness(
    document_bytes: object,
) -> EntraCallingClientMSALRetryExceptionDecisionReadinessReceipt:
    """Validate one exact offline Step 224 decision-readiness document."""

    result = None
    error = None
    invalid = False
    interrupted = False
    terminated = False
    try:
        result = _load_internal(document_bytes)
    except _ArgumentTypeError as caught:
        error = caught
        invalid = True
    except BaseException as caught:  # noqa: BLE001
        error = caught
    finally:
        document_bytes = None
        if error is not None:
            interrupted, terminated = _scrub(error)
        error = None
    if interrupted:
        raise KeyboardInterrupt("MSAL retry decision readiness interrupted")
    if terminated:
        raise SystemExit("MSAL retry decision readiness terminated")
    if invalid:
        raise TypeError("MSAL retry decision readiness input is invalid")
    if result is None:
        raise EntraCallingClientMSALRetryExceptionDecisionReadinessError(
            "MSAL retry decision readiness validation failed"
        )
    return result


def render_entra_calling_client_msal_retry_exception_decision_readiness_receipt(
    receipt: EntraCallingClientMSALRetryExceptionDecisionReadinessReceipt,
) -> str:
    """Render canonical privacy-minimized Step 224 evidence."""

    if (
        type(receipt)
        is not EntraCallingClientMSALRetryExceptionDecisionReadinessReceipt
    ):
        raise TypeError("exact MSAL retry decision readiness receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {name: getattr(receipt, name) for name in receipt.__dataclass_fields__},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "BACKOFF_MILLISECONDS",
    "BROWSER_PACKAGE_NAME",
    "BROWSER_VERSION",
    "CLIENT_CONFIGURATION_STUB_PATH",
    "CLIENT_CONFIGURATION_STUB_SHA256",
    "COMMON_PACKAGE_NAME",
    "COMMON_VERSION",
    "DOCUMENT_TYPE",
    "FETCH_CLIENT_PATH",
    "FETCH_CLIENT_SHA256",
    "MAXIMUM_ATTEMPT_COUNT",
    "MAXIMUM_RETRY_COUNT",
    "NETWORK_INTERFACE_PATH",
    "NETWORK_INTERFACE_SHA256",
    "PROFILE",
    "RECEIPT_TYPE",
    "SOURCE",
    "STATUS",
    "STEP223_PACKAGE_MANIFEST_SHA256",
    "TOKEN_CALL_SITE_PATH",
    "TOKEN_CALL_SITE_SHA256",
    "EntraCallingClientMSALRetryExceptionDecisionReadinessError",
    "EntraCallingClientMSALRetryExceptionDecisionReadinessReceipt",
    "load_entra_calling_client_msal_retry_exception_decision_readiness",
    "render_entra_calling_client_msal_retry_exception_decision_readiness_receipt",
]

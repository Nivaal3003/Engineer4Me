"""Offline MSAL Browser zero-retry network-client override readiness.

This contract performs no filesystem, package, browser, OAuth, DNS, TLS, HTTP,
Graph, Entra, npm, or other provider I/O. It binds a fail-closed design for an
Engineer4Me-owned `system.networkClient` that makes one token POST attempt.
"""

from __future__ import annotations

import hashlib
import json
from builtins import BaseExceptionGroup
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import model_validator

from app.security.identity_models import SecurityModel

DOCUMENT_TYPE = "engineer4me_microsoft_entra_calling_client_msal_zero_retry_network_client_readiness"
RECEIPT_TYPE = DOCUMENT_TYPE + "_receipt"
SCHEMA_VERSION = 1
SOURCE = "engineer4me_reviewed_msal_5_18_0_system_network_client_override"
SCOPE = "offline_exact_token_endpoint_zero_retry_network_client_override_plan"
PROFILE = "engineer4me_msal_browser_5_18_0_zero_retry_network_client_v1"
STATUS = "override_plan_bound_but_not_implemented_executed_or_selected"
STEP225_PACKAGE_MANIFEST_SHA256 = (
    "a60cd0564fa94abbb7f5fffecd1cd53c980044d2a57ba7eaf5ac9fadbb6d9ea1"
)

BROWSER_PACKAGE_NAME = "@azure/msal-browser"
BROWSER_VERSION = "5.18.0"
COMMON_PACKAGE_NAME = "@azure/msal-common"
COMMON_VERSION = "16.12.0"
CONFIGURATION_PATH = "package/dist/config/Configuration.mjs"
CONFIGURATION_SHA256 = (
    "896222cbb1d12b93afe9852548170e892eb0983c8f93e626f571335de9638b2e"
)
CONFIGURATION_BYTES = 5_877
FETCH_CLIENT_PATH = "package/dist/network/FetchClient.mjs"
FETCH_CLIENT_SHA256 = "abf75690801b45b64347873bb5483774aab1b70f1cf261021aa4e6b5181e9704"

NETWORK_CLIENT_CONFIGURATION_KEY = "system.networkClient"
GET_METHOD_NAME = "sendGetRequestAsync"
POST_METHOD_NAME = "sendPostRequestAsync"
TOKEN_POST_ATTEMPT_COUNT = 1
TOKEN_POST_RETRY_COUNT = 0
REQUEST_TIMEOUT_MILLISECONDS = 10_000
MAX_RESPONSE_BYTES = 1_048_576
FETCH_MODE = "cors"
FETCH_CREDENTIALS = "omit"
FETCH_REDIRECT = "error"
FETCH_CACHE = "no-store"
FETCH_REFERRER_POLICY = "no-referrer"
MAX_DOCUMENT_BYTES = 4_096


class EntraCallingClientMSALZeroRetryNetworkClientReadinessError(ValueError):
    """Sanitized Step 226 readiness failure."""


class _ArgumentTypeError(TypeError):
    """Private marker for invalid public inputs."""


class EntraCallingClientMSALZeroRetryNetworkClientReadinessDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_zero_retry_network_client_readiness"
    ]
    schema_version: Literal[1]
    source: Literal["engineer4me_reviewed_msal_5_18_0_system_network_client_override"]
    approved_step225_package_manifest_sha256: str
    override_profile: Literal[
        "engineer4me_msal_browser_5_18_0_zero_retry_network_client_v1"
    ]

    @model_validator(mode="before")
    @classmethod
    def validate_exact_wire_types(cls, value: object) -> object:
        if type(value) is not dict:
            raise ValueError("readiness document must be an exact object")
        expected = {
            "document_type": str,
            "schema_version": int,
            "source": str,
            "approved_step225_package_manifest_sha256": str,
            "override_profile": str,
        }
        if set(value) != set(expected):
            raise ValueError("readiness document keys are not exact")
        for name, expected_type in expected.items():
            if type(value[name]) is not expected_type:
                raise ValueError("readiness document field type is not exact")
        return value

    @model_validator(mode="after")
    def validate_manifest(
        self,
    ) -> EntraCallingClientMSALZeroRetryNetworkClientReadinessDocument:
        if (
            self.approved_step225_package_manifest_sha256
            != STEP225_PACKAGE_MANIFEST_SHA256
        ):
            raise ValueError("approved Step 225 package manifest is not exact")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALZeroRetryNetworkClientReadinessReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    override_profile: str
    readiness_status: str
    browser_package_name: str
    browser_version: str
    common_package_name: str
    common_version: str
    network_client_configuration_key: str
    get_method_name: str
    post_method_name: str
    configuration_path: str
    fetch_client_path: str
    fetch_mode: str
    fetch_credentials: str
    fetch_redirect: str
    fetch_cache: str
    fetch_referrer_policy: str
    approved_step225_package_manifest_sha256: str
    readiness_document_sha256: str
    configuration_sha256: str
    fetch_client_sha256: str
    override_interface_profile_sha256: str
    token_post_policy_sha256: str
    fetch_security_profile_sha256: str
    response_projection_profile_sha256: str
    failure_handling_profile_sha256: str
    successor_implementation_gate_sha256: str
    configuration_bytes: int
    token_post_attempt_count: int
    token_post_retry_count: int
    request_timeout_milliseconds: int
    maximum_response_bytes: int
    step225_package_manifest_digest_bound: bool
    exact_msal_browser_and_common_versions_bound: bool
    exact_configuration_and_fetch_client_identities_bound: bool
    system_network_client_override_supported_declared: bool
    exact_get_and_post_interface_required: bool
    exact_token_endpoint_post_target_required: bool
    exactly_one_token_post_attempt_required: bool
    zero_token_post_retries_required: bool
    retry_loop_timer_and_recursion_forbidden: bool
    request_body_reuse_or_replay_forbidden: bool
    credentials_omit_required: bool
    cors_mode_required: bool
    redirects_rejected_required: bool
    browser_cache_bypass_required: bool
    no_referrer_required: bool
    abort_controller_timeout_required: bool
    timeout_abort_must_not_retry: bool
    bounded_response_required: bool
    response_status_headers_and_json_projection_required: bool
    authorization_cookie_and_proxy_headers_forbidden: bool
    sensitive_body_or_token_logging_forbidden: bool
    normalized_sanitized_error_required: bool
    step216_zero_retry_requirement_satisfied_by_plan: bool
    step225_retry_rejection_preserved: bool
    no_version_downgrade_required: bool
    offline_override_readiness_validated: bool
    step225_rendered_receipt_accepted_as_provenance: bool
    compiled_configuration_rescanned: bool
    adapter_source_implemented: bool
    adapter_compiled: bool
    adapter_behavior_executed: bool
    browser_fetch_behavior_checked: bool
    exact_token_endpoint_cors_checked: bool
    dns_tls_http_checked: bool
    real_oauth_values_processed: bool
    runtime_pkce_or_token_exchange_executed: bool
    library_compatibility_approved: bool
    package_selection_approved: bool
    dependency_installed_or_locked: bool
    frontend_framework_selected: bool
    application_configuration_mutation_performed: bool
    application_activation_performed: bool

    def __post_init__(self) -> None:
        constants: dict[str, object] = {
            "receipt_type": RECEIPT_TYPE,
            "schema_version": SCHEMA_VERSION,
            "source": SOURCE,
            "validation_scope": SCOPE,
            "override_profile": PROFILE,
            "readiness_status": STATUS,
            "browser_package_name": BROWSER_PACKAGE_NAME,
            "browser_version": BROWSER_VERSION,
            "common_package_name": COMMON_PACKAGE_NAME,
            "common_version": COMMON_VERSION,
            "network_client_configuration_key": NETWORK_CLIENT_CONFIGURATION_KEY,
            "get_method_name": GET_METHOD_NAME,
            "post_method_name": POST_METHOD_NAME,
            "configuration_path": CONFIGURATION_PATH,
            "fetch_client_path": FETCH_CLIENT_PATH,
            "fetch_mode": FETCH_MODE,
            "fetch_credentials": FETCH_CREDENTIALS,
            "fetch_redirect": FETCH_REDIRECT,
            "fetch_cache": FETCH_CACHE,
            "fetch_referrer_policy": FETCH_REFERRER_POLICY,
            "approved_step225_package_manifest_sha256": STEP225_PACKAGE_MANIFEST_SHA256,
            "configuration_sha256": CONFIGURATION_SHA256,
            "fetch_client_sha256": FETCH_CLIENT_SHA256,
            "configuration_bytes": CONFIGURATION_BYTES,
            "token_post_attempt_count": TOKEN_POST_ATTEMPT_COUNT,
            "token_post_retry_count": TOKEN_POST_RETRY_COUNT,
            "request_timeout_milliseconds": REQUEST_TIMEOUT_MILLISECONDS,
            "maximum_response_bytes": MAX_RESPONSE_BYTES,
        }
        for name, expected in constants.items():
            actual = getattr(self, name)
            if type(actual) is not type(expected) or actual != expected:
                raise ValueError("zero-retry network-client constant is invalid")
        for name in ("readiness_document_sha256",):
            if not _is_sha256(getattr(self, name)):
                raise ValueError("zero-retry network-client digest is invalid")
        profile_digests = {
            "override_interface_profile_sha256": (
                "00394d7383637f8dc7b9a6d8f3b8d4bbe752ffcf5980e0c64dc35bfea926b91b"
            ),
            "token_post_policy_sha256": (
                "1cf49280aebfe94384deafb149024151affed2d08cbdce3e7b06bae417346d99"
            ),
            "fetch_security_profile_sha256": (
                "ed4f26bcf984dd5c316aa4930bd2ed2981d3266cc189921fe4d97c19e5fd09b3"
            ),
            "response_projection_profile_sha256": (
                "fe905b05dda2887eec03baed271c4f16ecbcad9e3d05b581c8184f39af790a15"
            ),
            "failure_handling_profile_sha256": (
                "3249072aa4b0ca9355c82bc5b08b7014817fab7f889a448f85d73be393340542"
            ),
            "successor_implementation_gate_sha256": (
                "293acd3d3981fd4ab7cf4940a89dde7c205ba71f0322455fb876c2e89799b9af"
            ),
        }
        for name, expected in profile_digests.items():
            if type(getattr(self, name)) is not str or getattr(self, name) != expected:
                raise ValueError("zero-retry network-client profile digest is invalid")
        true_names = (
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
        )
        false_names = (
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
        )
        for name in true_names:
            if type(getattr(self, name)) is not bool or not getattr(self, name):
                raise ValueError("required zero-retry readiness fact is false")
        for name in false_names:
            if type(getattr(self, name)) is not bool or getattr(self, name):
                raise ValueError("deferred zero-retry readiness fact is true")


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
        b"Engineer4Me-Step226-v1\x00" + domain.encode() + b"\x00" + _canonical(value)
    ).hexdigest()


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


def _load_internal(
    document_bytes: object,
) -> EntraCallingClientMSALZeroRetryNetworkClientReadinessReceipt:
    if type(document_bytes) is not bytes:
        raise _ArgumentTypeError("exact readiness document bytes are required")
    if not document_bytes or len(document_bytes) > MAX_DOCUMENT_BYTES:
        raise ValueError("readiness document size is invalid")
    try:
        text = document_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("readiness document encoding is invalid") from None
    try:
        raw = json.loads(text, object_pairs_hook=_pairs)
    except (json.JSONDecodeError, ValueError):
        raise ValueError("readiness document JSON is invalid") from None
    document = (
        EntraCallingClientMSALZeroRetryNetworkClientReadinessDocument.model_validate(
            raw
        )
    )
    canonical_document = _canonical(document.model_dump(mode="json"))
    interface = {
        "configuration_key": NETWORK_CLIENT_CONFIGURATION_KEY,
        "methods": [GET_METHOD_NAME, POST_METHOD_NAME],
        "response": ["headers", "body", "status"],
    }
    post_policy = {
        "target": "exact_step216_derived_token_endpoint",
        "attempts": 1,
        "retries": 0,
        "loops": False,
        "recursive_calls": False,
        "backoff_timers": False,
        "body_replay": False,
    }
    fetch_security = {
        "mode": FETCH_MODE,
        "credentials": FETCH_CREDENTIALS,
        "redirect": FETCH_REDIRECT,
        "cache": FETCH_CACHE,
        "referrerPolicy": FETCH_REFERRER_POLICY,
        "timeout_ms": REQUEST_TIMEOUT_MILLISECONDS,
        "forbidden_headers": [
            "authorization",
            "connection",
            "content-length",
            "cookie",
            "host",
            "proxy-authorization",
            "transfer-encoding",
        ],
    }
    response = {
        "maximum_bytes": MAX_RESPONSE_BYTES,
        "json_once": True,
        "status": True,
        "normalized_headers": True,
        "token_logging": False,
    }
    failures = {
        "transport": "sanitized_once_no_retry",
        "abort": "sanitized_no_retry",
        "timeout": "abort_then_sanitized_no_retry",
        "http": "return_response_no_retry",
        "json": "sanitized_no_retry",
        "oauth": "return_response_no_retry",
    }
    successor = {
        "typescript_source_required": True,
        "compiled_identity_required": True,
        "sealed_fake_fetch_matrix_required": True,
        "browser_integration_required": True,
        "exact_token_endpoint_required": True,
        "package_selection_approved": False,
    }
    true_values = {
        name: True
        for name in (
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
        )
    }
    false_values = {
        name: False
        for name in (
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
        )
    }
    return EntraCallingClientMSALZeroRetryNetworkClientReadinessReceipt(
        receipt_type=RECEIPT_TYPE,
        schema_version=SCHEMA_VERSION,
        source=SOURCE,
        validation_scope=SCOPE,
        override_profile=PROFILE,
        readiness_status=STATUS,
        browser_package_name=BROWSER_PACKAGE_NAME,
        browser_version=BROWSER_VERSION,
        common_package_name=COMMON_PACKAGE_NAME,
        common_version=COMMON_VERSION,
        network_client_configuration_key=NETWORK_CLIENT_CONFIGURATION_KEY,
        get_method_name=GET_METHOD_NAME,
        post_method_name=POST_METHOD_NAME,
        configuration_path=CONFIGURATION_PATH,
        fetch_client_path=FETCH_CLIENT_PATH,
        fetch_mode=FETCH_MODE,
        fetch_credentials=FETCH_CREDENTIALS,
        fetch_redirect=FETCH_REDIRECT,
        fetch_cache=FETCH_CACHE,
        fetch_referrer_policy=FETCH_REFERRER_POLICY,
        approved_step225_package_manifest_sha256=STEP225_PACKAGE_MANIFEST_SHA256,
        readiness_document_sha256=hashlib.sha256(canonical_document).hexdigest(),
        configuration_sha256=CONFIGURATION_SHA256,
        fetch_client_sha256=FETCH_CLIENT_SHA256,
        override_interface_profile_sha256=_framed("interface", interface),
        token_post_policy_sha256=_framed("token-post", post_policy),
        fetch_security_profile_sha256=_framed("fetch", fetch_security),
        response_projection_profile_sha256=_framed("response", response),
        failure_handling_profile_sha256=_framed("failures", failures),
        successor_implementation_gate_sha256=_framed("successor", successor),
        configuration_bytes=CONFIGURATION_BYTES,
        token_post_attempt_count=TOKEN_POST_ATTEMPT_COUNT,
        token_post_retry_count=TOKEN_POST_RETRY_COUNT,
        request_timeout_milliseconds=REQUEST_TIMEOUT_MILLISECONDS,
        maximum_response_bytes=MAX_RESPONSE_BYTES,
        **true_values,
        **false_values,
    )


def load_entra_calling_client_msal_zero_retry_network_client_readiness(
    document_bytes: object,
) -> EntraCallingClientMSALZeroRetryNetworkClientReadinessReceipt:
    """Return one sanitized offline Step 226 readiness receipt."""

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
        raise KeyboardInterrupt("MSAL zero-retry readiness interrupted")
    if terminated:
        raise SystemExit("MSAL zero-retry readiness terminated")
    if invalid:
        raise TypeError("MSAL zero-retry readiness input is invalid")
    if result is None:
        raise EntraCallingClientMSALZeroRetryNetworkClientReadinessError(
            "MSAL zero-retry network-client readiness validation failed"
        )
    return result


def render_entra_calling_client_msal_zero_retry_network_client_readiness_receipt(
    receipt: EntraCallingClientMSALZeroRetryNetworkClientReadinessReceipt,
) -> str:
    """Render canonical privacy-minimized Step 226 evidence."""

    if (
        type(receipt)
        is not EntraCallingClientMSALZeroRetryNetworkClientReadinessReceipt
    ):
        raise TypeError("exact MSAL zero-retry readiness receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {name: getattr(receipt, name) for name in receipt.__dataclass_fields__},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "BROWSER_PACKAGE_NAME",
    "BROWSER_VERSION",
    "CONFIGURATION_PATH",
    "CONFIGURATION_SHA256",
    "DOCUMENT_TYPE",
    "FETCH_CLIENT_PATH",
    "FETCH_CLIENT_SHA256",
    "NETWORK_CLIENT_CONFIGURATION_KEY",
    "PROFILE",
    "RECEIPT_TYPE",
    "SOURCE",
    "STATUS",
    "STEP225_PACKAGE_MANIFEST_SHA256",
    "EntraCallingClientMSALZeroRetryNetworkClientReadinessError",
    "EntraCallingClientMSALZeroRetryNetworkClientReadinessReceipt",
    "load_entra_calling_client_msal_zero_retry_network_client_readiness",
    "render_entra_calling_client_msal_zero_retry_network_client_readiness_receipt",
]

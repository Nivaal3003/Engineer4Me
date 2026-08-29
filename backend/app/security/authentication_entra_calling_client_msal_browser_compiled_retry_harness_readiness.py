"""Offline sealed-harness and compiled retry scope-review readiness.

No registry, filesystem, process, Node, browser, OAuth, or provider I/O is
performed. The exact Step 221 source chain and caller-supplied frozen harness
bytes are validated before a privacy-minimized, fail-closed receipt is emitted.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import model_validator

from app.security.authentication_entra_calling_client_msal_browser_compiled_retry_execution_readiness import (
    BROWSER_TARBALL_SHA256,
    COMMON_TARBALL_SHA256,
    COMPILED_RETRY_ENTRY_SHA256,
    EntraCallingClientMSALCompiledRetryExecutionReadinessReceipt,
    load_entra_calling_client_msal_compiled_retry_execution_readiness,
    render_entra_calling_client_msal_compiled_retry_execution_readiness_receipt,
)
from app.security.authentication_entra_calling_client_msal_browser_compiled_retry_execution_readiness import (
    READINESS_STATUS as STEP221_READINESS_STATUS,
)
from app.security.identity_models import SecurityModel

DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_msal_compiled_retry_harness_readiness"
)
RECEIPT_TYPE = DOCUMENT_TYPE + "_receipt"
SOURCE = "engineer4me_reviewed_msal_browser_5_18_0_compiled_retry_scope_and_harness"
PROFILE = "engineer4me_msal_browser_5_18_0_sealed_retry_harness_v1"
SCOPE = "offline_exact_harness_and_compiled_retry_scope_review"
STATUS = "harness_bound_and_non_token_retry_scope_conflict_recorded_execution_unchecked"
SCHEMA_VERSION = 1
HARNESS_FILE_NAME = (
    "authentication_entra_calling_client_msal_browser_compiled_retry_harness.mjs"
)
HARNESS_SHA256 = "ac59e5dbad5c6cccf4933601c639a23b7db3d98612727a2bbc008b4c9a85fa6e"
HARNESS_BYTES = 4_886
HARNESS_SCENARIO_COUNT = 10
REVIEWED_NON_TOKEN_POST_ATTEMPTS = 2
MAX_DOCUMENT_BYTES = 4_096


class EntraCallingClientMSALCompiledRetryHarnessReadinessError(ValueError):
    """Sanitized Step 222 readiness failure."""


class _ArgumentTypeError(TypeError):
    """Private marker for public input misuse."""


class EntraCallingClientMSALCompiledRetryHarnessReadinessDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_compiled_retry_harness_readiness"
    ]
    schema_version: Literal[1]
    source: Literal[
        "engineer4me_reviewed_msal_browser_5_18_0_compiled_retry_scope_and_harness"
    ]
    approved_compiled_retry_execution_readiness_document_sha256: str
    harness_profile: Literal["engineer4me_msal_browser_5_18_0_sealed_retry_harness_v1"]

    @model_validator(mode="after")
    def validate_digest(
        self,
    ) -> EntraCallingClientMSALCompiledRetryHarnessReadinessDocument:
        if not _is_sha256(
            self.approved_compiled_retry_execution_readiness_document_sha256
        ):
            raise ValueError("approved digest must be lowercase SHA-256")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALCompiledRetryHarnessReadinessReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    harness_profile: str
    readiness_status: str
    harness_file_name: str
    compiled_scope_finding: str
    configuration_sha256: str
    api_registration_document_sha256: str
    calling_client_registration_document_sha256: str
    inventory_document_sha256: str
    compiled_retry_execution_readiness_document_sha256: str
    compiled_retry_execution_readiness_receipt_sha256: str
    harness_readiness_document_sha256: str
    harness_sha256: str
    browser_tarball_sha256: str
    common_tarball_sha256: str
    compiled_retry_entry_sha256: str
    harness_execution_plan_sha256: str
    reviewed_scope_conflict_sha256: str
    selection_state_sha256: str
    harness_bytes: int
    harness_scenario_count: int
    reviewed_non_token_post_attempts: int
    step221_source_chain_revalidated: bool
    approved_step221_document_digest_bound: bool
    exact_step221_fail_closed_state_validated: bool
    exact_harness_bytes_bound: bool
    exact_harness_sha256_bound: bool
    exact_ten_scenario_matrix_bound: bool
    real_oauth_inputs_forbidden: bool
    fake_fetch_only_required: bool
    one_node_process_required: bool
    ephemeral_workspace_required: bool
    network_disabled_before_import_required: bool
    compiled_send_post_scope_reviewed: bool
    non_token_post_retry_scope_conflict_recorded: bool
    step216_zero_retry_requirement_preserved: bool
    conditional_exception_remains_unapproved: bool
    harness_readiness_validated: bool
    browser_artifact_live_verified: bool
    common_artifact_live_verified: bool
    harness_executed_by_contract: bool
    exact_node_identity_checked: bool
    retry_trigger_runtime_checked: bool
    retry_count_runtime_checked: bool
    retry_backoff_runtime_checked: bool
    response_exclusions_runtime_checked: bool
    abort_exclusion_runtime_checked: bool
    non_token_exclusion_runtime_checked: bool
    concurrency_runtime_checked: bool
    telemetry_runtime_checked: bool
    request_equivalence_runtime_checked: bool
    conditional_exception_approved: bool
    step216_zero_retry_superseded: bool
    candidate_compatible: bool
    candidate_selected: bool
    package_installed: bool
    package_code_imported: bool
    filesystem_io_performed: bool
    process_io_performed: bool
    network_io_performed: bool
    provider_io_performed: bool
    activation_ready: bool
    receipt_self_authenticating: bool

    def __post_init__(self) -> None:
        strings = tuple(getattr(self, name) for name in _STRING_FIELDS)
        digests = tuple(
            getattr(self, name)
            for name in self.__dataclass_fields__
            if name.endswith("_sha256")
        )
        counts = tuple(getattr(self, name) for name in _COUNT_FIELDS)
        if (
            any(type(value) is not str for value in strings)
            or self.receipt_type != RECEIPT_TYPE
            or type(self.schema_version) is not int
            or self.schema_version != SCHEMA_VERSION
            or self.source != SOURCE
            or self.validation_scope != SCOPE
            or self.harness_profile != PROFILE
            or self.readiness_status != STATUS
            or self.harness_file_name != HARNESS_FILE_NAME
            or self.compiled_scope_finding
            != "sendPostRequestAsync_retries_non_abort_transport_failure_for_any_post_url"
            or any(not _is_sha256(value) for value in digests)
            or self.harness_sha256 != HARNESS_SHA256
            or self.browser_tarball_sha256 != BROWSER_TARBALL_SHA256
            or self.common_tarball_sha256 != COMMON_TARBALL_SHA256
            or self.compiled_retry_entry_sha256 != COMPILED_RETRY_ENTRY_SHA256
            or any(type(value) is not int for value in counts)
            or self.harness_bytes != HARNESS_BYTES
            or self.harness_scenario_count != HARNESS_SCENARIO_COUNT
            or self.reviewed_non_token_post_attempts != REVIEWED_NON_TOKEN_POST_ATTEMPTS
            or any(getattr(self, name) is not True for name in _TRUE_FIELDS)
            or any(getattr(self, name) is not False for name in _FALSE_FIELDS)
        ):
            raise ValueError("MSAL compiled retry harness readiness receipt is invalid")


_STRING_FIELDS = (
    "receipt_type",
    "source",
    "validation_scope",
    "harness_profile",
    "readiness_status",
    "harness_file_name",
    "compiled_scope_finding",
)
_COUNT_FIELDS = (
    "harness_bytes",
    "harness_scenario_count",
    "reviewed_non_token_post_attempts",
)
_TRUE_FIELDS = (
    "step221_source_chain_revalidated",
    "approved_step221_document_digest_bound",
    "exact_step221_fail_closed_state_validated",
    "exact_harness_bytes_bound",
    "exact_harness_sha256_bound",
    "exact_ten_scenario_matrix_bound",
    "real_oauth_inputs_forbidden",
    "fake_fetch_only_required",
    "one_node_process_required",
    "ephemeral_workspace_required",
    "network_disabled_before_import_required",
    "compiled_send_post_scope_reviewed",
    "non_token_post_retry_scope_conflict_recorded",
    "step216_zero_retry_requirement_preserved",
    "conditional_exception_remains_unapproved",
    "harness_readiness_validated",
)
_FALSE_FIELDS = (
    "browser_artifact_live_verified",
    "common_artifact_live_verified",
    "harness_executed_by_contract",
    "exact_node_identity_checked",
    "retry_trigger_runtime_checked",
    "retry_count_runtime_checked",
    "retry_backoff_runtime_checked",
    "response_exclusions_runtime_checked",
    "abort_exclusion_runtime_checked",
    "non_token_exclusion_runtime_checked",
    "concurrency_runtime_checked",
    "telemetry_runtime_checked",
    "request_equivalence_runtime_checked",
    "conditional_exception_approved",
    "step216_zero_retry_superseded",
    "candidate_compatible",
    "candidate_selected",
    "package_installed",
    "package_code_imported",
    "filesystem_io_performed",
    "process_io_performed",
    "network_io_performed",
    "provider_io_performed",
    "activation_ready",
    "receipt_self_authenticating",
)


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _framed(label: str, value: object) -> str:
    digest = hashlib.sha256()
    for part in ("engineer4me-step222-v1", label, _canonical(value)):
        encoded = part if isinstance(part, bytes) else part.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _parse(
    raw: bytes,
) -> tuple[bytes, EntraCallingClientMSALCompiledRetryHarnessReadinessDocument]:
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_DOCUMENT_BYTES:
        raise _ArgumentTypeError("exact document bytes are required")
    parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    keys = {
        "document_type",
        "schema_version",
        "source",
        "approved_compiled_retry_execution_readiness_document_sha256",
        "harness_profile",
    }
    if (
        type(parsed) is not dict
        or set(parsed) != keys
        or type(parsed["schema_version"]) is not int
        or any(type(parsed[key]) is not str for key in keys - {"schema_version"})
    ):
        raise ValueError("compiled retry harness document is invalid")
    canonical = _canonical(parsed)
    return (
        canonical,
        EntraCallingClientMSALCompiledRetryHarnessReadinessDocument.model_validate_json(
            canonical
        ),
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
        pending.extend(
            linked
            for linked in (current.__context__, current.__cause__)
            if isinstance(linked, BaseException)
        )
        children = getattr(current, "exceptions", ())
        if type(children) is tuple:
            pending.extend(
                child for child in children if isinstance(child, BaseException)
            )
        try:
            current.args = ()
            current.__traceback__ = None
            current.__context__ = None
            current.__cause__ = None
            current.__suppress_context__ = True
        except BaseException:  # noqa: BLE001,S110
            pass
    return interrupted, terminated


def _load_internal(
    *, document: bytes, harness: bytes, **step221_arguments: object
) -> EntraCallingClientMSALCompiledRetryHarnessReadinessReceipt:
    if type(document) is not bytes or type(harness) is not bytes:
        raise _ArgumentTypeError("exact document and harness bytes are required")
    prior_document = step221_arguments.pop(
        "compiled_retry_execution_readiness_document", None
    )
    approved = step221_arguments.pop(
        "approved_compiled_retry_execution_readiness_document_sha256", None
    )
    if type(prior_document) is not bytes or not _is_sha256(approved):
        raise _ArgumentTypeError("exact Step 221 evidence is required")
    prior = load_entra_calling_client_msal_compiled_retry_execution_readiness(
        document=prior_document,
        **step221_arguments,
    )
    if type(prior) is not EntraCallingClientMSALCompiledRetryExecutionReadinessReceipt:
        raise ValueError("exact Step 221 receipt is required")
    prior_rendered = (
        render_entra_calling_client_msal_compiled_retry_execution_readiness_receipt(
            prior
        )
    )
    if (
        prior.readiness_status != STEP221_READINESS_STATUS
        or prior.conditional_exception_approved
        or prior.step216_zero_retry_superseded
        or prior.current_candidate_selected
        or prior.node_process_executed
        or prior.activation_ready
        or prior.compiled_execution_readiness_document_sha256 != approved
    ):
        raise ValueError("Step 221 state is not the exact fail-closed baseline")
    canonical_document, validated = _parse(document)
    if (
        validated.approved_compiled_retry_execution_readiness_document_sha256
        != approved
        or len(harness) != HARNESS_BYTES
        or hashlib.sha256(harness).hexdigest() != HARNESS_SHA256
    ):
        raise ValueError("approved Step 221 or harness evidence mismatch")
    execution_plan = {
        "harnessSha256": HARNESS_SHA256,
        "scenarioCount": HARNESS_SCENARIO_COUNT,
        "node": "exact_identity_required",
        "workspace": "ephemeral",
        "networkBeforeImport": "disabled",
        "fetch": "fake_only",
        "oauthInputs": "synthetic_only",
    }
    scope_conflict = {
        "compiledEntrySha256": COMPILED_RETRY_ENTRY_SHA256,
        "method": "sendPostRequestAsync",
        "guard": "non_abort_transport_failure_and_online",
        "urlTokenRestrictionPresent": False,
        "reviewedNonTokenAttempts": REVIEWED_NON_TOKEN_POST_ATTEMPTS,
    }
    selection = {
        "step216ZeroRetrySuperseded": False,
        "exceptionApproved": False,
        "compatible": False,
        "selected": False,
    }
    return EntraCallingClientMSALCompiledRetryHarnessReadinessReceipt(
        receipt_type=RECEIPT_TYPE,
        schema_version=SCHEMA_VERSION,
        source=validated.source,
        validation_scope=SCOPE,
        harness_profile=validated.harness_profile,
        readiness_status=STATUS,
        harness_file_name=HARNESS_FILE_NAME,
        compiled_scope_finding="sendPostRequestAsync_retries_non_abort_transport_failure_for_any_post_url",
        configuration_sha256=prior.configuration_sha256,
        api_registration_document_sha256=prior.api_registration_document_sha256,
        calling_client_registration_document_sha256=prior.calling_client_registration_document_sha256,
        inventory_document_sha256=prior.inventory_document_sha256,
        compiled_retry_execution_readiness_document_sha256=prior.compiled_execution_readiness_document_sha256,
        compiled_retry_execution_readiness_receipt_sha256=hashlib.sha256(
            prior_rendered.encode("utf-8")
        ).hexdigest(),
        harness_readiness_document_sha256=hashlib.sha256(
            canonical_document
        ).hexdigest(),
        harness_sha256=HARNESS_SHA256,
        browser_tarball_sha256=BROWSER_TARBALL_SHA256,
        common_tarball_sha256=COMMON_TARBALL_SHA256,
        compiled_retry_entry_sha256=COMPILED_RETRY_ENTRY_SHA256,
        harness_execution_plan_sha256=_framed("execution", execution_plan),
        reviewed_scope_conflict_sha256=_framed("scope_conflict", scope_conflict),
        selection_state_sha256=_framed("selection", selection),
        harness_bytes=HARNESS_BYTES,
        harness_scenario_count=HARNESS_SCENARIO_COUNT,
        reviewed_non_token_post_attempts=REVIEWED_NON_TOKEN_POST_ATTEMPTS,
        **{name: True for name in _TRUE_FIELDS},
        **{name: False for name in _FALSE_FIELDS},
    )


def load_entra_calling_client_msal_compiled_retry_harness_readiness(
    **arguments: object,
) -> EntraCallingClientMSALCompiledRetryHarnessReadinessReceipt:
    """Return one sanitized offline Step 222 receipt."""

    result = None
    error = None
    invalid = False
    interrupted = False
    terminated = False
    try:
        result = _load_internal(**arguments)
    except _ArgumentTypeError as caught:
        error = caught
        invalid = True
    except BaseException as caught:  # noqa: BLE001
        error = caught
    finally:
        if error is not None:
            interrupted, terminated = _scrub(error)
        error = None
        arguments.clear()
    if interrupted:
        raise KeyboardInterrupt("MSAL compiled retry harness readiness interrupted")
    if terminated:
        raise SystemExit("MSAL compiled retry harness readiness terminated")
    if invalid:
        raise TypeError("MSAL compiled retry harness readiness inputs are invalid")
    if result is None:
        raise EntraCallingClientMSALCompiledRetryHarnessReadinessError(
            "MSAL compiled retry harness readiness validation failed"
        )
    return result


def render_entra_calling_client_msal_compiled_retry_harness_readiness_receipt(
    receipt: EntraCallingClientMSALCompiledRetryHarnessReadinessReceipt,
) -> str:
    """Render canonical Step 222 evidence."""

    if type(receipt) is not EntraCallingClientMSALCompiledRetryHarnessReadinessReceipt:
        raise TypeError("exact compiled retry harness receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {name: getattr(receipt, name) for name in receipt.__dataclass_fields__},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "DOCUMENT_TYPE",
    "HARNESS_BYTES",
    "HARNESS_FILE_NAME",
    "HARNESS_SCENARIO_COUNT",
    "HARNESS_SHA256",
    "PROFILE",
    "RECEIPT_TYPE",
    "REVIEWED_NON_TOKEN_POST_ATTEMPTS",
    "SOURCE",
    "STATUS",
    "EntraCallingClientMSALCompiledRetryHarnessReadinessError",
    "EntraCallingClientMSALCompiledRetryHarnessReadinessReceipt",
    "load_entra_calling_client_msal_compiled_retry_harness_readiness",
    "render_entra_calling_client_msal_compiled_retry_harness_readiness_receipt",
]

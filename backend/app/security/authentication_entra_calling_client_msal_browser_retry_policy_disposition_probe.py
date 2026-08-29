"""Controlled exact-artifact call-graph proof and retry-policy disposition.

The sealed path performs four read-only npm GETs through the Step 223 loader,
revalidates both exact archives, scans every compiled dist `.mjs` member, and
rejects the retry exception fail-closed. Injected evidence is synthetic and
cannot claim registry, archive, or scan attestation.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from builtins import BaseExceptionGroup
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import model_validator

import app.security.authentication_entra_calling_client_msal_browser_compiled_retry_execution_probe as step223_probe
from app.security.authentication_entra_calling_client_msal_browser_compiled_retry_live_loader import (
    BoundedEntraCallingClientMSALCompiledRetryLiveHTTPSLoader,
    build_entra_calling_client_msal_compiled_retry_live_request_plan,
)
from app.security.authentication_entra_calling_client_msal_browser_retry_exception_decision_readiness import (
    BROWSER_PACKAGE_NAME,
    BROWSER_VERSION,
    CLIENT_CONFIGURATION_STUB_PATH,
    CLIENT_CONFIGURATION_STUB_SHA256,
    COMMON_PACKAGE_NAME,
    COMMON_VERSION,
    FETCH_CLIENT_PATH,
    FETCH_CLIENT_SHA256,
    NETWORK_INTERFACE_PATH,
    NETWORK_INTERFACE_SHA256,
    TOKEN_CALL_SITE_PATH,
    TOKEN_CALL_SITE_SHA256,
    EntraCallingClientMSALRetryExceptionDecisionReadinessReceipt,
    load_entra_calling_client_msal_retry_exception_decision_readiness,
    render_entra_calling_client_msal_retry_exception_decision_readiness_receipt,
)
from app.security.authentication_entra_calling_client_msal_browser_retry_exception_decision_readiness import (
    STATUS as STEP224_STATUS,
)
from app.security.identity_models import SecurityModel

DOCUMENT_TYPE = (
    "engineer4me_microsoft_entra_calling_client_msal_retry_policy_disposition_proof"
)
RECEIPT_TYPE = DOCUMENT_TYPE + "_receipt"
SCHEMA_VERSION = 1
SOURCE = "engineer4me_controlled_msal_5_18_0_compiled_call_graph_rescan"
SCOPE = "exact_artifact_compiled_post_call_graph_and_retry_policy_rejection"
PROFILE = "engineer4me_msal_5_18_0_retry_policy_disposition_v1"
STATUS = "exact_call_graph_proof_correlated_and_retry_exception_rejected"
POLICY_DISPOSITION = "reject_retry_exception_require_zero_retry_candidate"

BROWSER_DIST_MJS_COUNT = 183
BROWSER_DIST_MJS_BYTES = 880_592
COMMON_DIST_MJS_COUNT = 69
COMMON_DIST_MJS_BYTES = 392_662
CALL_SITE_FILE_COUNT = 4
REAL_INVOCATION_FILE_COUNT = 1
FETCH_CLIENT_RAW_OCCURRENCE_COUNT = 1
TOKEN_RAW_OCCURRENCE_COUNT = 2
CLIENT_CONFIGURATION_RAW_OCCURRENCE_COUNT = 1
NETWORK_INTERFACE_RAW_OCCURRENCE_COUNT = 1
SEALED_REGISTRY_REQUEST_COUNT = 4
SEALED_ARTIFACT_SCAN_COUNT = 2
MAX_DOCUMENT_BYTES = 4_096
MAX_MJS_MEMBER_BYTES = 262_144
_SYMBOL = b"sendPostRequestAsync"
_TOKEN_INVOCATION = (
    b")(tokenEndpoint, { ...options, correlationId, performanceClient });"
)


class EntraCallingClientMSALRetryPolicyDispositionProbeError(ValueError):
    """Sanitized Step 225 proof failure."""


class _ArgumentTypeError(TypeError):
    """Private marker for invalid public arguments."""


class EntraCallingClientMSALRetryPolicyDispositionDocument(SecurityModel):
    document_type: Literal[
        "engineer4me_microsoft_entra_calling_client_msal_retry_policy_disposition_proof"
    ]
    schema_version: Literal[1]
    source: Literal["engineer4me_controlled_msal_5_18_0_compiled_call_graph_rescan"]
    approved_step224_decision_document_sha256: str
    disposition_profile: Literal["engineer4me_msal_5_18_0_retry_policy_disposition_v1"]

    @model_validator(mode="after")
    def validate_digest(
        self,
    ) -> EntraCallingClientMSALRetryPolicyDispositionDocument:
        if not _is_sha256(self.approved_step224_decision_document_sha256):
            raise ValueError("approved Step 224 digest is invalid")
        return self


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALCompiledCallGraphEvidence:
    browser_dist_mjs_count: int
    browser_dist_mjs_bytes: int
    common_dist_mjs_count: int
    common_dist_mjs_bytes: int
    call_site_file_count: int
    real_invocation_file_count: int
    fetch_client_sha256: str
    token_call_site_sha256: str
    client_configuration_stub_sha256: str
    network_interface_sha256: str
    fetch_client_raw_occurrence_count: int
    token_raw_occurrence_count: int
    client_configuration_raw_occurrence_count: int
    network_interface_raw_occurrence_count: int
    token_endpoint_argument_observed: bool
    fetch_client_url_guard_observed: bool
    live_exact_artifacts_attested: bool
    live_complete_dist_mjs_scan_attested: bool

    def __post_init__(self) -> None:
        expected: dict[str, object] = {
            "browser_dist_mjs_count": BROWSER_DIST_MJS_COUNT,
            "browser_dist_mjs_bytes": BROWSER_DIST_MJS_BYTES,
            "common_dist_mjs_count": COMMON_DIST_MJS_COUNT,
            "common_dist_mjs_bytes": COMMON_DIST_MJS_BYTES,
            "call_site_file_count": CALL_SITE_FILE_COUNT,
            "real_invocation_file_count": REAL_INVOCATION_FILE_COUNT,
            "fetch_client_sha256": FETCH_CLIENT_SHA256,
            "token_call_site_sha256": TOKEN_CALL_SITE_SHA256,
            "client_configuration_stub_sha256": CLIENT_CONFIGURATION_STUB_SHA256,
            "network_interface_sha256": NETWORK_INTERFACE_SHA256,
            "fetch_client_raw_occurrence_count": FETCH_CLIENT_RAW_OCCURRENCE_COUNT,
            "token_raw_occurrence_count": TOKEN_RAW_OCCURRENCE_COUNT,
            "client_configuration_raw_occurrence_count": CLIENT_CONFIGURATION_RAW_OCCURRENCE_COUNT,
            "network_interface_raw_occurrence_count": NETWORK_INTERFACE_RAW_OCCURRENCE_COUNT,
            "token_endpoint_argument_observed": True,
            "fetch_client_url_guard_observed": False,
        }
        for name, value in expected.items():
            actual = getattr(self, name)
            if type(actual) is not type(value) or actual != value:
                raise ValueError("compiled call-graph evidence is invalid")
        live_values = (
            self.live_exact_artifacts_attested,
            self.live_complete_dist_mjs_scan_attested,
        )
        if (
            any(type(value) is not bool for value in live_values)
            or len(set(live_values)) != 1
        ):
            raise ValueError("compiled call-graph provenance is invalid")


@dataclass(frozen=True, slots=True)
class EntraCallingClientMSALRetryPolicyDispositionReceipt:
    receipt_type: str
    schema_version: int
    source: str
    validation_scope: str
    disposition_profile: str
    proof_status: str
    policy_disposition: str
    browser_package_name: str
    browser_version: str
    common_package_name: str
    common_version: str
    fetch_client_path: str
    token_call_site_path: str
    client_configuration_stub_path: str
    network_interface_path: str
    step224_decision_document_sha256: str
    step224_decision_receipt_sha256: str
    disposition_document_sha256: str
    fetch_client_sha256: str
    token_call_site_sha256: str
    client_configuration_stub_sha256: str
    network_interface_sha256: str
    complete_call_graph_projection_sha256: str
    policy_rationale_sha256: str
    required_successor_state_sha256: str
    browser_dist_mjs_count: int
    browser_dist_mjs_bytes: int
    common_dist_mjs_count: int
    common_dist_mjs_bytes: int
    call_site_file_count: int
    real_invocation_file_count: int
    raw_symbol_occurrence_count: int
    sealed_registry_request_count: int
    sealed_artifact_scan_count: int
    step224_source_document_revalidated: bool
    approved_step224_digest_bound: bool
    exact_browser_and_common_artifacts_required: bool
    complete_dist_mjs_scan_required: bool
    exact_four_file_occurrence_inventory_validated: bool
    one_real_token_protocol_invocation_validated: bool
    real_invocation_passes_token_endpoint_validated: bool
    fetch_client_method_remains_url_agnostic: bool
    standard_public_client_call_site_confinement_validated: bool
    response_loss_code_consumption_risk_preserved: bool
    step216_zero_retry_requirement_authoritative: bool
    retry_exception_rejected: bool
    zero_retry_candidate_required: bool
    fail_closed_policy_disposition_validated: bool
    synthetic_evidence_used: bool
    sealed_registry_reads_attested: bool
    sealed_exact_artifacts_attested: bool
    sealed_complete_dist_mjs_scan_attested: bool
    step224_rendered_receipt_accepted_as_provenance: bool
    application_frontend_import_graph_checked: bool
    application_network_client_override_checked: bool
    source_to_distribution_reproducibility_checked: bool
    npm_registry_freshness_checked: bool
    npm_package_provenance_checked: bool
    package_security_advisories_checked: bool
    retry_exception_approved: bool
    msal_browser_5_18_0_compatible: bool
    msal_browser_5_18_0_selected: bool
    dependency_installed_or_locked: bool
    real_oauth_values_processed: bool
    runtime_retry_or_token_exchange_executed: bool
    application_configuration_mutation_performed: bool
    application_activation_performed: bool
    injected_transport_side_effects_checked: bool

    def __post_init__(self) -> None:
        constants: dict[str, object] = {
            "receipt_type": RECEIPT_TYPE,
            "schema_version": SCHEMA_VERSION,
            "source": SOURCE,
            "validation_scope": SCOPE,
            "disposition_profile": PROFILE,
            "proof_status": STATUS,
            "policy_disposition": POLICY_DISPOSITION,
            "browser_package_name": BROWSER_PACKAGE_NAME,
            "browser_version": BROWSER_VERSION,
            "common_package_name": COMMON_PACKAGE_NAME,
            "common_version": COMMON_VERSION,
            "fetch_client_path": FETCH_CLIENT_PATH,
            "token_call_site_path": TOKEN_CALL_SITE_PATH,
            "client_configuration_stub_path": CLIENT_CONFIGURATION_STUB_PATH,
            "network_interface_path": NETWORK_INTERFACE_PATH,
            "fetch_client_sha256": FETCH_CLIENT_SHA256,
            "token_call_site_sha256": TOKEN_CALL_SITE_SHA256,
            "client_configuration_stub_sha256": CLIENT_CONFIGURATION_STUB_SHA256,
            "network_interface_sha256": NETWORK_INTERFACE_SHA256,
            "browser_dist_mjs_count": BROWSER_DIST_MJS_COUNT,
            "browser_dist_mjs_bytes": BROWSER_DIST_MJS_BYTES,
            "common_dist_mjs_count": COMMON_DIST_MJS_COUNT,
            "common_dist_mjs_bytes": COMMON_DIST_MJS_BYTES,
            "call_site_file_count": CALL_SITE_FILE_COUNT,
            "real_invocation_file_count": REAL_INVOCATION_FILE_COUNT,
            "raw_symbol_occurrence_count": 5,
        }
        for name, expected in constants.items():
            actual = getattr(self, name)
            if type(actual) is not type(expected) or actual != expected:
                raise ValueError("retry-policy disposition constant is invalid")
        for name in (
            "step224_decision_document_sha256",
            "step224_decision_receipt_sha256",
            "disposition_document_sha256",
            "complete_call_graph_projection_sha256",
            "policy_rationale_sha256",
            "required_successor_state_sha256",
        ):
            if not _is_sha256(getattr(self, name)):
                raise ValueError("retry-policy disposition digest is invalid")
        true_names = (
            "step224_source_document_revalidated",
            "approved_step224_digest_bound",
            "exact_browser_and_common_artifacts_required",
            "complete_dist_mjs_scan_required",
            "exact_four_file_occurrence_inventory_validated",
            "one_real_token_protocol_invocation_validated",
            "real_invocation_passes_token_endpoint_validated",
            "fetch_client_method_remains_url_agnostic",
            "standard_public_client_call_site_confinement_validated",
            "response_loss_code_consumption_risk_preserved",
            "step216_zero_retry_requirement_authoritative",
            "retry_exception_rejected",
            "zero_retry_candidate_required",
            "fail_closed_policy_disposition_validated",
        )
        false_names = (
            "step224_rendered_receipt_accepted_as_provenance",
            "application_frontend_import_graph_checked",
            "application_network_client_override_checked",
            "source_to_distribution_reproducibility_checked",
            "npm_registry_freshness_checked",
            "npm_package_provenance_checked",
            "package_security_advisories_checked",
            "retry_exception_approved",
            "msal_browser_5_18_0_compatible",
            "msal_browser_5_18_0_selected",
            "dependency_installed_or_locked",
            "real_oauth_values_processed",
            "runtime_retry_or_token_exchange_executed",
            "application_configuration_mutation_performed",
            "application_activation_performed",
            "injected_transport_side_effects_checked",
        )
        for name in true_names:
            if type(getattr(self, name)) is not bool or not getattr(self, name):
                raise ValueError("required retry-policy fact is false")
        for name in false_names:
            if type(getattr(self, name)) is not bool or getattr(self, name):
                raise ValueError("deferred retry-policy fact is true")
        dynamic = (
            self.sealed_registry_reads_attested,
            self.sealed_exact_artifacts_attested,
            self.sealed_complete_dist_mjs_scan_attested,
        )
        if (
            any(type(value) is not bool for value in dynamic)
            or type(self.synthetic_evidence_used) is not bool
            or any(dynamic) == self.synthetic_evidence_used
            or len(set(dynamic)) != 1
        ):
            raise ValueError("retry-policy disposition provenance is invalid")
        live = not self.synthetic_evidence_used
        expected_requests = SEALED_REGISTRY_REQUEST_COUNT if live else 0
        expected_scans = SEALED_ARTIFACT_SCAN_COUNT if live else 0
        if (
            type(self.sealed_registry_request_count) is not int
            or self.sealed_registry_request_count != expected_requests
            or type(self.sealed_artifact_scan_count) is not int
            or self.sealed_artifact_scan_count != expected_scans
        ):
            raise ValueError("sealed operation counts are invalid")


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
    payload = _canonical(value)
    return hashlib.sha256(
        b"Engineer4Me-Step225-v1\x00" + domain.encode() + b"\x00" + payload
    ).hexdigest()


def _parse_document(
    document_bytes: object,
) -> tuple[bytes, EntraCallingClientMSALRetryPolicyDispositionDocument]:
    if type(document_bytes) is not bytes:
        raise _ArgumentTypeError("exact disposition document bytes are required")
    if not document_bytes or len(document_bytes) > MAX_DOCUMENT_BYTES:
        raise ValueError("disposition document size is invalid")
    try:
        text = document_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("disposition document encoding is invalid") from None
    try:
        raw = json.loads(text, object_pairs_hook=_pairs)
    except (json.JSONDecodeError, ValueError):
        raise ValueError("disposition document JSON is invalid") from None
    validated = EntraCallingClientMSALRetryPolicyDispositionDocument.model_validate(raw)
    return _canonical(validated.model_dump(mode="json")), validated


def _scan_archive(raw: bytes, package: str) -> tuple[int, int, dict[str, bytes]]:
    count = 0
    total = 0
    hits: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile() or not member.name.startswith("package/dist/"):
                continue
            if not member.name.endswith(".mjs"):
                continue
            if member.size < 1 or member.size > MAX_MJS_MEMBER_BYTES:
                raise ValueError("compiled module size is invalid")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("compiled module cannot be read")
            content = stream.read(member.size + 1)
            if len(content) != member.size:
                raise ValueError("compiled module length changed")
            count += 1
            total += len(content)
            if _SYMBOL in content:
                hits[member.name] = content
    expected = (
        (BROWSER_DIST_MJS_COUNT, BROWSER_DIST_MJS_BYTES)
        if package == BROWSER_PACKAGE_NAME
        else (COMMON_DIST_MJS_COUNT, COMMON_DIST_MJS_BYTES)
    )
    if (count, total) != expected:
        raise ValueError("compiled dist module closure changed")
    return count, total, hits


def _scan_exact_artifacts(
    browser_tarball: bytes, common_tarball: bytes
) -> EntraCallingClientMSALCompiledCallGraphEvidence:
    browser_count, browser_bytes, browser_hits = _scan_archive(
        browser_tarball, BROWSER_PACKAGE_NAME
    )
    common_count, common_bytes, common_hits = _scan_archive(
        common_tarball, COMMON_PACKAGE_NAME
    )
    expected_browser = {FETCH_CLIENT_PATH}
    expected_common = {
        CLIENT_CONFIGURATION_STUB_PATH,
        NETWORK_INTERFACE_PATH,
        TOKEN_CALL_SITE_PATH,
    }
    if set(browser_hits) != expected_browser or set(common_hits) != expected_common:
        raise ValueError("compiled POST call-site inventory changed")
    files = {**browser_hits, **common_hits}
    expected_hashes = {
        FETCH_CLIENT_PATH: FETCH_CLIENT_SHA256,
        TOKEN_CALL_SITE_PATH: TOKEN_CALL_SITE_SHA256,
        CLIENT_CONFIGURATION_STUB_PATH: CLIENT_CONFIGURATION_STUB_SHA256,
        NETWORK_INTERFACE_PATH: NETWORK_INTERFACE_SHA256,
    }
    if any(
        hashlib.sha256(files[path]).hexdigest() != digest
        for path, digest in expected_hashes.items()
    ):
        raise ValueError("compiled POST call-site identity changed")
    if _TOKEN_INVOCATION not in files[TOKEN_CALL_SITE_PATH]:
        raise ValueError("token endpoint invocation changed")
    return EntraCallingClientMSALCompiledCallGraphEvidence(
        browser_dist_mjs_count=browser_count,
        browser_dist_mjs_bytes=browser_bytes,
        common_dist_mjs_count=common_count,
        common_dist_mjs_bytes=common_bytes,
        call_site_file_count=len(files),
        real_invocation_file_count=1,
        fetch_client_sha256=FETCH_CLIENT_SHA256,
        token_call_site_sha256=TOKEN_CALL_SITE_SHA256,
        client_configuration_stub_sha256=CLIENT_CONFIGURATION_STUB_SHA256,
        network_interface_sha256=NETWORK_INTERFACE_SHA256,
        fetch_client_raw_occurrence_count=files[FETCH_CLIENT_PATH].count(_SYMBOL),
        token_raw_occurrence_count=files[TOKEN_CALL_SITE_PATH].count(_SYMBOL),
        client_configuration_raw_occurrence_count=files[
            CLIENT_CONFIGURATION_STUB_PATH
        ].count(_SYMBOL),
        network_interface_raw_occurrence_count=files[NETWORK_INTERFACE_PATH].count(
            _SYMBOL
        ),
        token_endpoint_argument_observed=True,
        fetch_client_url_guard_observed=False,
        live_exact_artifacts_attested=True,
        live_complete_dist_mjs_scan_attested=True,
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
            current.__suppress_context__ = True
        except BaseException:  # noqa: BLE001, S110
            pass
    return interrupted, terminated


def _load_internal(
    *,
    document_bytes: object,
    step224_document_bytes: object,
    call_graph_transport: object = None,
) -> EntraCallingClientMSALRetryPolicyDispositionReceipt:
    if type(document_bytes) is not bytes or type(step224_document_bytes) is not bytes:
        raise _ArgumentTypeError(
            "exact Step 224 and disposition document bytes are required"
        )
    if call_graph_transport is not None and not isinstance(
        call_graph_transport, Callable
    ):
        raise _ArgumentTypeError("call-graph transport must be callable")
    prior = load_entra_calling_client_msal_retry_exception_decision_readiness(
        step224_document_bytes
    )
    if type(prior) is not EntraCallingClientMSALRetryExceptionDecisionReadinessReceipt:
        raise ValueError("exact Step 224 receipt is required")
    prior.__post_init__()
    prior_rendered = (
        render_entra_calling_client_msal_retry_exception_decision_readiness_receipt(
            prior
        )
    )
    if (
        prior.readiness_status != STEP224_STATUS
        or prior.retry_exception_approved
        or prior.library_compatibility_approved
        or prior.package_selection_approved
        or not prior.step216_zero_retry_requirement_preserved
        or not prior.lost_response_code_consumption_ambiguity_preserved
    ):
        raise ValueError("Step 224 fail-closed state changed")
    canonical_document, document = _parse_document(document_bytes)
    if (
        document.approved_step224_decision_document_sha256
        != prior.decision_document_sha256
    ):
        raise ValueError("Step 224 approved digest changed")
    live = call_graph_transport is None
    artifacts = None
    responses = None
    if live:
        plan = build_entra_calling_client_msal_compiled_retry_live_request_plan()
        responses = BoundedEntraCallingClientMSALCompiledRetryLiveHTTPSLoader().load(
            plan
        )
        artifacts = step223_probe._verify_live_responses(responses)
        evidence = _scan_exact_artifacts(
            artifacts.browser_tarball, artifacts.common_tarball
        )
    else:
        evidence = call_graph_transport()
    if type(evidence) is not EntraCallingClientMSALCompiledCallGraphEvidence:
        raise ValueError("exact compiled call-graph evidence is required")
    evidence.__post_init__()
    if live != evidence.live_exact_artifacts_attested:
        raise ValueError("compiled call-graph evidence provenance changed")
    projection = {
        "browser_mjs": [
            evidence.browser_dist_mjs_count,
            evidence.browser_dist_mjs_bytes,
        ],
        "common_mjs": [evidence.common_dist_mjs_count, evidence.common_dist_mjs_bytes],
        "files": [
            [FETCH_CLIENT_PATH, FETCH_CLIENT_SHA256, "implementation", 1],
            [TOKEN_CALL_SITE_PATH, TOKEN_CALL_SITE_SHA256, "real_invocation", 2],
            [
                CLIENT_CONFIGURATION_STUB_PATH,
                CLIENT_CONFIGURATION_STUB_SHA256,
                "stub",
                1,
            ],
            [NETWORK_INTERFACE_PATH, NETWORK_INTERFACE_SHA256, "interface", 1],
        ],
        "token_endpoint_argument": True,
        "method_url_guard": False,
    }
    rationale = {
        "lost_response_may_have_consumed_code": True,
        "retry_success_guaranteed": False,
        "step216_zero_retry_authoritative": True,
        "method_is_url_agnostic": True,
        "standard_call_site_is_token_confined": True,
    }
    successor = {
        "candidate_retry_count": 0,
        "exact_artifact_proof_required": True,
        "compiled_behavior_proof_required": True,
        "application_import_graph_review_required": True,
        "package_selection_requires_new_gate": True,
    }
    receipt = EntraCallingClientMSALRetryPolicyDispositionReceipt(
        receipt_type=RECEIPT_TYPE,
        schema_version=SCHEMA_VERSION,
        source=SOURCE,
        validation_scope=SCOPE,
        disposition_profile=PROFILE,
        proof_status=STATUS,
        policy_disposition=POLICY_DISPOSITION,
        browser_package_name=BROWSER_PACKAGE_NAME,
        browser_version=BROWSER_VERSION,
        common_package_name=COMMON_PACKAGE_NAME,
        common_version=COMMON_VERSION,
        fetch_client_path=FETCH_CLIENT_PATH,
        token_call_site_path=TOKEN_CALL_SITE_PATH,
        client_configuration_stub_path=CLIENT_CONFIGURATION_STUB_PATH,
        network_interface_path=NETWORK_INTERFACE_PATH,
        step224_decision_document_sha256=prior.decision_document_sha256,
        step224_decision_receipt_sha256=hashlib.sha256(
            prior_rendered.encode()
        ).hexdigest(),
        disposition_document_sha256=hashlib.sha256(canonical_document).hexdigest(),
        fetch_client_sha256=FETCH_CLIENT_SHA256,
        token_call_site_sha256=TOKEN_CALL_SITE_SHA256,
        client_configuration_stub_sha256=CLIENT_CONFIGURATION_STUB_SHA256,
        network_interface_sha256=NETWORK_INTERFACE_SHA256,
        complete_call_graph_projection_sha256=_framed("call-graph", projection),
        policy_rationale_sha256=_framed("rationale", rationale),
        required_successor_state_sha256=_framed("successor", successor),
        browser_dist_mjs_count=BROWSER_DIST_MJS_COUNT,
        browser_dist_mjs_bytes=BROWSER_DIST_MJS_BYTES,
        common_dist_mjs_count=COMMON_DIST_MJS_COUNT,
        common_dist_mjs_bytes=COMMON_DIST_MJS_BYTES,
        call_site_file_count=CALL_SITE_FILE_COUNT,
        real_invocation_file_count=REAL_INVOCATION_FILE_COUNT,
        raw_symbol_occurrence_count=5,
        sealed_registry_request_count=SEALED_REGISTRY_REQUEST_COUNT if live else 0,
        sealed_artifact_scan_count=SEALED_ARTIFACT_SCAN_COUNT if live else 0,
        step224_source_document_revalidated=True,
        approved_step224_digest_bound=True,
        exact_browser_and_common_artifacts_required=True,
        complete_dist_mjs_scan_required=True,
        exact_four_file_occurrence_inventory_validated=True,
        one_real_token_protocol_invocation_validated=True,
        real_invocation_passes_token_endpoint_validated=True,
        fetch_client_method_remains_url_agnostic=True,
        standard_public_client_call_site_confinement_validated=True,
        response_loss_code_consumption_risk_preserved=True,
        step216_zero_retry_requirement_authoritative=True,
        retry_exception_rejected=True,
        zero_retry_candidate_required=True,
        fail_closed_policy_disposition_validated=True,
        synthetic_evidence_used=not live,
        sealed_registry_reads_attested=live,
        sealed_exact_artifacts_attested=live,
        sealed_complete_dist_mjs_scan_attested=live,
        step224_rendered_receipt_accepted_as_provenance=False,
        application_frontend_import_graph_checked=False,
        application_network_client_override_checked=False,
        source_to_distribution_reproducibility_checked=False,
        npm_registry_freshness_checked=False,
        npm_package_provenance_checked=False,
        package_security_advisories_checked=False,
        retry_exception_approved=False,
        msal_browser_5_18_0_compatible=False,
        msal_browser_5_18_0_selected=False,
        dependency_installed_or_locked=False,
        real_oauth_values_processed=False,
        runtime_retry_or_token_exchange_executed=False,
        application_configuration_mutation_performed=False,
        application_activation_performed=False,
        injected_transport_side_effects_checked=False,
    )
    if artifacts is not None:
        artifacts.browser_tarball = b""
        artifacts.common_tarball = b""
    responses = None
    step224_document_bytes = None
    return receipt


def load_entra_calling_client_msal_retry_policy_disposition_proof(
    **arguments: object,
) -> EntraCallingClientMSALRetryPolicyDispositionReceipt:
    """Return one sanitized Step 225 proof/disposition receipt."""

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
        raise KeyboardInterrupt("MSAL retry-policy disposition interrupted")
    if terminated:
        raise SystemExit("MSAL retry-policy disposition terminated")
    if invalid:
        raise TypeError("MSAL retry-policy disposition inputs are invalid")
    if result is None:
        raise EntraCallingClientMSALRetryPolicyDispositionProbeError(
            "MSAL retry-policy disposition proof failed"
        )
    return result


def render_entra_calling_client_msal_retry_policy_disposition_receipt(
    receipt: EntraCallingClientMSALRetryPolicyDispositionReceipt,
) -> str:
    """Render canonical privacy-minimized Step 225 evidence."""

    if type(receipt) is not EntraCallingClientMSALRetryPolicyDispositionReceipt:
        raise TypeError("exact MSAL retry-policy disposition receipt is required")
    receipt.__post_init__()
    return json.dumps(
        {name: getattr(receipt, name) for name in receipt.__dataclass_fields__},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


__all__ = [
    "BROWSER_DIST_MJS_BYTES",
    "BROWSER_DIST_MJS_COUNT",
    "CALL_SITE_FILE_COUNT",
    "COMMON_DIST_MJS_BYTES",
    "COMMON_DIST_MJS_COUNT",
    "DOCUMENT_TYPE",
    "POLICY_DISPOSITION",
    "PROFILE",
    "RECEIPT_TYPE",
    "SOURCE",
    "STATUS",
    "EntraCallingClientMSALCompiledCallGraphEvidence",
    "EntraCallingClientMSALRetryPolicyDispositionProbeError",
    "EntraCallingClientMSALRetryPolicyDispositionReceipt",
    "load_entra_calling_client_msal_retry_policy_disposition_proof",
    "render_entra_calling_client_msal_retry_policy_disposition_receipt",
]

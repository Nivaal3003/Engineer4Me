"""Strict stateless workflow contracts for Phase 7 Step 105 pressure relief.

The workflow exposes the existing Step 103 readiness assessment separately
from the three exact-version Step 104 required-area methods.  It adds only
typed request routing, inert catalogue metadata, deterministic audit evidence,
and safety-leading preliminary outcomes.  It performs no persistence, network
access, standards execution, device or orifice selection, manufacturer
selection, or final compliance decision.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from enum import StrEnum
from hashlib import sha256
from math import isfinite
from types import MappingProxyType
from typing import Annotated, Final, Literal

from pydantic import (
    Field,
    StrictBool,
    TypeAdapter,
    field_validator,
    model_validator,
)

from app.engineering.calculations.models import CalculationModel
from app.engineering.calculations.pressure_relief import (
    API_520_521_STANDARDS_PACK,
    ISO_4126_STANDARDS_PACK,
    PRESSURE_RELIEF_FOUNDATION_VERSION,
    PRESSURE_RELIEF_STANDARDS_PACK_VERSION,
    PressureReliefReadinessRequest,
    PressureReliefSafetyGateResult,
    PressureReliefStandardsFamily,
    PressureReliefStandardsPackMetadata,
    assess_pressure_relief_readiness,
    fingerprint_pressure_relief_readiness,
)
from app.engineering.calculations.pressure_relief_required_area import (
    ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
    ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION,
    GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
    GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION,
    LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
    LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION,
    PRESSURE_RELIEF_REQUIRED_AREA_CALCULATORS_VERSION,
    PRESSURE_RELIEF_REQUIRED_AREA_METHOD_REGISTRY,
    EligibleSteamPressureReliefRequiredAreaInput,
    EligibleSteamPressureReliefRequiredAreaResult,
    GasVapourPressureReliefRequiredAreaInput,
    GasVapourPressureReliefRequiredAreaResult,
    LiquidPressureReliefRequiredAreaInput,
    LiquidPressureReliefRequiredAreaResult,
)

PRESSURE_RELIEF_WORKFLOW_VERSION: Final = "1.0.0"
PRESSURE_RELIEF_CALCULATOR_PACK_VERSION: Final = "1.1.0"

# These public limits mirror the narrower limits already enforced by the
# Step 103-104 domain models.  They are exported so API documentation and
# clients do not need to depend on private calculation-module constants.
MAX_PRESSURE_RELIEF_TEXT_LENGTH: Final = 2_500
MAX_PUBLIC_PRESSURE_RELIEF_PRESSURE_PA: Final = 1.0e12
MAX_PUBLIC_PRESSURE_RELIEF_MASS_FLOW_KG_S: Final = 1.0e9
MAX_PUBLIC_PRESSURE_RELIEF_REQUIRED_AREA_M2: Final = 1.0e6

PRESSURE_RELIEF_FIXED_DISCLAIMERS: Final = (
    (
        "Every response is preliminary engineering decision support and is not "
        "approval for project use."
    ),
    (
        "No device, certified capacity, lettered or nominal orifice, product, "
        "brand, or manufacturer is selected."
    ),
    (
        "No API, ISO, jurisdictional, legal, site-authority, or manufacturer "
        "conformity is claimed."
    ),
    (
        "An independent competent pressure-systems engineer must review the "
        "scenario, load, pressure basis, properties, coefficients, installation, "
        "disposal system, and result."
    ),
)

_CANONICALIZATION: Final = "json-sort-keys-utf8-sha256-v1"
_LOWERCASE_SHA256_PATTERN: Final = r"^[0-9a-f]{64}$"


class PressureReliefOperation(StrEnum):
    """The three and only three executable Step 105 API operations."""

    LIQUID_REQUIRED_AREA = "liquid_required_area"
    GAS_VAPOUR_REQUIRED_AREA = "gas_vapour_required_area"
    ELIGIBLE_STEAM_REQUIRED_AREA = "eligible_steam_required_area"


class PressureReliefAuditAction(StrEnum):
    """Separate public audit actions; readiness is not a sizing method."""

    READINESS_ASSESSMENT = "readiness_assessment"
    REQUIRED_AREA_EXECUTION = "required_area_execution"


class PressureReliefWorkflowDisposition(StrEnum):
    """Fail-closed dispositions exposed by the stateless workflow."""

    READINESS_BLOCKED = "readiness_blocked"
    PRELIMINARY_REQUIRED_AREA_COMPLETE_REVIEW_REQUIRED = (
        "preliminary_required_area_complete_review_required"
    )


class PressureReliefWorkflowSafetySeverity(StrEnum):
    """Stable severity ordering for workflow-level safety findings."""

    BLOCKING = "blocking"
    REVIEW_REQUIRED = "review_required"


def _strict_unpadded_text(value: object, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be text")
    if not value or value != value.strip():
        raise ValueError(f"{field_name} must be nonblank and unpadded")
    return value


def _revalidate(value: object, model_type: type[CalculationModel]) -> CalculationModel:
    """Revalidate even frozen model instances at every workflow boundary."""

    if isinstance(value, CalculationModel):
        value = value.model_dump(mode="python", round_trip=True, warnings="error")
    return model_type.model_validate(value)


class PressureReliefReadinessAssessmentRequest(CalculationModel):
    """Typed body for the separate readiness-assessment endpoint."""

    readiness_request: PressureReliefReadinessRequest

    @field_validator("readiness_request", mode="before")
    @classmethod
    def revalidate_readiness_request(cls, value: object) -> CalculationModel:
        return _revalidate(value, PressureReliefReadinessRequest)


class _PressureReliefExecutionRequestBase(CalculationModel):
    method_id: str
    method_version: str

    @field_validator("method_id", "method_version", mode="before")
    @classmethod
    def reject_padded_method_identity(cls, value: object, info) -> str:
        return _strict_unpadded_text(value, field_name=info.field_name)


class LiquidPressureReliefExecutionRequest(_PressureReliefExecutionRequestBase):
    operation: Literal["liquid_required_area"]
    method_id: Literal["pressure-relief.liquid.required-area.supplied-factors"]
    method_version: Literal["1.0.0"]
    sizing_input: LiquidPressureReliefRequiredAreaInput

    @field_validator("sizing_input", mode="before")
    @classmethod
    def revalidate_sizing_input(cls, value: object) -> CalculationModel:
        return _revalidate(value, LiquidPressureReliefRequiredAreaInput)


class GasVapourPressureReliefExecutionRequest(_PressureReliefExecutionRequestBase):
    operation: Literal["gas_vapour_required_area"]
    method_id: Literal["pressure-relief.gas-vapour.required-area.supplied-factors"]
    method_version: Literal["1.0.0"]
    sizing_input: GasVapourPressureReliefRequiredAreaInput

    @field_validator("sizing_input", mode="before")
    @classmethod
    def revalidate_sizing_input(cls, value: object) -> CalculationModel:
        return _revalidate(value, GasVapourPressureReliefRequiredAreaInput)


class EligibleSteamPressureReliefExecutionRequest(_PressureReliefExecutionRequestBase):
    operation: Literal["eligible_steam_required_area"]
    method_id: Literal["pressure-relief.eligible-steam.required-area.supplied-factors"]
    method_version: Literal["1.0.0"]
    sizing_input: EligibleSteamPressureReliefRequiredAreaInput

    @field_validator("sizing_input", mode="before")
    @classmethod
    def revalidate_sizing_input(cls, value: object) -> CalculationModel:
        return _revalidate(value, EligibleSteamPressureReliefRequiredAreaInput)


type PressureReliefExecutionRequest = Annotated[
    LiquidPressureReliefExecutionRequest
    | GasVapourPressureReliefExecutionRequest
    | EligibleSteamPressureReliefExecutionRequest,
    Field(discriminator="operation"),
]
PRESSURE_RELIEF_REQUEST_ADAPTER: Final = TypeAdapter(PressureReliefExecutionRequest)

type PressureReliefRequiredAreaResult = Annotated[
    LiquidPressureReliefRequiredAreaResult
    | GasVapourPressureReliefRequiredAreaResult
    | EligibleSteamPressureReliefRequiredAreaResult,
    Field(discriminator="method_id"),
]
PRESSURE_RELIEF_RESULT_ADAPTER: Final = TypeAdapter(PressureReliefRequiredAreaResult)


class PressureReliefMethodCatalogueEntry(CalculationModel):
    """Public metadata for one exact approved generic calculation."""

    operation: PressureReliefOperation
    method_id: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]+$", max_length=160)
    method_version: str = Field(pattern=r"^\d+\.\d+\.\d+$", max_length=32)
    title: str = Field(min_length=3, max_length=240)
    implementation_name: str = Field(pattern=r"^[a-z][a-z0-9_]+$", max_length=160)
    input_model_name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9]+$", max_length=160)
    result_model_name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9]+$", max_length=160)
    knowledge_source_ids: tuple[str, ...] = Field(min_length=2, max_length=2)
    executable: Literal[True] = True
    lifecycle_status: Literal["approved"] = "approved"
    generic_supplied_factor_method: Literal[True] = True
    preliminary_only: Literal[True] = True
    knowledge_links_are_inert: Literal[True] = True
    standards_adapter_execution_count: Literal[0] = 0
    device_selection_performed: Literal[False] = False
    orifice_selection_performed: Literal[False] = False
    manufacturer_selection_performed: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False
    final_compliance_claimed: Literal[False] = False
    final_design_approval_granted: Literal[False] = False


class PressureReliefKnowledgeLink(CalculationModel):
    """Inert projection of one Step 103 standards discovery record."""

    source_id: str = Field(
        pattern=r"^pressure-relief\.[a-z0-9.-]+\.discovery$", max_length=160
    )
    source_version: Literal["1.0.0"] = PRESSURE_RELIEF_STANDARDS_PACK_VERSION
    standards_family: PressureReliefStandardsFamily
    title: str = Field(min_length=3, max_length=240)
    official_catalog_urls: tuple[str, ...] = Field(min_length=1, max_length=4)
    usage_boundary: str = Field(min_length=20, max_length=1_500)
    retrieval_mode: Literal["inert_metadata_only"] = "inert_metadata_only"
    network_access_performed: Literal[False] = False
    protected_content_embedded: Literal[False] = False
    approved_as_equation_or_factor_source: Literal[False] = False
    executable: Literal[False] = False
    conformity_evidence: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False


_RELATED_KNOWLEDGE_IDS: Final = (
    API_520_521_STANDARDS_PACK.pack_id,
    ISO_4126_STANDARDS_PACK.pack_id,
)


def _catalogue_entry(
    *,
    operation: PressureReliefOperation,
    method_id: str,
    method_version: str,
    title: str,
    input_model_name: str,
    result_model_name: str,
) -> PressureReliefMethodCatalogueEntry:
    metadata = PRESSURE_RELIEF_REQUIRED_AREA_METHOD_REGISTRY[
        (method_id, method_version)
    ]
    return PressureReliefMethodCatalogueEntry(
        operation=operation,
        method_id=method_id,
        method_version=method_version,
        title=title,
        implementation_name=metadata.implementation_name,
        input_model_name=input_model_name,
        result_model_name=result_model_name,
        knowledge_source_ids=_RELATED_KNOWLEDGE_IDS,
    )


PRESSURE_RELIEF_API_CATALOGUE: Final = (
    _catalogue_entry(
        operation=PressureReliefOperation.LIQUID_REQUIRED_AREA,
        method_id=LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
        method_version=LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION,
        title="Preliminary generic nonflashing-liquid required area",
        input_model_name="LiquidPressureReliefExecutionRequest",
        result_model_name="LiquidPressureReliefRequiredAreaResult",
    ),
    _catalogue_entry(
        operation=PressureReliefOperation.GAS_VAPOUR_REQUIRED_AREA,
        method_id=GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
        method_version=GAS_VAPOUR_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION,
        title="Preliminary generic gas or vapour required area",
        input_model_name="GasVapourPressureReliefExecutionRequest",
        result_model_name="GasVapourPressureReliefRequiredAreaResult",
    ),
    _catalogue_entry(
        operation=PressureReliefOperation.ELIGIBLE_STEAM_REQUIRED_AREA,
        method_id=ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
        method_version=ELIGIBLE_STEAM_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION,
        title="Preliminary generic eligible choked-steam required area",
        input_model_name="EligibleSteamPressureReliefExecutionRequest",
        result_model_name="EligibleSteamPressureReliefRequiredAreaResult",
    ),
)
PRESSURE_RELIEF_API_REGISTRY: Final = MappingProxyType(
    {entry.operation: entry for entry in PRESSURE_RELIEF_API_CATALOGUE}
)


def _knowledge_link(
    source: PressureReliefStandardsPackMetadata,
) -> PressureReliefKnowledgeLink:
    return PressureReliefKnowledgeLink(
        source_id=source.pack_id,
        source_version=source.pack_version,
        standards_family=source.standards_family,
        title=source.title,
        official_catalog_urls=source.official_catalog_urls,
        usage_boundary=source.boundary,
    )


PRESSURE_RELIEF_KNOWLEDGE_LINKS: Final = (
    _knowledge_link(API_520_521_STANDARDS_PACK),
    _knowledge_link(ISO_4126_STANDARDS_PACK),
)
PRESSURE_RELIEF_KNOWLEDGE_REGISTRY: Final = MappingProxyType(
    {entry.source_id: entry for entry in PRESSURE_RELIEF_KNOWLEDGE_LINKS}
)

if len(PRESSURE_RELIEF_API_REGISTRY) != 3:
    raise RuntimeError("pressure-relief API must expose exactly three operations")
if len(PRESSURE_RELIEF_KNOWLEDGE_REGISTRY) != 2:
    raise RuntimeError("pressure-relief API must expose exactly two knowledge links")
if set(PRESSURE_RELIEF_REQUIRED_AREA_METHOD_REGISTRY) != {
    (entry.method_id, entry.method_version) for entry in PRESSURE_RELIEF_API_CATALOGUE
}:
    raise RuntimeError("pressure-relief API exact method bindings are incomplete")
if any(
    not set(entry.knowledge_source_ids).issubset(PRESSURE_RELIEF_KNOWLEDGE_REGISTRY)
    for entry in PRESSURE_RELIEF_API_CATALOGUE
):
    raise RuntimeError("pressure-relief API references unknown knowledge metadata")


def _canonical_value(value: object) -> object:
    """Return a deterministic, JSON-safe workflow fingerprint value."""

    if isinstance(value, CalculationModel):
        return _canonical_value(
            value.model_dump(mode="json", round_trip=True, warnings="error")
        )
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("pressure-relief fingerprint keys must be strings")
        return {key: _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_canonical_value(item) for item in value]
    if isinstance(value, float):
        if not isfinite(value):
            raise ValueError("pressure-relief fingerprint values must be finite")
        return 0.0 if value == 0.0 else value
    if value is None or isinstance(value, (str, int, bool)):
        return value
    raise TypeError(
        "unsupported pressure-relief workflow fingerprint value: "
        f"{type(value).__name__}"
    )


def fingerprint_pressure_relief_workflow_payload(value: object) -> str:
    """Return one lowercase SHA-256 over canonical UTF-8 JSON."""

    payload = json.dumps(
        _canonical_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return sha256(payload).hexdigest()


def validate_pressure_relief_readiness_assessment_request(
    value: object,
) -> PressureReliefReadinessAssessmentRequest:
    return PressureReliefReadinessAssessmentRequest.model_validate(
        value.model_dump(mode="python", round_trip=True, warnings="error")
        if isinstance(value, CalculationModel)
        else value
    )


def validate_pressure_relief_execution_request(
    value: object,
) -> PressureReliefExecutionRequest:
    if isinstance(value, CalculationModel):
        value = value.model_dump(mode="python", round_trip=True, warnings="error")
    return PRESSURE_RELIEF_REQUEST_ADAPTER.validate_python(value)


def validate_pressure_relief_required_area_result(
    value: object,
) -> PressureReliefRequiredAreaResult:
    """Revalidate one exact method-discriminated Step 104 result."""

    if isinstance(value, CalculationModel):
        value = value.model_dump(mode="python", round_trip=True, warnings="error")
    return PRESSURE_RELIEF_RESULT_ADAPTER.validate_python(value)


def _selected_knowledge_source_ids(
    readiness_request: PressureReliefReadinessRequest,
) -> tuple[str, ...]:
    source_id = readiness_request.selected_standards_pack_id
    if source_id is None:
        return ()
    if source_id not in PRESSURE_RELIEF_KNOWLEDGE_REGISTRY:
        raise ValueError("selected pressure-relief knowledge source is unknown")
    return (source_id,)


def build_pressure_relief_readiness_input_fingerprint(
    request: PressureReliefReadinessAssessmentRequest,
) -> str:
    normalized = validate_pressure_relief_readiness_assessment_request(request)
    return fingerprint_pressure_relief_workflow_payload(
        {
            "schema": "engineer4me.pressure-relief.workflow-readiness-input.v1",
            "workflow_version": PRESSURE_RELIEF_WORKFLOW_VERSION,
            "foundation_version": PRESSURE_RELIEF_FOUNDATION_VERSION,
            "request": normalized,
        }
    )


def build_pressure_relief_input_fingerprint(
    request: PressureReliefExecutionRequest,
) -> str:
    normalized = validate_pressure_relief_execution_request(request)
    return fingerprint_pressure_relief_workflow_payload(
        {
            "schema": "engineer4me.pressure-relief.workflow-input.v1",
            "workflow_version": PRESSURE_RELIEF_WORKFLOW_VERSION,
            "calculator_pack_version": PRESSURE_RELIEF_CALCULATOR_PACK_VERSION,
            "request": normalized,
        }
    )


def build_pressure_relief_readiness_result_fingerprint(
    request: PressureReliefReadinessAssessmentRequest,
    result: PressureReliefSafetyGateResult,
) -> str:
    normalized = validate_pressure_relief_readiness_assessment_request(request)
    normalized_result = PressureReliefSafetyGateResult.model_validate(
        result.model_dump(mode="python", round_trip=True, warnings="error")
    )
    return fingerprint_pressure_relief_workflow_payload(
        {
            "schema": "engineer4me.pressure-relief.workflow-readiness-result.v1",
            "workflow_version": PRESSURE_RELIEF_WORKFLOW_VERSION,
            "foundation_version": PRESSURE_RELIEF_FOUNDATION_VERSION,
            "normalized_input_fingerprint": (
                build_pressure_relief_readiness_input_fingerprint(normalized)
            ),
            "result": normalized_result,
        }
    )


def build_pressure_relief_result_fingerprint(
    request: PressureReliefExecutionRequest,
    result: PressureReliefRequiredAreaResult,
) -> str:
    normalized = validate_pressure_relief_execution_request(request)
    operation = PressureReliefOperation(normalized.operation)
    metadata = PRESSURE_RELIEF_API_REGISTRY[operation]
    result_type = _RESULT_TYPE_BY_OPERATION[operation]
    validated_result = validate_pressure_relief_required_area_result(result)
    if not isinstance(validated_result, result_type):
        raise TypeError("pressure-relief result type does not match the operation")
    normalized_result = result_type.model_validate(
        validated_result.model_dump(mode="python", round_trip=True, warnings="error")
    )
    return fingerprint_pressure_relief_workflow_payload(
        {
            "schema": "engineer4me.pressure-relief.workflow-result.v1",
            "workflow_version": PRESSURE_RELIEF_WORKFLOW_VERSION,
            "calculator_pack_version": PRESSURE_RELIEF_CALCULATOR_PACK_VERSION,
            "operation": operation,
            "method_id": metadata.method_id,
            "method_version": metadata.method_version,
            "implementation_name": metadata.implementation_name,
            "normalized_input_fingerprint": build_pressure_relief_input_fingerprint(
                normalized
            ),
            "knowledge_source_ids": _selected_knowledge_source_ids(
                normalized.sizing_input.case.readiness_request
            ),
            "result": normalized_result,
        }
    )


def build_pressure_relief_attempt_fingerprint(
    *,
    action: PressureReliefAuditAction,
    input_fingerprint: str,
    result_fingerprint: str,
    operation: PressureReliefOperation | None,
    status: Literal["blocked", "completed_with_warnings"],
) -> str:
    return fingerprint_pressure_relief_workflow_payload(
        {
            "schema": "engineer4me.pressure-relief.workflow-attempt.v1",
            "workflow_version": PRESSURE_RELIEF_WORKFLOW_VERSION,
            "calculator_pack_version": PRESSURE_RELIEF_CALCULATOR_PACK_VERSION,
            "action": action,
            "operation": operation,
            "input_fingerprint": input_fingerprint,
            "result_fingerprint": result_fingerprint,
            "status": status,
        }
    )


_AUDIT_FINGERPRINT_FIELDS: Final = (
    "workflow_version",
    "foundation_version",
    "calculator_pack_version",
    "action",
    "operation",
    "method_id",
    "method_version",
    "calculator_version",
    "implementation_name",
    "request_model_name",
    "result_model_name",
    "readiness_request_id",
    "selected_scenario_id",
    "protected_equipment_reference",
    "selected_standards_pack_id",
    "selected_standards_pack_version",
    "normalized_input_fingerprint",
    "result_fingerprint",
    "attempt_fingerprint",
    "knowledge_source_ids",
    "canonicalization",
    "disclaimers",
    "status",
    "preliminary_engineering_decision_support",
    "independent_review_required",
    "calculation_performed",
    "persistence_performed",
    "network_access_performed",
    "standards_adapter_execution_count",
    "device_selected",
    "orifice_selected",
    "manufacturer_selection_performed",
    "standards_conformity_claimed",
    "final_compliance_claimed",
    "final_design_approval_granted",
    "approved_for_project_use",
)


def build_pressure_relief_audit_fingerprint(value: object) -> str:
    """Hash the complete immutable audit record except its self-hash."""

    if isinstance(value, CalculationModel):
        values = value.model_dump(mode="python", round_trip=True, warnings="error")
    elif isinstance(value, Mapping):
        values = value
    else:
        raise TypeError("pressure-relief audit values must be a mapping or model")
    missing = tuple(name for name in _AUDIT_FINGERPRINT_FIELDS if name not in values)
    if missing:
        raise ValueError("pressure-relief audit fingerprint payload is incomplete")
    return fingerprint_pressure_relief_workflow_payload(
        {
            "schema": "engineer4me.pressure-relief.workflow-audit.v1",
            **{name: values[name] for name in _AUDIT_FINGERPRINT_FIELDS},
        }
    )


_INPUT_TYPE_BY_OPERATION: Final = MappingProxyType(
    {
        PressureReliefOperation.LIQUID_REQUIRED_AREA: (
            LiquidPressureReliefRequiredAreaInput
        ),
        PressureReliefOperation.GAS_VAPOUR_REQUIRED_AREA: (
            GasVapourPressureReliefRequiredAreaInput
        ),
        PressureReliefOperation.ELIGIBLE_STEAM_REQUIRED_AREA: (
            EligibleSteamPressureReliefRequiredAreaInput
        ),
    }
)
_RESULT_TYPE_BY_OPERATION: Final = MappingProxyType(
    {
        PressureReliefOperation.LIQUID_REQUIRED_AREA: (
            LiquidPressureReliefRequiredAreaResult
        ),
        PressureReliefOperation.GAS_VAPOUR_REQUIRED_AREA: (
            GasVapourPressureReliefRequiredAreaResult
        ),
        PressureReliefOperation.ELIGIBLE_STEAM_REQUIRED_AREA: (
            EligibleSteamPressureReliefRequiredAreaResult
        ),
    }
)


class PressureReliefAuditRecord(CalculationModel):
    """Deterministic, self-validating, stateless evidence for one API attempt."""

    workflow_version: Literal["1.0.0"] = PRESSURE_RELIEF_WORKFLOW_VERSION
    foundation_version: Literal["1.0.0"] = PRESSURE_RELIEF_FOUNDATION_VERSION
    calculator_pack_version: Literal["1.1.0"] = PRESSURE_RELIEF_CALCULATOR_PACK_VERSION
    action: PressureReliefAuditAction
    operation: PressureReliefOperation | None
    method_id: str | None = Field(default=None, max_length=160)
    method_version: str | None = Field(default=None, max_length=32)
    calculator_version: Literal["1.0.0"]
    implementation_name: str = Field(pattern=r"^[a-z][a-z0-9_]+$", max_length=160)
    request_model_name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9]+$", max_length=160)
    result_model_name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9]+$", max_length=160)
    readiness_request_id: str = Field(
        min_length=3,
        max_length=120,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]+$",
    )
    selected_scenario_id: str | None = Field(default=None, max_length=120)
    protected_equipment_reference: str | None = Field(default=None, max_length=240)
    selected_standards_pack_id: str | None = Field(default=None, max_length=160)
    selected_standards_pack_version: str | None = Field(default=None, max_length=32)
    normalized_input_fingerprint: str = Field(pattern=_LOWERCASE_SHA256_PATTERN)
    result_fingerprint: str = Field(pattern=_LOWERCASE_SHA256_PATTERN)
    attempt_fingerprint: str = Field(pattern=_LOWERCASE_SHA256_PATTERN)
    knowledge_source_ids: tuple[str, ...] = Field(default=(), max_length=2)
    canonicalization: Literal["json-sort-keys-utf8-sha256-v1"] = _CANONICALIZATION
    disclaimers: tuple[str, ...] = PRESSURE_RELIEF_FIXED_DISCLAIMERS
    status: Literal["blocked", "completed_with_warnings"]
    preliminary_engineering_decision_support: Literal[True] = True
    independent_review_required: Literal[True] = True
    calculation_performed: StrictBool
    persistence_performed: Literal[False] = False
    network_access_performed: Literal[False] = False
    standards_adapter_execution_count: Literal[0] = 0
    device_selected: Literal[False] = False
    orifice_selected: Literal[False] = False
    manufacturer_selection_performed: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False
    final_compliance_claimed: Literal[False] = False
    final_design_approval_granted: Literal[False] = False
    approved_for_project_use: Literal[False] = False
    audit_fingerprint: str = Field(pattern=_LOWERCASE_SHA256_PATTERN)

    @field_validator(
        "readiness_request_id",
        "method_id",
        "method_version",
        "selected_scenario_id",
        "protected_equipment_reference",
        "selected_standards_pack_id",
        "selected_standards_pack_version",
        mode="before",
    )
    @classmethod
    def validate_optional_method_identity(cls, value: object, info) -> str | None:
        if value is None:
            if info.field_name == "readiness_request_id":
                raise ValueError("readiness_request_id is required")
            return None
        return _strict_unpadded_text(value, field_name=info.field_name)

    @field_validator(
        "normalized_input_fingerprint",
        "result_fingerprint",
        "attempt_fingerprint",
        "audit_fingerprint",
        mode="before",
    )
    @classmethod
    def reject_noncanonical_fingerprints(cls, value: object, info) -> str:
        normalized = _strict_unpadded_text(value, field_name=info.field_name)
        if len(normalized) != 64 or any(
            character not in "0123456789abcdef" for character in normalized
        ):
            raise ValueError(f"{info.field_name} must be lowercase SHA-256")
        return normalized

    @model_validator(mode="after")
    def validate_audit_integrity(self) -> PressureReliefAuditRecord:
        if self.disclaimers != PRESSURE_RELIEF_FIXED_DISCLAIMERS:
            raise ValueError("pressure-relief disclaimers must remain exact")
        if len(self.knowledge_source_ids) != len(set(self.knowledge_source_ids)):
            raise ValueError("pressure-relief knowledge source IDs must be unique")
        if any(
            source_id not in PRESSURE_RELIEF_KNOWLEDGE_REGISTRY
            for source_id in self.knowledge_source_ids
        ):
            raise ValueError("pressure-relief audit references unknown knowledge")
        if (self.selected_standards_pack_id is None) != (
            self.selected_standards_pack_version is None
        ):
            raise ValueError("selected standards pack ID and version must be paired")
        expected_knowledge = (
            ()
            if self.selected_standards_pack_id is None
            else (self.selected_standards_pack_id,)
        )
        if self.knowledge_source_ids != expected_knowledge:
            raise ValueError("audit knowledge must match the selected standards pack")
        if self.selected_standards_pack_id is not None and (
            self.selected_standards_pack_id not in PRESSURE_RELIEF_KNOWLEDGE_REGISTRY
            or self.selected_standards_pack_version
            != PRESSURE_RELIEF_KNOWLEDGE_REGISTRY[
                self.selected_standards_pack_id
            ].source_version
        ):
            raise ValueError("audit standards pack must resolve exactly")

        if self.action is PressureReliefAuditAction.READINESS_ASSESSMENT:
            if self.selected_scenario_id is not None:
                raise ValueError("readiness audit cannot select one scenario")
            expected_identity = (
                None,
                None,
                None,
                PRESSURE_RELIEF_FOUNDATION_VERSION,
                "assess_pressure_relief_readiness",
                "PressureReliefReadinessAssessmentRequest",
                "PressureReliefSafetyGateResult",
                "blocked",
                False,
            )
        else:
            if self.operation is None:
                raise ValueError("required-area audit requires an operation")
            if (
                self.selected_scenario_id is None
                or self.protected_equipment_reference is None
                or self.selected_standards_pack_id is None
            ):
                raise ValueError(
                    "required-area audit requires scenario, equipment, and standards trace"
                )
            metadata = PRESSURE_RELIEF_API_REGISTRY[self.operation]
            expected_identity = (
                self.operation,
                metadata.method_id,
                metadata.method_version,
                PRESSURE_RELIEF_REQUIRED_AREA_CALCULATORS_VERSION,
                metadata.implementation_name,
                metadata.input_model_name,
                metadata.result_model_name,
                "completed_with_warnings",
                True,
            )
        actual_identity = (
            self.operation,
            self.method_id,
            self.method_version,
            self.calculator_version,
            self.implementation_name,
            self.request_model_name,
            self.result_model_name,
            self.status,
            self.calculation_performed,
        )
        if actual_identity != expected_identity:
            raise ValueError("pressure-relief audit identity is inconsistent")
        expected_attempt = build_pressure_relief_attempt_fingerprint(
            action=self.action,
            operation=self.operation,
            input_fingerprint=self.normalized_input_fingerprint,
            result_fingerprint=self.result_fingerprint,
            status=self.status,
        )
        if self.attempt_fingerprint != expected_attempt:
            raise ValueError("pressure-relief attempt fingerprint is stale")
        if self.audit_fingerprint != build_pressure_relief_audit_fingerprint(self):
            raise ValueError("pressure-relief audit fingerprint is stale")
        return self


class PressureReliefWorkflowSafetyFinding(CalculationModel):
    """Safety-leading finding derived only from typed result state."""

    severity: PressureReliefWorkflowSafetySeverity
    code: str = Field(pattern=r"^[a-z][a-z0-9_]+$", max_length=120)
    source_finding_id: str | None = Field(default=None, max_length=160)
    summary: str = Field(min_length=10, max_length=500)
    required_action: str = Field(min_length=10, max_length=1_500)
    safety_first: Literal[True] = True
    preliminary_only: Literal[True] = True
    project_approval_granted: Literal[False] = False

    @model_validator(mode="after")
    def validate_source_binding(self) -> PressureReliefWorkflowSafetyFinding:
        if self.severity is PressureReliefWorkflowSafetySeverity.BLOCKING:
            if self.source_finding_id is None:
                raise ValueError("blocking workflow findings require a source finding")
        elif self.source_finding_id is not None:
            raise ValueError("review findings cannot claim a blocking source finding")
        return self


def _independent_review_finding() -> PressureReliefWorkflowSafetyFinding:
    return PressureReliefWorkflowSafetyFinding(
        severity=PressureReliefWorkflowSafetySeverity.REVIEW_REQUIRED,
        code="independent_pressure_systems_review_required",
        summary="Independent competent pressure-systems review remains mandatory.",
        required_action=(
            "Have an independent competent pressure-systems engineer review the "
            "complete application before any project, device, or compliance decision."
        ),
    )


def derive_pressure_relief_readiness_safety_findings(
    result: PressureReliefSafetyGateResult,
) -> tuple[PressureReliefWorkflowSafetyFinding, ...]:
    """Project typed Step 103 blocks into an ordered workflow safety lead."""

    normalized = PressureReliefSafetyGateResult.model_validate(
        result.model_dump(mode="python", round_trip=True, warnings="error")
    )
    return (
        *(
            PressureReliefWorkflowSafetyFinding(
                severity=PressureReliefWorkflowSafetySeverity.BLOCKING,
                code=finding.code.value,
                source_finding_id=finding.finding_id,
                summary=finding.title,
                required_action=finding.required_action,
            )
            for finding in normalized.blocking_findings
        ),
        _independent_review_finding(),
    )


def derive_pressure_relief_execution_safety_findings(
    result: PressureReliefRequiredAreaResult,
) -> tuple[PressureReliefWorkflowSafetyFinding, ...]:
    """Return fixed findings for every successful preliminary area result."""

    validate_pressure_relief_required_area_result(result)
    return (
        PressureReliefWorkflowSafetyFinding(
            severity=PressureReliefWorkflowSafetySeverity.REVIEW_REQUIRED,
            code="preliminary_required_area_not_device_selection",
            summary="The calculated required area is preliminary and is not a device area.",
            required_action=(
                "Complete the controlled certified-capacity, orifice, device, installation, "
                "disposal-system, and project reviews before selection."
            ),
        ),
        _independent_review_finding(),
    )


def _foundation_request_fingerprint(
    request: PressureReliefReadinessRequest,
) -> str:
    return fingerprint_pressure_relief_readiness(
        {
            "schema": "engineer4me.pressure-relief.readiness.v1",
            "foundation_version": PRESSURE_RELIEF_FOUNDATION_VERSION,
            "request": request,
        }
    )


class PressureReliefReadinessAssessmentOutcome(CalculationModel):
    """Safety-leading, immutable outcome for the separate readiness endpoint."""

    safety_findings: tuple[PressureReliefWorkflowSafetyFinding, ...] = Field(
        min_length=2, max_length=17
    )
    disposition: Literal[PressureReliefWorkflowDisposition.READINESS_BLOCKED] = (
        PressureReliefWorkflowDisposition.READINESS_BLOCKED
    )
    normalized_request: PressureReliefReadinessAssessmentRequest
    result: PressureReliefSafetyGateResult
    audit: PressureReliefAuditRecord
    disclaimers: tuple[str, ...] = PRESSURE_RELIEF_FIXED_DISCLAIMERS
    ready_for_required_area_execution: Literal[False] = False
    preliminary_engineering_decision_support: Literal[True] = True
    independent_review_required: Literal[True] = True
    device_selected: Literal[False] = False
    orifice_selected: Literal[False] = False
    manufacturer_selection_performed: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False
    final_compliance_claimed: Literal[False] = False
    final_design_approval_granted: Literal[False] = False
    approved_for_project_use: Literal[False] = False

    @model_validator(mode="after")
    def validate_readiness_outcome(self) -> PressureReliefReadinessAssessmentOutcome:
        request = validate_pressure_relief_readiness_assessment_request(
            self.normalized_request
        )
        result = PressureReliefSafetyGateResult.model_validate(
            self.result.model_dump(mode="python", round_trip=True, warnings="error")
        )
        expected_result = assess_pressure_relief_readiness(request.readiness_request)
        if result != expected_result:
            raise ValueError(
                "readiness result does not match the deterministic safety gate"
            )
        if self.disclaimers != PRESSURE_RELIEF_FIXED_DISCLAIMERS:
            raise ValueError("pressure-relief disclaimers must remain exact")
        if result.request_id != request.readiness_request.request_id or (
            result.request_fingerprint
            != _foundation_request_fingerprint(request.readiness_request)
        ):
            raise ValueError("readiness result does not bind the exact request")
        expected_findings = derive_pressure_relief_readiness_safety_findings(result)
        if self.safety_findings != expected_findings:
            raise ValueError("readiness safety findings are stale")
        expected_input = build_pressure_relief_readiness_input_fingerprint(request)
        expected_result = build_pressure_relief_readiness_result_fingerprint(
            request, result
        )
        expected_sources = _selected_knowledge_source_ids(request.readiness_request)
        audit = self.audit
        expected_equipment_reference = (
            None
            if not request.readiness_request.scenarios
            else request.readiness_request.scenarios[0].protected_equipment_reference
        )
        if (
            audit.action is not PressureReliefAuditAction.READINESS_ASSESSMENT
            or audit.normalized_input_fingerprint != expected_input
            or audit.result_fingerprint != expected_result
            or audit.knowledge_source_ids != expected_sources
            or audit.readiness_request_id != request.readiness_request.request_id
            or audit.selected_scenario_id is not None
            or audit.protected_equipment_reference != expected_equipment_reference
            or audit.selected_standards_pack_id
            != request.readiness_request.selected_standards_pack_id
            or audit.selected_standards_pack_version
            != request.readiness_request.selected_standards_pack_version
        ):
            raise ValueError("readiness audit does not bind the exact outcome")
        return self


class PressureReliefExecutionOutcome(CalculationModel):
    """Safety-leading, immutable outcome for one exact required-area method."""

    safety_findings: tuple[PressureReliefWorkflowSafetyFinding, ...] = Field(
        min_length=2, max_length=2
    )
    disposition: Literal[
        PressureReliefWorkflowDisposition.PRELIMINARY_REQUIRED_AREA_COMPLETE_REVIEW_REQUIRED
    ] = PressureReliefWorkflowDisposition.PRELIMINARY_REQUIRED_AREA_COMPLETE_REVIEW_REQUIRED
    normalized_request: PressureReliefExecutionRequest
    result: PressureReliefRequiredAreaResult
    audit: PressureReliefAuditRecord
    disclaimers: tuple[str, ...] = PRESSURE_RELIEF_FIXED_DISCLAIMERS
    preliminary_engineering_decision_support: Literal[True] = True
    independent_review_required: Literal[True] = True
    ready_for_device_selection: Literal[False] = False
    device_selected: Literal[False] = False
    orifice_selected: Literal[False] = False
    manufacturer_selection_performed: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False
    final_compliance_claimed: Literal[False] = False
    final_design_approval_granted: Literal[False] = False
    approved_for_project_use: Literal[False] = False

    @model_validator(mode="after")
    def validate_execution_outcome(self) -> PressureReliefExecutionOutcome:
        request = validate_pressure_relief_execution_request(self.normalized_request)
        operation = PressureReliefOperation(request.operation)
        metadata = PRESSURE_RELIEF_API_REGISTRY[operation]
        result_type = _RESULT_TYPE_BY_OPERATION[operation]
        if not isinstance(self.result, result_type):
            raise TypeError("pressure-relief result type does not match the operation")
        result = result_type.model_validate(
            self.result.model_dump(mode="python", round_trip=True, warnings="error")
        )
        if not isinstance(request.sizing_input, _INPUT_TYPE_BY_OPERATION[operation]):
            raise TypeError("pressure-relief input type does not match the operation")
        if result.normalized_input != request.sizing_input:
            raise ValueError("pressure-relief result does not bind the exact request")
        if (
            result.method_id != metadata.method_id
            or result.method_version != metadata.method_version
            or result.calculator_version
            != PRESSURE_RELIEF_REQUIRED_AREA_CALCULATORS_VERSION
        ):
            raise ValueError("pressure-relief result method identity is inconsistent")
        if self.disclaimers != PRESSURE_RELIEF_FIXED_DISCLAIMERS:
            raise ValueError("pressure-relief disclaimers must remain exact")
        expected_findings = derive_pressure_relief_execution_safety_findings(result)
        if self.safety_findings != expected_findings:
            raise ValueError("pressure-relief execution safety findings are stale")
        expected_input = build_pressure_relief_input_fingerprint(request)
        expected_result = build_pressure_relief_result_fingerprint(request, result)
        expected_sources = _selected_knowledge_source_ids(
            request.sizing_input.case.readiness_request
        )
        audit = self.audit
        if (
            audit.action is not PressureReliefAuditAction.REQUIRED_AREA_EXECUTION
            or audit.operation is not operation
            or audit.normalized_input_fingerprint != expected_input
            or audit.result_fingerprint != expected_result
            or audit.knowledge_source_ids != expected_sources
            or audit.readiness_request_id
            != request.sizing_input.case.readiness_request.request_id
            or audit.selected_scenario_id != request.sizing_input.case.scenario_id
            or audit.selected_scenario_id != result.selected_scenario_id
            or audit.protected_equipment_reference
            != result.protected_equipment_reference
            or audit.selected_standards_pack_id
            != request.sizing_input.case.readiness_request.selected_standards_pack_id
            or audit.selected_standards_pack_version
            != request.sizing_input.case.readiness_request.selected_standards_pack_version
        ):
            raise ValueError("pressure-relief audit does not bind the exact outcome")
        return self


def _build_audit_record(
    *,
    action: PressureReliefAuditAction,
    operation: PressureReliefOperation | None,
    method_id: str | None,
    method_version: str | None,
    calculator_version: Literal["1.0.0"],
    implementation_name: str,
    request_model_name: str,
    result_model_name: str,
    readiness_request_id: str,
    selected_scenario_id: str | None,
    protected_equipment_reference: str | None,
    selected_standards_pack_id: str | None,
    selected_standards_pack_version: str | None,
    input_fingerprint: str,
    result_fingerprint: str,
    knowledge_source_ids: tuple[str, ...],
    status: Literal["blocked", "completed_with_warnings"],
    calculation_performed: bool,
) -> PressureReliefAuditRecord:
    values: dict[str, object] = {
        "workflow_version": PRESSURE_RELIEF_WORKFLOW_VERSION,
        "foundation_version": PRESSURE_RELIEF_FOUNDATION_VERSION,
        "calculator_pack_version": PRESSURE_RELIEF_CALCULATOR_PACK_VERSION,
        "action": action,
        "operation": operation,
        "method_id": method_id,
        "method_version": method_version,
        "calculator_version": calculator_version,
        "implementation_name": implementation_name,
        "request_model_name": request_model_name,
        "result_model_name": result_model_name,
        "readiness_request_id": readiness_request_id,
        "selected_scenario_id": selected_scenario_id,
        "protected_equipment_reference": protected_equipment_reference,
        "selected_standards_pack_id": selected_standards_pack_id,
        "selected_standards_pack_version": selected_standards_pack_version,
        "normalized_input_fingerprint": input_fingerprint,
        "result_fingerprint": result_fingerprint,
        "attempt_fingerprint": build_pressure_relief_attempt_fingerprint(
            action=action,
            operation=operation,
            input_fingerprint=input_fingerprint,
            result_fingerprint=result_fingerprint,
            status=status,
        ),
        "knowledge_source_ids": knowledge_source_ids,
        "canonicalization": _CANONICALIZATION,
        "disclaimers": PRESSURE_RELIEF_FIXED_DISCLAIMERS,
        "status": status,
        "preliminary_engineering_decision_support": True,
        "independent_review_required": True,
        "calculation_performed": calculation_performed,
        "persistence_performed": False,
        "network_access_performed": False,
        "standards_adapter_execution_count": 0,
        "device_selected": False,
        "orifice_selected": False,
        "manufacturer_selection_performed": False,
        "standards_conformity_claimed": False,
        "final_compliance_claimed": False,
        "final_design_approval_granted": False,
        "approved_for_project_use": False,
    }
    return PressureReliefAuditRecord(
        **values,
        audit_fingerprint=build_pressure_relief_audit_fingerprint(values),
    )


def build_pressure_relief_readiness_outcome(
    request: PressureReliefReadinessAssessmentRequest,
    result: PressureReliefSafetyGateResult,
) -> PressureReliefReadinessAssessmentOutcome:
    """Build and revalidate a complete deterministic readiness outcome."""

    normalized = validate_pressure_relief_readiness_assessment_request(request)
    normalized_result = PressureReliefSafetyGateResult.model_validate(
        result.model_dump(mode="python", round_trip=True, warnings="error")
    )
    if normalized_result != assess_pressure_relief_readiness(
        normalized.readiness_request
    ):
        raise ValueError(
            "readiness result does not match the deterministic safety gate"
        )
    input_fingerprint = build_pressure_relief_readiness_input_fingerprint(normalized)
    result_fingerprint = build_pressure_relief_readiness_result_fingerprint(
        normalized, normalized_result
    )
    audit = _build_audit_record(
        action=PressureReliefAuditAction.READINESS_ASSESSMENT,
        operation=None,
        method_id=None,
        method_version=None,
        calculator_version=PRESSURE_RELIEF_FOUNDATION_VERSION,
        implementation_name="assess_pressure_relief_readiness",
        request_model_name="PressureReliefReadinessAssessmentRequest",
        result_model_name="PressureReliefSafetyGateResult",
        readiness_request_id=normalized.readiness_request.request_id,
        selected_scenario_id=None,
        protected_equipment_reference=(
            None
            if not normalized.readiness_request.scenarios
            else normalized.readiness_request.scenarios[0].protected_equipment_reference
        ),
        selected_standards_pack_id=(
            normalized.readiness_request.selected_standards_pack_id
        ),
        selected_standards_pack_version=(
            normalized.readiness_request.selected_standards_pack_version
        ),
        input_fingerprint=input_fingerprint,
        result_fingerprint=result_fingerprint,
        knowledge_source_ids=_selected_knowledge_source_ids(
            normalized.readiness_request
        ),
        status="blocked",
        calculation_performed=False,
    )
    return PressureReliefReadinessAssessmentOutcome(
        safety_findings=derive_pressure_relief_readiness_safety_findings(
            normalized_result
        ),
        normalized_request=normalized,
        result=normalized_result,
        audit=audit,
    )


def build_pressure_relief_execution_outcome(
    request: PressureReliefExecutionRequest,
    result: PressureReliefRequiredAreaResult,
) -> PressureReliefExecutionOutcome:
    """Build and revalidate a complete deterministic required-area outcome."""

    normalized = validate_pressure_relief_execution_request(request)
    operation = PressureReliefOperation(normalized.operation)
    metadata = PRESSURE_RELIEF_API_REGISTRY[operation]
    result_type = _RESULT_TYPE_BY_OPERATION[operation]
    validated_result = validate_pressure_relief_required_area_result(result)
    if not isinstance(validated_result, result_type):
        raise TypeError("pressure-relief result type does not match the operation")
    normalized_result = result_type.model_validate(
        validated_result.model_dump(mode="python", round_trip=True, warnings="error")
    )
    input_fingerprint = build_pressure_relief_input_fingerprint(normalized)
    result_fingerprint = build_pressure_relief_result_fingerprint(
        normalized, normalized_result
    )
    audit = _build_audit_record(
        action=PressureReliefAuditAction.REQUIRED_AREA_EXECUTION,
        operation=operation,
        method_id=metadata.method_id,
        method_version=metadata.method_version,
        calculator_version=PRESSURE_RELIEF_REQUIRED_AREA_CALCULATORS_VERSION,
        implementation_name=metadata.implementation_name,
        request_model_name=metadata.input_model_name,
        result_model_name=metadata.result_model_name,
        readiness_request_id=(
            normalized.sizing_input.case.readiness_request.request_id
        ),
        selected_scenario_id=normalized.sizing_input.case.scenario_id,
        protected_equipment_reference=normalized_result.protected_equipment_reference,
        selected_standards_pack_id=(
            normalized.sizing_input.case.readiness_request.selected_standards_pack_id
        ),
        selected_standards_pack_version=(
            normalized.sizing_input.case.readiness_request.selected_standards_pack_version
        ),
        input_fingerprint=input_fingerprint,
        result_fingerprint=result_fingerprint,
        knowledge_source_ids=_selected_knowledge_source_ids(
            normalized.sizing_input.case.readiness_request
        ),
        status="completed_with_warnings",
        calculation_performed=True,
    )
    return PressureReliefExecutionOutcome(
        safety_findings=derive_pressure_relief_execution_safety_findings(
            normalized_result
        ),
        normalized_request=normalized,
        result=normalized_result,
        audit=audit,
    )


__all__ = [
    "MAX_PRESSURE_RELIEF_TEXT_LENGTH",
    "MAX_PUBLIC_PRESSURE_RELIEF_MASS_FLOW_KG_S",
    "MAX_PUBLIC_PRESSURE_RELIEF_PRESSURE_PA",
    "MAX_PUBLIC_PRESSURE_RELIEF_REQUIRED_AREA_M2",
    "PRESSURE_RELIEF_API_CATALOGUE",
    "PRESSURE_RELIEF_API_REGISTRY",
    "PRESSURE_RELIEF_CALCULATOR_PACK_VERSION",
    "PRESSURE_RELIEF_FIXED_DISCLAIMERS",
    "PRESSURE_RELIEF_KNOWLEDGE_LINKS",
    "PRESSURE_RELIEF_KNOWLEDGE_REGISTRY",
    "PRESSURE_RELIEF_REQUEST_ADAPTER",
    "PRESSURE_RELIEF_RESULT_ADAPTER",
    "PRESSURE_RELIEF_WORKFLOW_VERSION",
    "EligibleSteamPressureReliefExecutionRequest",
    "GasVapourPressureReliefExecutionRequest",
    "LiquidPressureReliefExecutionRequest",
    "PressureReliefAuditAction",
    "PressureReliefAuditRecord",
    "PressureReliefExecutionOutcome",
    "PressureReliefExecutionRequest",
    "PressureReliefKnowledgeLink",
    "PressureReliefMethodCatalogueEntry",
    "PressureReliefOperation",
    "PressureReliefReadinessAssessmentOutcome",
    "PressureReliefReadinessAssessmentRequest",
    "PressureReliefRequiredAreaResult",
    "PressureReliefWorkflowDisposition",
    "PressureReliefWorkflowSafetyFinding",
    "PressureReliefWorkflowSafetySeverity",
    "build_pressure_relief_attempt_fingerprint",
    "build_pressure_relief_audit_fingerprint",
    "build_pressure_relief_execution_outcome",
    "build_pressure_relief_input_fingerprint",
    "build_pressure_relief_readiness_input_fingerprint",
    "build_pressure_relief_readiness_outcome",
    "build_pressure_relief_readiness_result_fingerprint",
    "build_pressure_relief_result_fingerprint",
    "derive_pressure_relief_execution_safety_findings",
    "derive_pressure_relief_readiness_safety_findings",
    "fingerprint_pressure_relief_workflow_payload",
    "validate_pressure_relief_execution_request",
    "validate_pressure_relief_readiness_assessment_request",
    "validate_pressure_relief_required_area_result",
]

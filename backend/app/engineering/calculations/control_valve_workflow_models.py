"""Typed Step 102 control-valve workflow and design-case contracts.

The public workflow exposes only the three exact-version Step 100-101
implementations.  Installed screens accept raw sizing inputs in fixed
minimum/normal/maximum fields so the service calculates every child result and
the workflow fingerprint cannot depend on caller tuple order.  Safety findings
are derived from typed result fields, lead every design-case response, and
never imply product approval, standards conformity, or an acoustic guarantee.
"""

from __future__ import annotations

import json
from enum import StrEnum
from hashlib import sha256
from types import MappingProxyType
from typing import Annotated, Final, Literal, TypeAlias

from app.engineering.calculations.control_valve import (
    CONTROL_VALVE_CALCULATORS_VERSION,
    LIQUID_CONTROL_VALVE_SIZING_METHOD_ID,
    LIQUID_CONTROL_VALVE_SIZING_METHOD_VERSION,
    LiquidCavitationStatus,
    LiquidControlValveSizingInput,
    LiquidControlValveSizingResult,
    LiquidVelocityStatus,
)
from app.engineering.calculations.control_valve_compressible import (
    COMPRESSIBLE_CONTROL_VALVE_CALCULATORS_VERSION,
    COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_ID,
    COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_VERSION,
    CompressibleControlValveSizingInput,
    CompressibleControlValveSizingResult,
)
from app.engineering.calculations.control_valve_installed import (
    CONTROL_VALVE_INSTALLED_CALCULATORS_VERSION,
    CONTROL_VALVE_INSTALLED_METHOD_VERSION,
    INSTALLED_CONTROL_VALVE_SCREEN_METHOD_ID,
    AerodynamicNoisePriority,
    CapacityCurveStatus,
    FactorTravelCoherenceStatus,
    InstalledCaseRole,
    InstalledControlValveScreenRequest,
    InstalledControlValveScreenResult,
    InstalledOperatingCase,
    RangeabilityStatus,
    TraceableDownstreamAcousticState,
    TraceableInstalledValveCandidate,
    TravelWindowStatus,
)
from app.engineering.calculations.models import CalculationModel, FingerprintText
from pydantic import (
    Field,
    StrictBool,
    StrictInt,
    TypeAdapter,
    field_validator,
    model_validator,
)

CONTROL_VALVE_WORKFLOW_VERSION: Final = "1.0.0"
CONTROL_VALVE_CALCULATOR_PACK_VERSION: Final = "1.1.0"
MAX_CONTROL_VALVE_TEXT_LENGTH: Final = 1_500
MIN_PUBLIC_CAPACITY_CV: Final = 1.0e-12
MAX_PUBLIC_CAPACITY_CV: Final = 1.0e12


class ControlValveOperation(StrEnum):
    """Exact Step 102 allow-listed operations."""

    LIQUID_SIZING = "liquid_sizing"
    COMPRESSIBLE_SIZING = "compressible_sizing"
    INSTALLED_SCREEN = "installed_screen"


ControlValveSizingInput: TypeAlias = (
    LiquidControlValveSizingInput | CompressibleControlValveSizingInput
)
ControlValveResult: TypeAlias = (
    LiquidControlValveSizingResult
    | CompressibleControlValveSizingResult
    | InstalledControlValveScreenResult
)


def _bounded_sizing_input(value: ControlValveSizingInput) -> ControlValveSizingInput:
    """Constrain public inputs before any calculation kernel is invoked."""

    if isinstance(value, LiquidControlValveSizingInput):
        properties = value.properties
        pressure = value.pressure_state
        velocity_limit = value.maximum_outlet_velocity
        checks = (
            1.0e-12 <= value.actual_volumetric_flow_m3_h <= 1.0e12,
            1.0e-9 <= value.outlet_inside_diameter_m <= 20.0,
            1.0e-12 <= properties.specific_gravity <= 1.0e7,
            1.0 <= properties.flowing_temperature_k <= 1.0e6,
            0.0 <= properties.vapor_pressure_absolute_pa <= 1.0e12,
            1.0 <= properties.critical_pressure_absolute_pa <= 1.0e12,
            1.0 <= pressure.downstream_pressure_absolute_pa <= 1.0e12,
            1.0 <= pressure.upstream_pressure_absolute_pa <= 1.0e12,
            velocity_limit is None
            or velocity_limit.maximum_velocity_m_s <= 1.0e6,
        )
    else:
        properties = value.properties
        pressure = value.pressure_state
        checks = (
            1.0e-12 <= value.mass_flow_kg_h <= 1.0e15,
            1.0 <= properties.upstream_temperature_k <= 1.0e6,
            1.0e-12 <= properties.upstream_density_kg_m3 <= 1.0e7,
            1.0e-9 <= properties.molecular_mass_kg_kmol <= 1.0e6,
            1.0e-12 <= properties.compressibility_factor <= 100.0,
            1.0 <= pressure.downstream_pressure_absolute_pa <= 1.0e12,
            1.0 <= pressure.upstream_pressure_absolute_pa <= 1.0e12,
            properties.state_uncertainty_k is None
            or properties.state_uncertainty_k <= 1.0e6,
            properties.state_pressure_uncertainty_pa is None
            or properties.state_pressure_uncertainty_pa <= 1.0e12,
        )
    if not all(checks):
        raise ValueError("sizing input exceeds the bounded public workflow domain")
    return value


def _bounded_acoustic_state(
    value: TraceableDownstreamAcousticState | None,
) -> TraceableDownstreamAcousticState | None:
    if value is None:
        return None
    if not (
        1.0e-12 <= value.downstream_density_kg_m3 <= 1.0e7
        and 1.0e-9 <= value.downstream_speed_of_sound_m_s <= 1.0e6
        and 1.0e-9 <= value.downstream_pipe_inside_diameter_m <= 20.0
    ):
        raise ValueError("acoustic state exceeds the bounded public workflow domain")
    return value


class _ExecutionRequestBase(CalculationModel):
    method_id: str
    method_version: str


class LiquidControlValveExecutionRequest(_ExecutionRequestBase):
    operation: Literal["liquid_sizing"]
    method_id: Literal[LIQUID_CONTROL_VALVE_SIZING_METHOD_ID]
    method_version: Literal[LIQUID_CONTROL_VALVE_SIZING_METHOD_VERSION]
    sizing_input: LiquidControlValveSizingInput

    _input_bounds = field_validator("sizing_input")(_bounded_sizing_input)


class CompressibleControlValveExecutionRequest(_ExecutionRequestBase):
    operation: Literal["compressible_sizing"]
    method_id: Literal[COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_ID]
    method_version: Literal[COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_VERSION]
    sizing_input: CompressibleControlValveSizingInput

    _input_bounds = field_validator("sizing_input")(_bounded_sizing_input)


class ControlValveOperatingPointInput(CalculationModel):
    """One raw operating point; its role is fixed by the parent field name."""

    sizing_input: ControlValveSizingInput
    downstream_acoustic_state: TraceableDownstreamAcousticState | None = None

    _input_bounds = field_validator("sizing_input")(_bounded_sizing_input)
    _acoustic_bounds = field_validator("downstream_acoustic_state")(
        _bounded_acoustic_state
    )

    @model_validator(mode="after")
    def validate_case_binding(self) -> ControlValveOperatingPointInput:
        state = self.downstream_acoustic_state
        if state is not None and state.sizing_case_id != self.sizing_input.case_id:
            raise ValueError("acoustic state must bind the exact sizing case")
        return self


class InstalledControlValveExecutionRequest(_ExecutionRequestBase):
    """Canonical raw-input contract for the installed candidate screen."""

    operation: Literal["installed_screen"]
    method_id: Literal[INSTALLED_CONTROL_VALVE_SCREEN_METHOD_ID]
    method_version: Literal[CONTROL_VALVE_INSTALLED_METHOD_VERSION]
    screen_id: str = Field(min_length=2, max_length=160)
    candidate: TraceableInstalledValveCandidate
    minimum_case: ControlValveOperatingPointInput
    normal_case: ControlValveOperatingPointInput
    maximum_case: ControlValveOperatingPointInput
    candidate_binding_confirmed: StrictBool
    candidate_binding_source_reference: str = Field(min_length=3, max_length=500)

    @field_validator(
        "screen_id",
        "candidate_binding_source_reference",
        mode="before",
    )
    @classmethod
    def reject_padded_traceability_text(cls, value: object) -> object:
        if not isinstance(value, str) or value != value.strip():
            raise ValueError("installed traceability text must not be padded")
        return value

    @model_validator(mode="after")
    def validate_installed_contract(self) -> InstalledControlValveExecutionRequest:
        points = (self.minimum_case, self.normal_case, self.maximum_case)
        inputs = tuple(point.sizing_input for point in points)
        if len({item.case_id for item in inputs}) != 3:
            raise ValueError("minimum, normal, and maximum case IDs must be unique")
        if len({type(item) for item in inputs}) != 1:
            raise ValueError("all installed cases must use one sizing-input kind")

        if isinstance(inputs[0], LiquidControlValveSizingInput):
            flows = tuple(item.actual_volumetric_flow_m3_h for item in inputs)
            bases = tuple(item.factors.installation_basis for item in inputs)
            if len(set(bases)) != 1:
                raise ValueError("liquid cases must use one installation basis")
        else:
            flows = tuple(item.mass_flow_kg_h for item in inputs)
            identities = tuple(item.properties.fluid_identity for item in inputs)
            phases = tuple(item.properties.fluid_phase for item in inputs)
            bases = tuple(item.factors.installation_basis for item in inputs)
            contexts = tuple(
                (
                    item.factors.candidate_id,
                    item.factors.trim_id,
                    item.factors.installation_context_id,
                    item.factors.flow_direction,
                )
                for item in inputs
            )
            if (
                len(set(identities)) != 1
                or len(set(phases)) != 1
                or len(set(bases)) != 1
                or len(set(contexts)) != 1
            ):
                raise ValueError(
                    "compressible cases must share fluid, phase, basis, and factor context"
                )
            expected_context = (
                self.candidate.candidate_id,
                self.candidate.trim_id,
                self.candidate.installation_context_id,
                self.candidate.flow_direction,
            )
            if contexts[0] != expected_context:
                raise ValueError(
                    "compressible factors do not bind the supplied candidate"
                )

        if not flows[0] < flows[1] < flows[2]:
            raise ValueError("minimum, normal, and maximum flow must increase strictly")
        if not self.candidate_binding_confirmed:
            raise ValueError("candidate binding must be explicitly confirmed")
        if any(
            len(value) > 160
            for value in (
                self.candidate.candidate_id,
                self.candidate.trim_id,
                self.candidate.installation_context_id,
            )
        ):
            raise ValueError("candidate identifiers exceed the workflow limit")
        if any(
            not MIN_PUBLIC_CAPACITY_CV <= point.available_cv <= MAX_PUBLIC_CAPACITY_CV
            for point in self.candidate.capacity_curve
        ):
            raise ValueError("candidate capacity exceeds the workflow bounds")
        if not (
            1.0
            < self.candidate.declared_inherent_rangeability
            <= MAX_PUBLIC_CAPACITY_CV
        ):
            raise ValueError("candidate rangeability exceeds the workflow bounds")

        for point in points:
            state = point.downstream_acoustic_state
            if state is None:
                continue
            expected = (
                point.sizing_input.case_id,
                self.candidate.candidate_id,
                self.candidate.trim_id,
                self.candidate.flow_direction,
                self.candidate.installation_context_id,
            )
            actual = (
                state.sizing_case_id,
                state.candidate_id,
                state.trim_id,
                state.flow_direction,
                state.installation_context_id,
            )
            if actual != expected:
                raise ValueError(
                    "acoustic state does not bind the exact case and candidate"
                )
        return self


ControlValveExecutionRequest: TypeAlias = Annotated[
    LiquidControlValveExecutionRequest
    | CompressibleControlValveExecutionRequest
    | InstalledControlValveExecutionRequest,
    Field(discriminator="operation"),
]
CONTROL_VALVE_REQUEST_ADAPTER: Final = TypeAdapter(ControlValveExecutionRequest)


def installed_sizing_inputs(
    request: InstalledControlValveExecutionRequest,
) -> tuple[ControlValveSizingInput, ...]:
    """Return the only permitted minimum/normal/maximum sizing order."""

    return (
        request.minimum_case.sizing_input,
        request.normal_case.sizing_input,
        request.maximum_case.sizing_input,
    )


def build_installed_screen_request(
    request: InstalledControlValveExecutionRequest,
) -> InstalledControlValveScreenRequest:
    """Build the Step 101 request in one canonical operating-case order."""

    points = (
        (InstalledCaseRole.MINIMUM, request.minimum_case),
        (InstalledCaseRole.NORMAL, request.normal_case),
        (InstalledCaseRole.MAXIMUM, request.maximum_case),
    )
    return InstalledControlValveScreenRequest(
        screen_id=request.screen_id,
        candidate=request.candidate,
        operating_cases=tuple(
            InstalledOperatingCase(
                role=role,
                sizing_case_id=point.sizing_input.case_id,
                downstream_acoustic_state=point.downstream_acoustic_state,
            )
            for role, point in points
        ),
        candidate_binding_confirmed=request.candidate_binding_confirmed,
        candidate_binding_source_reference=(request.candidate_binding_source_reference),
    )


class ControlValveMethodCatalogueEntry(CalculationModel):
    operation: ControlValveOperation
    method_id: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]+$", max_length=160)
    method_version: str = Field(pattern=r"^\d+\.\d+\.\d+$", max_length=32)
    title: str = Field(min_length=3, max_length=240)
    implementation_name: str = Field(pattern=r"^[a-z][a-z0-9_]+$", max_length=160)
    input_model_name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9]+$", max_length=160)
    result_model_name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9]+$", max_length=160)
    knowledge_source_ids: tuple[str, ...] = Field(default=(), max_length=8)
    executable: Literal[True] = True
    lifecycle_status: Literal["approved"] = "approved"
    knowledge_links_are_inert: Literal[True] = True
    manufacturer_factors_derived: Literal[False] = False
    manufacturer_selection_performed: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False


class ControlValveKnowledgeLink(CalculationModel):
    source_id: str = Field(pattern=r"^official\.[a-z0-9.-]+$", max_length=120)
    owner: Literal["IEC"] = "IEC"
    title: str = Field(min_length=3, max_length=240)
    public_url: str = Field(
        pattern=r"^https://webstore\.iec\.ch/", max_length=500
    )
    reviewed_on: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    usage_boundary: str = Field(min_length=20, max_length=1_500)
    retrieval_mode: Literal["inert_metadata_only"] = "inert_metadata_only"
    network_access_performed: Literal[False] = False
    approved_as_factor_source: Literal[False] = False
    executable: Literal[False] = False
    conformity_evidence: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False


CONTROL_VALVE_API_CATALOGUE: Final = (
    ControlValveMethodCatalogueEntry(
        operation=ControlValveOperation.LIQUID_SIZING,
        method_id=LIQUID_CONTROL_VALVE_SIZING_METHOD_ID,
        method_version=LIQUID_CONTROL_VALVE_SIZING_METHOD_VERSION,
        title="Preliminary liquid Cv/Kv sizing with supplied factors",
        implementation_name="size_liquid_control_valve",
        input_model_name="LiquidControlValveExecutionRequest",
        result_model_name="LiquidControlValveSizingResult",
        knowledge_source_ids=("official.iec.60534-2-1",),
    ),
    ControlValveMethodCatalogueEntry(
        operation=ControlValveOperation.COMPRESSIBLE_SIZING,
        method_id=COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_ID,
        method_version=COMPRESSIBLE_CONTROL_VALVE_SIZING_METHOD_VERSION,
        title="Preliminary gas, vapour, and eligible-steam Cv/Kv sizing",
        implementation_name="size_compressible_control_valve",
        input_model_name="CompressibleControlValveExecutionRequest",
        result_model_name="CompressibleControlValveSizingResult",
        knowledge_source_ids=("official.iec.60534-2-1",),
    ),
    ControlValveMethodCatalogueEntry(
        operation=ControlValveOperation.INSTALLED_SCREEN,
        method_id=INSTALLED_CONTROL_VALVE_SCREEN_METHOD_ID,
        method_version=CONTROL_VALVE_INSTALLED_METHOD_VERSION,
        title="Installed minimum, normal, and maximum candidate screen",
        implementation_name="evaluate_installed_control_valve_scenarios",
        input_model_name="InstalledControlValveExecutionRequest",
        result_model_name="InstalledControlValveScreenResult",
        knowledge_source_ids=(
            "official.iec.60534-2-4",
            "official.iec.60534-8-3",
        ),
    ),
)
CONTROL_VALVE_API_REGISTRY: Final = MappingProxyType(
    {entry.operation: entry for entry in CONTROL_VALVE_API_CATALOGUE}
)
CONTROL_VALVE_KNOWLEDGE_LINKS: Final = (
    ControlValveKnowledgeLink(
        source_id="official.iec.60534-2-1",
        title="IEC 60534-2-1 control-valve sizing catalogue metadata",
        public_url="https://webstore.iec.ch/en/publication/2461",
        reviewed_on="2026-08-01",
        usage_boundary=(
            "Public catalogue metadata only; it does not provide executable "
            "standard text, tables, factor derivation, or conformity evidence."
        ),
    ),
    ControlValveKnowledgeLink(
        source_id="official.iec.60534-2-4",
        title="IEC 60534-2-4 inherent flow characteristics catalogue metadata",
        public_url="https://webstore.iec.ch/en/publication/2463",
        reviewed_on="2026-08-01",
        usage_boundary=(
            "Public catalogue metadata only; no protected characteristic, "
            "tolerance, or rangeability content is executable."
        ),
    ),
    ControlValveKnowledgeLink(
        source_id="official.iec.60534-8-3",
        title="IEC 60534-8-3 aerodynamic noise catalogue metadata",
        public_url="https://webstore.iec.ch/en/publication/2474",
        reviewed_on="2026-08-01",
        usage_boundary=(
            "Public catalogue metadata only; no sound-pressure-level method, "
            "noise guarantee, or conformity assessment is executable."
        ),
    ),
)
if len(CONTROL_VALVE_API_REGISTRY) != len(CONTROL_VALVE_API_CATALOGUE):
    raise RuntimeError("duplicate control-valve API operation registration")
_KNOWN_KNOWLEDGE_IDS = frozenset(
    item.source_id for item in CONTROL_VALVE_KNOWLEDGE_LINKS
)
if any(
    not set(entry.knowledge_source_ids).issubset(_KNOWN_KNOWLEDGE_IDS)
    for entry in CONTROL_VALVE_API_CATALOGUE
):
    raise RuntimeError("control-valve method references unknown knowledge metadata")


class ControlValveExecutionTrace(CalculationModel):
    workflow_version: Literal[CONTROL_VALVE_WORKFLOW_VERSION] = (
        CONTROL_VALVE_WORKFLOW_VERSION
    )
    calculator_pack_version: Literal[CONTROL_VALVE_CALCULATOR_PACK_VERSION] = (
        CONTROL_VALVE_CALCULATOR_PACK_VERSION
    )
    operation: ControlValveOperation
    method_id: str
    method_version: str
    calculator_version: str
    implementation_name: str
    normalized_input_fingerprint: FingerprintText
    result_fingerprint: FingerprintText
    attempt_fingerprint: FingerprintText
    knowledge_source_ids: tuple[str, ...] = Field(default=(), max_length=8)
    canonicalization: Literal["json-sort-keys-utf8-sha256-v1"] = (
        "json-sort-keys-utf8-sha256-v1"
    )
    standards_adapter_execution_count: Literal[0] = 0
    manufacturer_factors_derived: Literal[False] = False
    manufacturer_selection_performed: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False


def _canonical_value(value: object) -> object:
    if isinstance(value, float) and value == 0.0:
        return 0.0
    if isinstance(value, dict):
        return {key: _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    return value


def fingerprint_control_valve_workflow_payload(value: object) -> str:
    payload = json.dumps(
        _canonical_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return sha256(payload).hexdigest()


def validate_control_valve_execution_request(
    value: object,
) -> ControlValveExecutionRequest:
    if isinstance(value, CalculationModel):
        value = value.model_dump(mode="python", round_trip=True, warnings="error")
    return CONTROL_VALVE_REQUEST_ADAPTER.validate_python(value)


def build_control_valve_input_fingerprint(
    request: ControlValveExecutionRequest,
) -> str:
    normalized = validate_control_valve_execution_request(request)
    return fingerprint_control_valve_workflow_payload(
        {
            "schema": "engineer4me.control-valve.workflow-input.v1",
            "workflow_version": CONTROL_VALVE_WORKFLOW_VERSION,
            "calculator_pack_version": CONTROL_VALVE_CALCULATOR_PACK_VERSION,
            "request": normalized.model_dump(
                mode="json", round_trip=True, warnings="error"
            ),
        }
    )


def build_control_valve_result_fingerprint(
    request: ControlValveExecutionRequest,
    result: ControlValveResult,
    knowledge_source_ids: tuple[str, ...],
) -> str:
    normalized = validate_control_valve_execution_request(request)
    metadata = CONTROL_VALVE_API_REGISTRY[ControlValveOperation(normalized.operation)]
    return fingerprint_control_valve_workflow_payload(
        {
            "schema": "engineer4me.control-valve.workflow-result.v1",
            "workflow_version": CONTROL_VALVE_WORKFLOW_VERSION,
            "calculator_pack_version": CONTROL_VALVE_CALCULATOR_PACK_VERSION,
            "operation": normalized.operation,
            "method_id": normalized.method_id,
            "method_version": normalized.method_version,
            "implementation_name": metadata.implementation_name,
            "normalized_input_fingerprint": build_control_valve_input_fingerprint(
                normalized
            ),
            "knowledge_source_ids": knowledge_source_ids,
            "result": result.model_dump(mode="json", round_trip=True, warnings="error"),
        }
    )


def build_control_valve_attempt_fingerprint(
    input_fingerprint: str,
    result_fingerprint: str,
) -> str:
    return fingerprint_control_valve_workflow_payload(
        {
            "schema": "engineer4me.control-valve.workflow-attempt.v1",
            "workflow_version": CONTROL_VALVE_WORKFLOW_VERSION,
            "calculator_pack_version": CONTROL_VALVE_CALCULATOR_PACK_VERSION,
            "input_fingerprint": input_fingerprint,
            "result_fingerprint": result_fingerprint,
            "status": "completed",
        }
    )


_RESULT_TYPE_BY_OPERATION: Final = MappingProxyType(
    {
        ControlValveOperation.LIQUID_SIZING: LiquidControlValveSizingResult,
        ControlValveOperation.COMPRESSIBLE_SIZING: (
            CompressibleControlValveSizingResult
        ),
        ControlValveOperation.INSTALLED_SCREEN: InstalledControlValveScreenResult,
    }
)
_CALCULATOR_VERSION_BY_OPERATION: Final = MappingProxyType(
    {
        ControlValveOperation.LIQUID_SIZING: CONTROL_VALVE_CALCULATORS_VERSION,
        ControlValveOperation.COMPRESSIBLE_SIZING: (
            COMPRESSIBLE_CONTROL_VALVE_CALCULATORS_VERSION
        ),
        ControlValveOperation.INSTALLED_SCREEN: (
            CONTROL_VALVE_INSTALLED_CALCULATORS_VERSION
        ),
    }
)


class ControlValveSafetySeverity(StrEnum):
    BLOCKING = "blocking"
    HIGH_PRIORITY = "high_priority"
    REVIEW_REQUIRED = "review_required"


class ControlValveSafetyFinding(CalculationModel):
    severity: ControlValveSafetySeverity
    code: str = Field(pattern=r"^[a-z][a-z0-9_]+$", max_length=120)
    case_role: InstalledCaseRole | None = None
    case_id: str | None = Field(default=None, max_length=160)
    summary: str = Field(min_length=10, max_length=500)
    required_action: str = Field(min_length=10, max_length=1_000)
    safety_first: Literal[True] = True
    project_approval_granted: Literal[False] = False

    @model_validator(mode="after")
    def validate_case_identity(self) -> ControlValveSafetyFinding:
        if (self.case_role is None) != (self.case_id is None):
            raise ValueError(
                "finding case role and identifier must be supplied together"
            )
        return self


class ControlValveDesignDisposition(StrEnum):
    BLOCKED = "blocked"
    PRELIMINARY_SCREEN_COMPLETE_REVIEW_REQUIRED = (
        "preliminary_screen_complete_review_required"
    )


def _finding(
    severity: ControlValveSafetySeverity,
    code: str,
    summary: str,
    action: str,
    *,
    case_role: InstalledCaseRole | None = None,
    case_id: str | None = None,
) -> ControlValveSafetyFinding:
    return ControlValveSafetyFinding(
        severity=severity,
        code=code,
        case_role=case_role,
        case_id=case_id,
        summary=summary,
        required_action=action,
    )


class ControlValveExecutionOutcome(CalculationModel):
    safety_findings: tuple[ControlValveSafetyFinding, ...] = Field(
        default=(), max_length=64
    )
    disposition: ControlValveDesignDisposition | None = None
    normalized_request: ControlValveExecutionRequest
    result: ControlValveResult
    trace: ControlValveExecutionTrace
    candidate_identity_origin: Literal["not_applicable", "caller_supplied"]
    selection_ready: Literal[False] = False
    independent_review_required: Literal[True] = True
    manufacturer_selection_performed: Literal[False] = False
    exact_product_selected: Literal[False] = False
    sound_pressure_level_predicted: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False

    @model_validator(mode="after")
    def validate_trace_binding(self) -> ControlValveExecutionOutcome:
        request = validate_control_valve_execution_request(self.normalized_request)
        operation = ControlValveOperation(request.operation)
        metadata = CONTROL_VALVE_API_REGISTRY[operation]
        if not isinstance(self.result, _RESULT_TYPE_BY_OPERATION[operation]):
            raise TypeError("control-valve result type does not match the operation")
        trace = self.trace
        if (
            trace.operation is not operation
            or trace.calculator_pack_version != CONTROL_VALVE_CALCULATOR_PACK_VERSION
            or trace.method_id != metadata.method_id
            or trace.method_version != metadata.method_version
            or trace.calculator_version != _CALCULATOR_VERSION_BY_OPERATION[operation]
            or trace.implementation_name != metadata.implementation_name
            or trace.knowledge_source_ids != metadata.knowledge_source_ids
        ):
            raise ValueError("execution trace does not match the exact operation")

        if isinstance(request, InstalledControlValveExecutionRequest):
            result = self.result
            if not isinstance(result, InstalledControlValveScreenResult):
                raise TypeError("installed request requires an installed result")
            expected_screen = build_installed_screen_request(request)
            if result.normalized_request != expected_screen:
                raise ValueError(
                    "installed result does not match the canonical request"
                )
            expected_inputs = installed_sizing_inputs(request)
            actual_inputs = tuple(
                item.normalized_input for item in result.normalized_sizing_results
            )
            if actual_inputs != expected_inputs:
                raise ValueError("installed result does not match server sizing inputs")

            expected_findings = derive_control_valve_safety_findings(result)
            expected_disposition = derive_control_valve_design_disposition(
                expected_findings
            )
            if (
                self.safety_findings != expected_findings
                or self.disposition is not expected_disposition
                or self.candidate_identity_origin != "caller_supplied"
            ):
                raise ValueError("installed execution safety contract is stale")
        else:
            if self.safety_findings or self.disposition is not None:
                raise ValueError("standalone sizing cannot carry installed findings")
            if isinstance(request, LiquidControlValveExecutionRequest):
                result = self.result
                if not isinstance(result, LiquidControlValveSizingResult):
                    raise TypeError("liquid request requires a liquid result")
                if result.normalized_input != request.sizing_input:
                    raise ValueError(
                        "standalone result does not match the canonical request"
                    )
                if self.candidate_identity_origin != "not_applicable":
                    raise ValueError("liquid sizing has no candidate identity")
            else:
                result = self.result
                if not isinstance(result, CompressibleControlValveSizingResult):
                    raise TypeError(
                        "compressible request requires a compressible result"
                    )
                if result.normalized_input != request.sizing_input:
                    raise ValueError(
                        "standalone result does not match the canonical request"
                    )
                if self.candidate_identity_origin != "caller_supplied":
                    raise ValueError(
                        "compressible sizing factors require caller identity"
                    )

        input_fingerprint = build_control_valve_input_fingerprint(request)
        result_fingerprint = build_control_valve_result_fingerprint(
            request,
            self.result,
            metadata.knowledge_source_ids,
        )
        if (
            trace.normalized_input_fingerprint != input_fingerprint
            or trace.result_fingerprint != result_fingerprint
            or trace.attempt_fingerprint
            != build_control_valve_attempt_fingerprint(
                input_fingerprint,
                result_fingerprint,
            )
        ):
            raise ValueError("control-valve workflow fingerprints are stale")
        return self


def derive_control_valve_safety_findings(
    result: InstalledControlValveScreenResult,
) -> tuple[ControlValveSafetyFinding, ...]:
    """Derive ordered findings from typed fields, never warning text."""

    sizing_by_id = {
        item.normalized_input.case_id: item for item in result.normalized_sizing_results
    }
    findings: list[ControlValveSafetyFinding] = []
    for case in result.case_results:
        evidence = case.evidence
        case_fields = {
            "case_role": evidence.role,
            "case_id": evidence.case_id,
        }
        sizing = sizing_by_id[evidence.case_id]
        if evidence.choked:
            findings.append(
                _finding(
                    ControlValveSafetySeverity.HIGH_PRIORITY,
                    "choked_flow_review",
                    "The operating case is classified as choked flow.",
                    "Verify the pressure regime, trim duty, vibration, erosion, and manufacturer limits.",
                    **case_fields,
                )
            )
        if isinstance(sizing, LiquidControlValveSizingResult):
            if sizing.regime.flashing:
                findings.append(
                    _finding(
                        ControlValveSafetySeverity.HIGH_PRIORITY,
                        "liquid_flashing_present",
                        "The liquid operating case indicates flashing.",
                        "Perform an approved flashing, erosion, outlet piping, and material review.",
                        **case_fields,
                    )
                )
            elif (
                sizing.regime.cavitation_status
                is LiquidCavitationStatus.CHOKED_CAVITATION_INDICATED
            ):
                findings.append(
                    _finding(
                        ControlValveSafetySeverity.HIGH_PRIORITY,
                        "liquid_cavitation_review",
                        "The liquid operating case indicates choked cavitation risk.",
                        "Verify cavitation duty with approved manufacturer and project evidence.",
                        **case_fields,
                    )
                )
            if sizing.velocity.velocity_status is LiquidVelocityStatus.NOT_ASSESSED:
                findings.append(
                    _finding(
                        ControlValveSafetySeverity.REVIEW_REQUIRED,
                        "liquid_velocity_limit_missing",
                        "No traceable liquid outlet-velocity limit was assessed.",
                        "Supply and verify the applicable project or manufacturer velocity limit.",
                        **case_fields,
                    )
                )
            elif sizing.velocity.velocity_status in {
                LiquidVelocityStatus.EXCEEDS_SUPPLIED_LIMIT,
                LiquidVelocityStatus.SUPPRESSED_FLASHING,
            }:
                findings.append(
                    _finding(
                        ControlValveSafetySeverity.HIGH_PRIORITY,
                        "liquid_velocity_review",
                        "The liquid outlet-velocity screen requires high-priority review.",
                        "Resolve the velocity or flashing condition before candidate approval.",
                        **case_fields,
                    )
                )

        if case.capacity_curve_status is not CapacityCurveStatus.WITHIN_CURVE:
            findings.append(
                _finding(
                    ControlValveSafetySeverity.BLOCKING,
                    "capacity_outside_supplied_curve",
                    "Required capacity is outside the supplied candidate curve.",
                    "Reject or revise the candidate using controlled capacity evidence without extrapolation.",
                    **case_fields,
                )
            )
        elif not case.inverse_solution_verified:
            findings.append(
                _finding(
                    ControlValveSafetySeverity.BLOCKING,
                    "capacity_inverse_unverified",
                    "The travel inverse does not have an accepted residual proof.",
                    "Resolve the supplied curve or numerical evidence before candidate review continues.",
                    **case_fields,
                )
            )
        if case.travel_window_status is not TravelWindowStatus.WITHIN_SUPPLIED_WINDOW:
            findings.append(
                _finding(
                    ControlValveSafetySeverity.BLOCKING,
                    "travel_window_not_met",
                    "Required travel is outside the supplied controllable window.",
                    "Revise the candidate or operating envelope using traceable manufacturer evidence.",
                    **case_fields,
                )
            )
        if (
            case.factor_travel_coherence_status
            is FactorTravelCoherenceStatus.NOT_MACHINE_VERIFIABLE_LIQUID
        ):
            findings.append(
                _finding(
                    ControlValveSafetySeverity.BLOCKING,
                    "liquid_factor_binding_unverified",
                    "Liquid factors are not machine-bound to candidate travel in Step 100 evidence.",
                    "Obtain traceable candidate, trim, travel, direction, and installation factor binding.",
                    **case_fields,
                )
            )
        elif (
            case.factor_travel_coherence_status
            is not FactorTravelCoherenceStatus.MATCHED
        ):
            findings.append(
                _finding(
                    ControlValveSafetySeverity.BLOCKING,
                    "factor_travel_binding_failed",
                    "The supplied factor travel does not match the calculated candidate travel.",
                    "Resolve factor, curve, trim, direction, and installation-context coherence.",
                    **case_fields,
                )
            )

        noise = case.aerodynamic_noise
        if noise.downstream_bulk_mach is not None and noise.downstream_bulk_mach >= 1.0:
            findings.append(
                _finding(
                    ControlValveSafetySeverity.BLOCKING,
                    "downstream_sonic_or_supersonic",
                    "The calculated downstream bulk flow is sonic or supersonic.",
                    "Block candidate use and resolve the downstream gas-flow regime with approved engineering evidence.",
                    **case_fields,
                )
            )
        elif noise.priority is AerodynamicNoisePriority.HIGH_PRIORITY_REVIEW:
            findings.append(
                _finding(
                    ControlValveSafetySeverity.HIGH_PRIORITY,
                    "aerodynamic_noise_high_priority",
                    "The preliminary aerodynamic screen requires high-priority review.",
                    "Obtain an approved acoustic prediction and verify downstream piping limits.",
                    **case_fields,
                )
            )
        elif noise.priority is AerodynamicNoisePriority.NOT_ASSESSED:
            findings.append(
                _finding(
                    ControlValveSafetySeverity.HIGH_PRIORITY,
                    "acoustic_state_missing",
                    "Downstream acoustic-state evidence was not supplied for this case.",
                    "Supply traceable downstream density, sound speed, geometry, and applicable limits.",
                    **case_fields,
                )
            )
        elif noise.priority is AerodynamicNoisePriority.REVIEW_REQUIRED:
            findings.append(
                _finding(
                    ControlValveSafetySeverity.REVIEW_REQUIRED,
                    "aerodynamic_noise_review",
                    "The preliminary aerodynamic screen requires specialist review.",
                    "Complete an approved manufacturer acoustic assessment before final selection.",
                    **case_fields,
                )
            )

    if result.rangeability.status is RangeabilityStatus.EXCEEDS_SUPPLIED_RANGEABILITY:
        findings.append(
            _finding(
                ControlValveSafetySeverity.BLOCKING,
                "rangeability_not_met",
                "Required operating capacity ratio exceeds supplied rangeability.",
                "Revise the candidate or operating strategy using controlled rangeability evidence.",
            )
        )
    if not result.candidate_capacity_and_travel_screen_passed and not any(
        finding.severity is ControlValveSafetySeverity.BLOCKING for finding in findings
    ):
        findings.append(
            _finding(
                ControlValveSafetySeverity.BLOCKING,
                "candidate_screen_not_passed",
                "The candidate capacity and travel screen did not pass.",
                "Resolve all capacity, travel, factor, and rangeability findings before approval.",
            )
        )
    findings.append(
        _finding(
            ControlValveSafetySeverity.REVIEW_REQUIRED,
            "independent_engineering_review_required",
            "Every preliminary control-valve scenario requires independent review.",
            "A competent control-valve engineer must verify the complete project and manufacturer data set.",
        )
    )

    severity_rank = {
        ControlValveSafetySeverity.BLOCKING: 0,
        ControlValveSafetySeverity.HIGH_PRIORITY: 1,
        ControlValveSafetySeverity.REVIEW_REQUIRED: 2,
    }
    role_rank = {
        InstalledCaseRole.MINIMUM: 0,
        InstalledCaseRole.NORMAL: 1,
        InstalledCaseRole.MAXIMUM: 2,
        None: 3,
    }
    unique = {(finding.code, finding.case_id): finding for finding in findings}
    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (
                severity_rank[item.severity],
                role_rank[item.case_role],
                item.code,
            ),
        )
    )


def derive_control_valve_design_disposition(
    findings: tuple[ControlValveSafetyFinding, ...],
) -> ControlValveDesignDisposition:
    if any(
        finding.severity is ControlValveSafetySeverity.BLOCKING for finding in findings
    ):
        return ControlValveDesignDisposition.BLOCKED
    return ControlValveDesignDisposition.PRELIMINARY_SCREEN_COMPLETE_REVIEW_REQUIRED


class ControlValveDesignCaseRequest(CalculationModel):
    design_case_id: str = Field(
        min_length=2,
        max_length=160,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$",
    )
    revision: StrictInt = Field(ge=1, le=10_000)
    title: str = Field(min_length=3, max_length=240)
    service_description: str = Field(min_length=10, max_length=1_500)
    installed_execution_request: InstalledControlValveExecutionRequest


def build_control_valve_design_case_fingerprint(
    request: ControlValveDesignCaseRequest,
    calculation: ControlValveExecutionOutcome,
    findings: tuple[ControlValveSafetyFinding, ...],
    disposition: ControlValveDesignDisposition,
) -> str:
    return fingerprint_control_valve_workflow_payload(
        {
            "schema": "engineer4me.control-valve.design-case.v1",
            "workflow_version": CONTROL_VALVE_WORKFLOW_VERSION,
            "calculator_pack_version": CONTROL_VALVE_CALCULATOR_PACK_VERSION,
            "request": request.model_dump(
                mode="json", round_trip=True, warnings="error"
            ),
            "attempt_fingerprint": calculation.trace.attempt_fingerprint,
            "safety_findings": [
                finding.model_dump(mode="json", round_trip=True, warnings="error")
                for finding in findings
            ],
            "disposition": disposition,
        }
    )


class ControlValveDesignCaseOutcome(CalculationModel):
    """Safety-leading, vendor-neutral output for one stateless design case."""

    safety_findings: tuple[ControlValveSafetyFinding, ...] = Field(
        min_length=1, max_length=64
    )
    disposition: ControlValveDesignDisposition
    normalized_design_case: ControlValveDesignCaseRequest
    calculation: ControlValveExecutionOutcome
    design_case_fingerprint: FingerprintText
    candidate_identity_origin: Literal["caller_supplied"] = "caller_supplied"
    selection_ready: Literal[False] = False
    independent_review_required: Literal[True] = True
    manufacturer_selection_performed: Literal[False] = False
    manufacturer_declared_best: Literal[False] = False
    exact_product_selected: Literal[False] = False
    final_brand_selection: Literal["user_decision_required"] = "user_decision_required"
    approved_for_project_use: Literal[False] = False
    sound_pressure_level_predicted: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False

    @model_validator(mode="after")
    def validate_design_contract(self) -> ControlValveDesignCaseOutcome:
        if self.calculation.normalized_request != (
            self.normalized_design_case.installed_execution_request
        ):
            raise ValueError("design calculation does not bind the exact request")
        if not isinstance(self.calculation.result, InstalledControlValveScreenResult):
            raise TypeError("design case requires an installed-screen result")
        expected_findings = derive_control_valve_safety_findings(
            self.calculation.result
        )
        expected_disposition = derive_control_valve_design_disposition(
            expected_findings
        )
        if (
            self.safety_findings != expected_findings
            or self.disposition is not expected_disposition
        ):
            raise ValueError("design safety findings or disposition are stale")
        expected_fingerprint = build_control_valve_design_case_fingerprint(
            self.normalized_design_case,
            self.calculation,
            expected_findings,
            expected_disposition,
        )
        if self.design_case_fingerprint != expected_fingerprint:
            raise ValueError("control-valve design-case fingerprint is stale")
        return self


__all__ = [
    "CONTROL_VALVE_API_CATALOGUE",
    "CONTROL_VALVE_API_REGISTRY",
    "CONTROL_VALVE_CALCULATOR_PACK_VERSION",
    "CONTROL_VALVE_KNOWLEDGE_LINKS",
    "CONTROL_VALVE_REQUEST_ADAPTER",
    "CONTROL_VALVE_WORKFLOW_VERSION",
    "CompressibleControlValveExecutionRequest",
    "ControlValveDesignCaseOutcome",
    "ControlValveDesignCaseRequest",
    "ControlValveDesignDisposition",
    "ControlValveExecutionOutcome",
    "ControlValveExecutionRequest",
    "ControlValveExecutionTrace",
    "ControlValveKnowledgeLink",
    "ControlValveMethodCatalogueEntry",
    "ControlValveOperatingPointInput",
    "ControlValveOperation",
    "ControlValveResult",
    "ControlValveSafetyFinding",
    "ControlValveSafetySeverity",
    "ControlValveSizingInput",
    "InstalledControlValveExecutionRequest",
    "LiquidControlValveExecutionRequest",
    "build_control_valve_attempt_fingerprint",
    "build_control_valve_design_case_fingerprint",
    "build_control_valve_input_fingerprint",
    "build_control_valve_result_fingerprint",
    "build_installed_screen_request",
    "derive_control_valve_design_disposition",
    "derive_control_valve_safety_findings",
    "fingerprint_control_valve_workflow_payload",
    "installed_sizing_inputs",
    "validate_control_valve_execution_request",
]

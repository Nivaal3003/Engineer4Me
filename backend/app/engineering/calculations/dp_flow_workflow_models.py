"""Typed Step 99 workflow contracts for differential-pressure flow.

The module wraps the Step 97-98 supplied-coefficient calculators without
adding a standards correlation, persistent store, network lookup, or OEM
selection.  Every execution request names one exact operation and version;
all traces are deterministic SHA-256 fingerprints over canonical JSON.
"""

from __future__ import annotations

from enum import StrEnum
from hashlib import sha256
import json
from math import isfinite
from types import MappingProxyType
from typing import Annotated, Final, Literal, TypeAlias

from pydantic import Field, StrictInt, TypeAdapter, field_validator, model_validator

from app.engineering.calculations.dp_flow import AveragingPitotFlowResult
from app.engineering.calculations.dp_flow import BoreSolverResult
from app.engineering.calculations.dp_flow import CircularRestrictionFlowResult
from app.engineering.calculations.dp_flow import DPFlowUncertaintyResult
from app.engineering.calculations.dp_flow import DPTransmitterRangeScreenResult
from app.engineering.calculations.dp_flow import DP_FLOW_CALCULATORS_VERSION
from app.engineering.calculations.dp_flow import DP_FLOW_METHOD_VERSION
from app.engineering.calculations.dp_flow import DP_FLOW_UNCERTAINTY_METHOD_ID
from app.engineering.calculations.dp_flow import DP_FLOW_UNCERTAINTY_METHOD_VERSION
from app.engineering.calculations.dp_flow import DP_TRANSMITTER_RANGE_METHOD_ID
from app.engineering.calculations.dp_flow import DP_TRANSMITTER_RANGE_METHOD_VERSION
from app.engineering.calculations.dp_flow import FlowingFluidProperties
from app.engineering.calculations.dp_flow import GENERIC_AVERAGING_PITOT_METHOD_ID
from app.engineering.calculations.dp_flow import GENERIC_AVERAGING_PITOT_METHOD_VERSION
from app.engineering.calculations.dp_flow import GENERIC_NOZZLE_METHOD_ID
from app.engineering.calculations.dp_flow import GENERIC_NOZZLE_METHOD_VERSION
from app.engineering.calculations.dp_flow import GENERIC_ORIFICE_METHOD_ID
from app.engineering.calculations.dp_flow import GENERIC_VENTURI_NOZZLE_METHOD_ID
from app.engineering.calculations.dp_flow import GENERIC_VENTURI_NOZZLE_METHOD_VERSION
from app.engineering.calculations.dp_flow import GENERIC_VENTURI_TUBE_METHOD_ID
from app.engineering.calculations.dp_flow import GENERIC_VENTURI_TUBE_METHOD_VERSION
from app.engineering.calculations.dp_flow import OrificeFlowResult
from app.engineering.calculations.dp_flow import PERMANENT_PRESSURE_LOSS_METHOD_ID
from app.engineering.calculations.dp_flow import PERMANENT_PRESSURE_LOSS_METHOD_VERSION
from app.engineering.calculations.dp_flow import PermanentPressureLossResult
from app.engineering.calculations.dp_flow import RelativeUncertaintyComponent
from app.engineering.calculations.dp_flow import TraceableCoefficient
from app.engineering.calculations.models import CalculationModel, FingerprintText
from app.engineering.design.dp_flow_application_models import DPFlowApplicationAssessment
from app.engineering.design.dp_flow_application_models import DPFlowApplicationRequest
from app.engineering.design.dp_flow_application_wizard import OFFICIAL_SOURCES


DP_FLOW_WORKFLOW_VERSION: Final = "1.0.0"
ORIFICE_BORE_SOLVER_METHOD_ID: Final = (
    "flow.dp.generic-orifice.solve-bore.supplied-coefficients"
)
ORIFICE_BORE_SOLVER_METHOD_VERSION: Final = "1.0.0"


class DPFlowOperation(StrEnum):
    GENERIC_ORIFICE = "generic_orifice"
    ORIFICE_BORE_SOLVER = "orifice_bore_solver"
    GENERIC_NOZZLE = "generic_nozzle"
    GENERIC_VENTURI_NOZZLE = "generic_venturi_nozzle"
    GENERIC_VENTURI_TUBE = "generic_venturi_tube"
    GENERIC_AVERAGING_PITOT = "generic_averaging_pitot"
    TRANSMITTER_RANGE = "transmitter_range"
    PERMANENT_PRESSURE_LOSS = "permanent_pressure_loss"
    RELATIVE_UNCERTAINTY = "relative_uncertainty"


def _finite_real(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("numeric inputs must be explicit finite real values")
    try:
        normalized = float(value)
    except (OverflowError, TypeError, ValueError) as error:
        raise ValueError("numeric inputs must be explicit finite real values") from error
    if not isfinite(normalized):
        raise ValueError("numeric inputs must be explicit finite real values")
    return 0.0 if normalized == 0.0 else normalized


def _bounded_fluid(value: FlowingFluidProperties) -> FlowingFluidProperties:
    """Constrain public workflow properties to a numerically safe domain."""

    if not (
        1.0e-12 <= value.density_kg_m3 <= 1.0e7
        and 1.0e-18 <= value.dynamic_viscosity_pa_s <= 1.0e6
        and 1.0 <= value.pressure_absolute_pa <= 1.0e12
        and 1.0 <= value.temperature_k <= 1.0e6
    ):
        raise ValueError("flowing properties exceed the bounded workflow domain")
    return value


def _bounded_coefficient(value: TraceableCoefficient) -> TraceableCoefficient:
    """Reject coefficients that could overflow the public workflow kernel."""

    if value.value > 1.0e6:
        raise ValueError("coefficient exceeds the bounded workflow domain")
    return value


class _RequestBase(CalculationModel):
    method_id: str
    method_version: str


class GenericOrificeFlowRequest(_RequestBase):
    operation: Literal["generic_orifice"]
    method_id: Literal[GENERIC_ORIFICE_METHOD_ID]
    method_version: Literal[DP_FLOW_METHOD_VERSION]
    pipe_inside_diameter_m: float = Field(ge=1.0e-9, le=20.0)
    bore_diameter_m: float = Field(ge=1.0e-9, le=20.0)
    differential_pressure_pa: float = Field(ge=1.0e-9, le=1.0e12)
    fluid: FlowingFluidProperties
    discharge_coefficient: TraceableCoefficient
    expansibility_factor: TraceableCoefficient

    _numbers = field_validator(
        "pipe_inside_diameter_m", "bore_diameter_m", "differential_pressure_pa",
        mode="before",
    )(_finite_real)
    _fluid = field_validator("fluid")(_bounded_fluid)
    _coefficients = field_validator(
        "discharge_coefficient",
        "expansibility_factor",
    )(_bounded_coefficient)


class OrificeBoreSolveRequest(_RequestBase):
    operation: Literal["orifice_bore_solver"]
    method_id: Literal[ORIFICE_BORE_SOLVER_METHOD_ID]
    method_version: Literal[ORIFICE_BORE_SOLVER_METHOD_VERSION]
    target_mass_flow_kg_s: float = Field(ge=1.0e-12, le=1.0e12)
    pipe_inside_diameter_m: float = Field(ge=1.0e-9, le=20.0)
    differential_pressure_pa: float = Field(ge=1.0e-9, le=1.0e12)
    fluid: FlowingFluidProperties
    discharge_coefficient: TraceableCoefficient
    expansibility_factor: TraceableCoefficient
    minimum_bore_diameter_m: float = Field(ge=1.0e-9, le=20.0)
    maximum_bore_diameter_m: float = Field(ge=1.0e-9, le=20.0)
    relative_tolerance: float = Field(default=1.0e-9, gt=0.0, lt=1.0)
    maximum_iterations: StrictInt = Field(default=96, ge=1, le=128)

    _numbers = field_validator(
        "target_mass_flow_kg_s", "pipe_inside_diameter_m",
        "differential_pressure_pa", "minimum_bore_diameter_m",
        "maximum_bore_diameter_m", "relative_tolerance", mode="before",
    )(_finite_real)
    _fluid = field_validator("fluid")(_bounded_fluid)
    _coefficients = field_validator(
        "discharge_coefficient",
        "expansibility_factor",
    )(_bounded_coefficient)


class _CircularFlowRequest(_RequestBase):
    pipe_inside_diameter_m: float = Field(ge=1.0e-9, le=20.0)
    throat_diameter_m: float = Field(ge=1.0e-9, le=20.0)
    differential_pressure_pa: float = Field(ge=1.0e-9, le=1.0e12)
    fluid: FlowingFluidProperties
    discharge_coefficient: TraceableCoefficient
    expansibility_factor: TraceableCoefficient

    _numbers = field_validator(
        "pipe_inside_diameter_m", "throat_diameter_m", "differential_pressure_pa",
        mode="before",
    )(_finite_real)
    _fluid = field_validator("fluid")(_bounded_fluid)
    _coefficients = field_validator(
        "discharge_coefficient",
        "expansibility_factor",
    )(_bounded_coefficient)


class GenericNozzleFlowRequest(_CircularFlowRequest):
    operation: Literal["generic_nozzle"]
    method_id: Literal[GENERIC_NOZZLE_METHOD_ID]
    method_version: Literal[GENERIC_NOZZLE_METHOD_VERSION]


class GenericVenturiNozzleFlowRequest(_CircularFlowRequest):
    operation: Literal["generic_venturi_nozzle"]
    method_id: Literal[GENERIC_VENTURI_NOZZLE_METHOD_ID]
    method_version: Literal[GENERIC_VENTURI_NOZZLE_METHOD_VERSION]


class GenericVenturiTubeFlowRequest(_CircularFlowRequest):
    operation: Literal["generic_venturi_tube"]
    method_id: Literal[GENERIC_VENTURI_TUBE_METHOD_ID]
    method_version: Literal[GENERIC_VENTURI_TUBE_METHOD_VERSION]


class GenericAveragingPitotFlowRequest(_RequestBase):
    operation: Literal["generic_averaging_pitot"]
    method_id: Literal[GENERIC_AVERAGING_PITOT_METHOD_ID]
    method_version: Literal[GENERIC_AVERAGING_PITOT_METHOD_VERSION]
    pipe_inside_diameter_m: float = Field(ge=1.0e-9, le=20.0)
    differential_pressure_pa: float = Field(ge=1.0e-9, le=1.0e12)
    fluid: FlowingFluidProperties
    meter_coefficient: TraceableCoefficient
    expansibility_factor: TraceableCoefficient

    _numbers = field_validator(
        "pipe_inside_diameter_m", "differential_pressure_pa", mode="before",
    )(_finite_real)
    _fluid = field_validator("fluid")(_bounded_fluid)
    _coefficients = field_validator(
        "meter_coefficient",
        "expansibility_factor",
    )(_bounded_coefficient)


class DPTransmitterRangeRequest(_RequestBase):
    operation: Literal["transmitter_range"]
    method_id: Literal[DP_TRANSMITTER_RANGE_METHOD_ID]
    method_version: Literal[DP_TRANSMITTER_RANGE_METHOD_VERSION]
    minimum_dp_pa: float = Field(ge=0.0, le=1.0e12)
    normal_dp_pa: float = Field(ge=0.0, le=1.0e12)
    maximum_dp_pa: float = Field(gt=0.0, le=1.0e12)
    configured_lrv_pa: float = Field(ge=-1.0e12, le=1.0e12)
    configured_urv_pa: float = Field(ge=-1.0e12, le=1.0e12)
    sensor_lrl_pa: float = Field(ge=-1.0e12, le=1.0e12)
    sensor_url_pa: float = Field(ge=-1.0e12, le=1.0e12)
    minimum_required_dp_fraction_of_span: float = Field(ge=0.0, le=1.0)

    _numbers = field_validator(
        "minimum_dp_pa", "normal_dp_pa", "maximum_dp_pa", "configured_lrv_pa",
        "configured_urv_pa", "sensor_lrl_pa", "sensor_url_pa",
        "minimum_required_dp_fraction_of_span", mode="before",
    )(_finite_real)


class PermanentPressureLossRequest(_RequestBase):
    operation: Literal["permanent_pressure_loss"]
    method_id: Literal[PERMANENT_PRESSURE_LOSS_METHOD_ID]
    method_version: Literal[PERMANENT_PRESSURE_LOSS_METHOD_VERSION]
    measured_differential_pressure_pa: float = Field(ge=0.0, le=1.0e12)
    permanent_loss_ratio: TraceableCoefficient

    _numbers = field_validator("measured_differential_pressure_pa", mode="before")(_finite_real)
    _coefficient = field_validator("permanent_loss_ratio")(_bounded_coefficient)


class DPFlowUncertaintyRequest(_RequestBase):
    operation: Literal["relative_uncertainty"]
    method_id: Literal[DP_FLOW_UNCERTAINTY_METHOD_ID]
    method_version: Literal[DP_FLOW_UNCERTAINTY_METHOD_VERSION]
    components: tuple[RelativeUncertaintyComponent, ...] = Field(min_length=1, max_length=64)
    coverage_factor: float = Field(default=2.0, ge=1.0, le=5.0)

    _numbers = field_validator("coverage_factor", mode="before")(_finite_real)

    @model_validator(mode="after")
    def validate_component_bounds(self) -> "DPFlowUncertaintyRequest":
        if any(
            abs(component.sensitivity_coefficient) > 1.0e6
            for component in self.components
        ):
            raise ValueError("uncertainty sensitivity exceeds the bounded workflow domain")
        return self


DPFlowExecutionRequest: TypeAlias = Annotated[
    GenericOrificeFlowRequest
    | OrificeBoreSolveRequest
    | GenericNozzleFlowRequest
    | GenericVenturiNozzleFlowRequest
    | GenericVenturiTubeFlowRequest
    | GenericAveragingPitotFlowRequest
    | DPTransmitterRangeRequest
    | PermanentPressureLossRequest
    | DPFlowUncertaintyRequest,
    Field(discriminator="operation"),
]
DP_FLOW_REQUEST_ADAPTER: Final = TypeAdapter(DPFlowExecutionRequest)

DPFlowResult: TypeAlias = (
    OrificeFlowResult
    | BoreSolverResult
    | CircularRestrictionFlowResult
    | AveragingPitotFlowResult
    | DPTransmitterRangeScreenResult
    | PermanentPressureLossResult
    | DPFlowUncertaintyResult
)

_RESULT_TYPE_BY_OPERATION: Final = MappingProxyType(
    {
        DPFlowOperation.GENERIC_ORIFICE: OrificeFlowResult,
        DPFlowOperation.ORIFICE_BORE_SOLVER: BoreSolverResult,
        DPFlowOperation.GENERIC_NOZZLE: CircularRestrictionFlowResult,
        DPFlowOperation.GENERIC_VENTURI_NOZZLE: CircularRestrictionFlowResult,
        DPFlowOperation.GENERIC_VENTURI_TUBE: CircularRestrictionFlowResult,
        DPFlowOperation.GENERIC_AVERAGING_PITOT: AveragingPitotFlowResult,
        DPFlowOperation.TRANSMITTER_RANGE: DPTransmitterRangeScreenResult,
        DPFlowOperation.PERMANENT_PRESSURE_LOSS: PermanentPressureLossResult,
        DPFlowOperation.RELATIVE_UNCERTAINTY: DPFlowUncertaintyResult,
    }
)
_PRIMARY_ELEMENT_BY_OPERATION: Final = MappingProxyType(
    {
        DPFlowOperation.GENERIC_NOZZLE: "flow_nozzle",
        DPFlowOperation.GENERIC_VENTURI_NOZZLE: "venturi_nozzle",
        DPFlowOperation.GENERIC_VENTURI_TUBE: "venturi_tube",
    }
)


class DPFlowMethodCatalogueEntry(CalculationModel):
    operation: DPFlowOperation
    method_id: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]+$", max_length=160)
    method_version: str = Field(pattern=r"^\d+\.\d+\.\d+$", max_length=32)
    title: str = Field(min_length=3, max_length=240)
    implementation_name: str = Field(pattern=r"^[a-z][a-z0-9_]+$", max_length=160)
    input_model_name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9]+$", max_length=160)
    result_model_name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9]+$", max_length=160)
    knowledge_source_ids: tuple[str, ...] = Field(default=(), max_length=16)
    executable: Literal[True] = True
    lifecycle_status: Literal["approved"] = "approved"
    knowledge_links_are_inert: Literal[True] = True
    coefficient_derivation_performed: Literal[False] = False
    manufacturer_selection_performed: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False


class DPFlowKnowledgeLink(CalculationModel):
    source_id: str
    owner: str
    title: str
    public_url: str = Field(pattern=r"^https://")
    reviewed_on: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    usage_boundary: str
    retrieval_mode: Literal["inert_metadata_only"] = "inert_metadata_only"
    network_access_performed: Literal[False] = False
    approved_as_coefficient_source: Literal[False] = False
    executable: Literal[False] = False
    conformity_evidence: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False


class DPFlowExecutionTrace(CalculationModel):
    workflow_version: Literal[DP_FLOW_WORKFLOW_VERSION] = DP_FLOW_WORKFLOW_VERSION
    calculator_pack_version: Literal[DP_FLOW_CALCULATORS_VERSION] = DP_FLOW_CALCULATORS_VERSION
    operation: DPFlowOperation
    method_id: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]+$", max_length=160)
    method_version: str = Field(pattern=r"^\d+\.\d+\.\d+$", max_length=32)
    implementation_name: str = Field(pattern=r"^[a-z][a-z0-9_]+$", max_length=160)
    normalized_input_fingerprint: FingerprintText
    result_fingerprint: FingerprintText
    attempt_fingerprint: FingerprintText
    knowledge_source_ids: tuple[str, ...] = Field(default=(), max_length=16)
    canonicalization: Literal["json-sort-keys-utf8-sha256-v1"] = "json-sort-keys-utf8-sha256-v1"
    standards_adapter_execution_count: Literal[0] = 0
    coefficient_derivation_performed: Literal[False] = False
    manufacturer_selection_performed: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False


class DPFlowExecutionOutcome(CalculationModel):
    normalized_request: DPFlowExecutionRequest
    result: DPFlowResult
    trace: DPFlowExecutionTrace
    coefficient_derivation_performed: Literal[False] = False
    manufacturer_selection_performed: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False

    @model_validator(mode="after")
    def validate_trace_binding(self) -> "DPFlowExecutionOutcome":
        """Bind the result and trace to the exact normalized request."""

        operation = DPFlowOperation(self.normalized_request.operation)
        metadata = DP_FLOW_API_REGISTRY[operation]
        trace = self.trace
        if (
            self.normalized_request.method_id != metadata.method_id
            or self.normalized_request.method_version != metadata.method_version
            or trace.operation is not operation
            or trace.method_id != metadata.method_id
            or trace.method_version != metadata.method_version
            or trace.implementation_name != metadata.implementation_name
            or trace.knowledge_source_ids != metadata.knowledge_source_ids
        ):
            raise ValueError("execution trace does not match the exact request")
        if not isinstance(self.result, _RESULT_TYPE_BY_OPERATION[operation]):
            raise ValueError("execution result type does not match the operation")
        expected_primary_element = _PRIMARY_ELEMENT_BY_OPERATION.get(operation)
        if (
            expected_primary_element is not None
            and self.result.primary_element != expected_primary_element
        ):
            raise ValueError("restriction result does not match the operation")
        input_fingerprint = build_input_fingerprint(self.normalized_request)
        result_fingerprint = build_result_fingerprint(
            self.normalized_request,
            self.result,
            metadata.knowledge_source_ids,
        )
        if (
            trace.normalized_input_fingerprint != input_fingerprint
            or trace.result_fingerprint != result_fingerprint
            or trace.attempt_fingerprint
            != build_attempt_fingerprint(input_fingerprint, result_fingerprint)
        ):
            raise ValueError("execution fingerprints do not match normalized content")
        return self


class DPFlowDesignCaseRequest(CalculationModel):
    application_request: DPFlowApplicationRequest
    selected_generic_option_id: str = Field(pattern=r"^generic\.[a-z0-9.-]+$", max_length=120)
    execution_request: DPFlowExecutionRequest


class DPFlowDesignCaseOutcome(CalculationModel):
    application_assessment: DPFlowApplicationAssessment
    selected_generic_option_id: str = Field(
        pattern=r"^generic\.[a-z0-9.-]+$",
        max_length=120,
    )
    calculation: DPFlowExecutionOutcome
    design_case_fingerprint: FingerprintText
    execution_mode: Literal["stateless", "stored_example_replay"]
    stored_example_id: str | None = Field(
        default=None,
        pattern=r"^dp-example\.[a-z0-9.-]+$",
        max_length=120,
    )
    stored_example_revision: StrictInt | None = Field(
        default=None,
        ge=1,
        le=10_000,
    )
    illustrative_only: bool
    approved_for_project_use: Literal[False] = False
    manufacturer_declared_best: Literal[False] = False
    final_brand_selection: Literal["user_decision_required"] = "user_decision_required"
    standards_conformity_claimed: Literal[False] = False

    @model_validator(mode="after")
    def validate_mode(self) -> "DPFlowDesignCaseOutcome":
        stored = self.execution_mode == "stored_example_replay"
        if stored != (self.stored_example_id is not None and self.stored_example_revision is not None):
            raise ValueError("stored replay identity must match execution mode")
        if stored != self.illustrative_only:
            raise ValueError("only stored reviewed examples are illustrative")
        return self


class DPFlowStoredDesignCaseExample(CalculationModel):
    example_id: str = Field(pattern=r"^dp-example\.[a-z0-9.-]+$", max_length=120)
    revision: StrictInt = Field(ge=1, le=10_000)
    title: str
    design_case: DPFlowDesignCaseRequest
    example_fingerprint: FingerprintText
    illustrative_only: Literal[True] = True
    approved_for_project_use: Literal[False] = False

    @model_validator(mode="after")
    def validate_fingerprint(self) -> "DPFlowStoredDesignCaseExample":
        expected = build_stored_example_fingerprint(
            self.example_id, self.revision, self.design_case
        )
        if self.example_fingerprint != expected:
            raise ValueError("stored example fingerprint does not match its exact content")
        return self


class DPFlowStoredDesignCaseReplayRequest(CalculationModel):
    example_id: str = Field(pattern=r"^dp-example\.[a-z0-9.-]+$", max_length=120)
    revision: StrictInt = Field(ge=1, le=10_000)
    example_fingerprint: FingerprintText


def _canonical_value(value: object) -> object:
    """Normalize JSON-equivalent values before deterministic hashing."""

    if isinstance(value, float) and value == 0.0:
        return 0.0
    if isinstance(value, dict):
        return {key: _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    return value


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        _canonical_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _hash(value: object) -> str:
    return sha256(_canonical_bytes(value)).hexdigest()


def validate_execution_request(value: object) -> DPFlowExecutionRequest:
    if isinstance(value, CalculationModel):
        value = value.model_dump(mode="python", round_trip=True, warnings="error")
    return DP_FLOW_REQUEST_ADAPTER.validate_python(value)


def build_input_fingerprint(request: DPFlowExecutionRequest) -> str:
    request = validate_execution_request(request)
    return _hash({
        "schema": "engineer4me.dp-flow.input.v1",
        "request": request.model_dump(mode="json", round_trip=True, warnings="error"),
    })


def build_result_fingerprint(
    request: DPFlowExecutionRequest,
    result: CalculationModel,
    knowledge_source_ids: tuple[str, ...],
) -> str:
    request = validate_execution_request(request)
    metadata = DP_FLOW_API_REGISTRY[DPFlowOperation(request.operation)]
    return _hash({
        "schema": "engineer4me.dp-flow.result.v1",
        "workflow_version": DP_FLOW_WORKFLOW_VERSION,
        "calculator_pack_version": DP_FLOW_CALCULATORS_VERSION,
        "method_id": request.method_id,
        "method_version": request.method_version,
        "operation": request.operation,
        "implementation_name": metadata.implementation_name,
        "normalized_input_fingerprint": build_input_fingerprint(request),
        "knowledge_source_ids": knowledge_source_ids,
        "result": result.model_dump(mode="json", round_trip=True, warnings="error"),
    })


def build_attempt_fingerprint(input_fingerprint: str, result_fingerprint: str) -> str:
    return _hash({
        "schema": "engineer4me.dp-flow.attempt.v1",
        "workflow_version": DP_FLOW_WORKFLOW_VERSION,
        "input_fingerprint": input_fingerprint,
        "result_fingerprint": result_fingerprint,
        "status": "completed",
    })


def build_design_case_fingerprint(
    request: DPFlowDesignCaseRequest,
    assessment: DPFlowApplicationAssessment,
    attempt_fingerprint: str,
) -> str:
    return _hash({
        "schema": "engineer4me.dp-flow.design-case.v1",
        "request": request.model_dump(mode="json", round_trip=True, warnings="error"),
        "assessment": assessment.model_dump(
            mode="json",
            round_trip=True,
            warnings="error",
        ),
        "attempt_fingerprint": attempt_fingerprint,
    })


def build_stored_example_fingerprint(
    example_id: str, revision: int, design_case: DPFlowDesignCaseRequest
) -> str:
    return _hash({
        "schema": "engineer4me.dp-flow.stored-example.v1",
        "example_id": example_id,
        "revision": revision,
        "design_case": design_case.model_dump(mode="json", round_trip=True, warnings="error"),
    })


DP_FLOW_API_CATALOGUE: Final = (
    DPFlowMethodCatalogueEntry(operation=DPFlowOperation.GENERIC_ORIFICE, method_id=GENERIC_ORIFICE_METHOD_ID, method_version=DP_FLOW_METHOD_VERSION, title="Generic orifice flow with supplied coefficients", implementation_name="calculate_generic_orifice_flow", input_model_name="GenericOrificeFlowRequest", result_model_name="OrificeFlowResult", knowledge_source_ids=("official.iso.5167-2",)),
    DPFlowMethodCatalogueEntry(operation=DPFlowOperation.ORIFICE_BORE_SOLVER, method_id=ORIFICE_BORE_SOLVER_METHOD_ID, method_version=ORIFICE_BORE_SOLVER_METHOD_VERSION, title="Bounded generic orifice bore solver", implementation_name="solve_orifice_bore_for_mass_flow", input_model_name="OrificeBoreSolveRequest", result_model_name="BoreSolverResult", knowledge_source_ids=("official.iso.5167-2",)),
    DPFlowMethodCatalogueEntry(operation=DPFlowOperation.GENERIC_NOZZLE, method_id=GENERIC_NOZZLE_METHOD_ID, method_version=GENERIC_NOZZLE_METHOD_VERSION, title="Generic nozzle flow with supplied coefficients", implementation_name="calculate_generic_nozzle_flow", input_model_name="GenericNozzleFlowRequest", result_model_name="CircularRestrictionFlowResult", knowledge_source_ids=("official.iso.5167-3",)),
    DPFlowMethodCatalogueEntry(operation=DPFlowOperation.GENERIC_VENTURI_NOZZLE, method_id=GENERIC_VENTURI_NOZZLE_METHOD_ID, method_version=GENERIC_VENTURI_NOZZLE_METHOD_VERSION, title="Generic Venturi-nozzle flow with supplied coefficients", implementation_name="calculate_generic_venturi_nozzle_flow", input_model_name="GenericVenturiNozzleFlowRequest", result_model_name="CircularRestrictionFlowResult", knowledge_source_ids=("official.iso.5167-3",)),
    DPFlowMethodCatalogueEntry(operation=DPFlowOperation.GENERIC_VENTURI_TUBE, method_id=GENERIC_VENTURI_TUBE_METHOD_ID, method_version=GENERIC_VENTURI_TUBE_METHOD_VERSION, title="Generic Venturi-tube flow with supplied coefficients", implementation_name="calculate_generic_venturi_tube_flow", input_model_name="GenericVenturiTubeFlowRequest", result_model_name="CircularRestrictionFlowResult", knowledge_source_ids=("official.iso.5167-4",)),
    DPFlowMethodCatalogueEntry(operation=DPFlowOperation.GENERIC_AVERAGING_PITOT, method_id=GENERIC_AVERAGING_PITOT_METHOD_ID, method_version=GENERIC_AVERAGING_PITOT_METHOD_VERSION, title="Generic averaging-Pitot flow with supplied coefficient", implementation_name="calculate_generic_averaging_pitot_flow", input_model_name="GenericAveragingPitotFlowRequest", result_model_name="AveragingPitotFlowResult"),
    DPFlowMethodCatalogueEntry(operation=DPFlowOperation.TRANSMITTER_RANGE, method_id=DP_TRANSMITTER_RANGE_METHOD_ID, method_version=DP_TRANSMITTER_RANGE_METHOD_VERSION, title="DP transmitter range screen", implementation_name="screen_dp_transmitter_range", input_model_name="DPTransmitterRangeRequest", result_model_name="DPTransmitterRangeScreenResult"),
    DPFlowMethodCatalogueEntry(operation=DPFlowOperation.PERMANENT_PRESSURE_LOSS, method_id=PERMANENT_PRESSURE_LOSS_METHOD_ID, method_version=PERMANENT_PRESSURE_LOSS_METHOD_VERSION, title="Permanent pressure loss using supplied ratio", implementation_name="calculate_permanent_pressure_loss", input_model_name="PermanentPressureLossRequest", result_model_name="PermanentPressureLossResult"),
    DPFlowMethodCatalogueEntry(operation=DPFlowOperation.RELATIVE_UNCERTAINTY, method_id=DP_FLOW_UNCERTAINTY_METHOD_ID, method_version=DP_FLOW_UNCERTAINTY_METHOD_VERSION, title="Independent relative uncertainty RSS", implementation_name="combine_dp_flow_relative_uncertainty", input_model_name="DPFlowUncertaintyRequest", result_model_name="DPFlowUncertaintyResult"),
)
DP_FLOW_API_REGISTRY: Final = MappingProxyType({entry.operation: entry for entry in DP_FLOW_API_CATALOGUE})
DP_FLOW_KNOWLEDGE_LINKS: Final = tuple(
    DPFlowKnowledgeLink(**source.model_dump(mode="python", round_trip=True, warnings="error"))
    for source in OFFICIAL_SOURCES
)
if len(DP_FLOW_API_REGISTRY) != len(DP_FLOW_API_CATALOGUE):
    raise RuntimeError("duplicate DP-flow API operation registration")
if len({link.source_id for link in DP_FLOW_KNOWLEDGE_LINKS}) != len(
    DP_FLOW_KNOWLEDGE_LINKS
):
    raise RuntimeError("duplicate DP-flow knowledge-link identifier")
_KNOWN_KNOWLEDGE_SOURCE_IDS = frozenset(
    link.source_id for link in DP_FLOW_KNOWLEDGE_LINKS
)
if any(
    not set(entry.knowledge_source_ids).issubset(_KNOWN_KNOWLEDGE_SOURCE_IDS)
    for entry in DP_FLOW_API_CATALOGUE
):
    raise RuntimeError("DP-flow API method references an unknown knowledge link")


def _coefficient(value: float, label: str) -> TraceableCoefficient:
    return TraceableCoefficient(value=value, source_reference=f"Illustrative Step 99 {label}", applicable_conditions="Illustrative geometry and operating point only; project verification required.", supplied_by="Engineer4Me reviewed example")


_LIQUID = FlowingFluidProperties(
    density_kg_m3=998.0,
    dynamic_viscosity_pa_s=0.001,
    pressure_absolute_pa=500_000.0,
    temperature_k=293.15,
    phase="liquid",
    property_source_reference="Illustrative Step 99 liquid properties",
    condition_basis="Illustrative flowing condition only",
)
_STEAM = FlowingFluidProperties(
    density_kg_m3=6.2,
    dynamic_viscosity_pa_s=1.8e-5,
    pressure_absolute_pa=1_000_000.0,
    temperature_k=450.0,
    phase="vapour",
    property_source_reference="Illustrative Step 99 steam properties",
    condition_basis="Illustrative flowing steam condition only",
)


def _application(
    *,
    assessment_id: str,
    fluid_phase: Literal["liquid", "steam"],
    pipe_inside_diameter_m: float,
    fluid: FlowingFluidProperties,
    minimum_mass_flow_kg_s: float,
    normal_mass_flow_kg_s: float,
    maximum_mass_flow_kg_s: float,
) -> DPFlowApplicationRequest:
    return DPFlowApplicationRequest(
        assessment_id=assessment_id,
        fluid_phase=fluid_phase,
        objective="process_control",
        pipe_inside_diameter_m=pipe_inside_diameter_m,
        minimum_mass_flow_kg_s=minimum_mass_flow_kg_s,
        normal_mass_flow_kg_s=normal_mass_flow_kg_s,
        maximum_mass_flow_kg_s=maximum_mass_flow_kg_s,
        flowing_density_kg_m3=fluid.density_kg_m3,
        flowing_viscosity_pa_s=fluid.dynamic_viscosity_pa_s,
        flowing_absolute_pressure_pa=fluid.pressure_absolute_pa,
        flowing_temperature_k=fluid.temperature_k,
        available_upstream_straight_run_d=20.0,
        available_downstream_straight_run_d=8.0,
        required_total_uncertainty_percent=2.0,
        full_pipe_confirmed="yes",
        flashing_or_cavitation_risk="no",
        sonic_or_choked_flow_risk="no",
        intrusive_element_allowed="yes",
        approved_standard_or_oem_method_available="yes",
        traceable_coefficient_available="yes",
        pulsating_flow="no",
        bidirectional_flow="no",
        wet_gas_or_condensing="no",
        hazardous_area="no",
        include_proprietary_variants=False,
    )


def _example(
    example_id: str,
    title: str,
    selected: str,
    application: DPFlowApplicationRequest,
    request: DPFlowExecutionRequest,
) -> DPFlowStoredDesignCaseExample:
    design_case = DPFlowDesignCaseRequest(
        application_request=application,
        selected_generic_option_id=selected,
        execution_request=request,
    )
    return DPFlowStoredDesignCaseExample(
        example_id=example_id,
        revision=1,
        title=title,
        design_case=design_case,
        example_fingerprint=build_stored_example_fingerprint(
            example_id,
            1,
            design_case,
        ),
    )


DP_FLOW_STORED_DESIGN_CASE_EXAMPLES: Final = (
    _example(
        "dp-example.liquid-orifice",
        "Illustrative liquid orifice flow",
        "generic.orifice.concentric-square-edge",
        _application(
            assessment_id="dp-example.liquid-orifice",
            fluid_phase="liquid",
            pipe_inside_diameter_m=0.2,
            fluid=_LIQUID,
            minimum_mass_flow_kg_s=10.0,
            normal_mass_flow_kg_s=22.0,
            maximum_mass_flow_kg_s=30.0,
        ),
        GenericOrificeFlowRequest(
            operation="generic_orifice",
            method_id=GENERIC_ORIFICE_METHOD_ID,
            method_version=DP_FLOW_METHOD_VERSION,
            pipe_inside_diameter_m=0.2,
            bore_diameter_m=0.1,
            differential_pressure_pa=10_000.0,
            fluid=_LIQUID,
            discharge_coefficient=_coefficient(0.61, "orifice coefficient"),
            expansibility_factor=_coefficient(1.0, "liquid expansibility"),
        ),
    ),
    _example(
        "dp-example.steam-nozzle",
        "Illustrative steam flow-nozzle calculation",
        "generic.nozzle.isa-or-long-radius",
        _application(
            assessment_id="dp-example.steam-nozzle",
            fluid_phase="steam",
            pipe_inside_diameter_m=0.15,
            fluid=_STEAM,
            minimum_mass_flow_kg_s=1.0,
            normal_mass_flow_kg_s=3.6,
            maximum_mass_flow_kg_s=5.0,
        ),
        GenericNozzleFlowRequest(
            operation="generic_nozzle",
            method_id=GENERIC_NOZZLE_METHOD_ID,
            method_version=GENERIC_NOZZLE_METHOD_VERSION,
            pipe_inside_diameter_m=0.15,
            throat_diameter_m=0.09,
            differential_pressure_pa=25_000.0,
            fluid=_STEAM,
            discharge_coefficient=_coefficient(0.99, "nozzle coefficient"),
            expansibility_factor=_coefficient(0.96, "steam expansibility"),
        ),
    ),
    _example(
        "dp-example.large-pipe-averaging-pitot",
        "Illustrative large-pipe averaging-Pitot flow",
        "generic.averaging-pitot",
        _application(
            assessment_id="dp-example.large-pipe-averaging-pitot",
            fluid_phase="liquid",
            pipe_inside_diameter_m=0.6,
            fluid=_LIQUID,
            minimum_mass_flow_kg_s=100.0,
            normal_mass_flow_kg_s=200.0,
            maximum_mass_flow_kg_s=300.0,
        ),
        GenericAveragingPitotFlowRequest(
            operation="generic_averaging_pitot",
            method_id=GENERIC_AVERAGING_PITOT_METHOD_ID,
            method_version=GENERIC_AVERAGING_PITOT_METHOD_VERSION,
            pipe_inside_diameter_m=0.6,
            differential_pressure_pa=400.0,
            fluid=_LIQUID,
            meter_coefficient=_coefficient(
                0.8,
                "averaging-Pitot coefficient",
            ),
            expansibility_factor=_coefficient(1.0, "liquid expansibility"),
        ),
    ),
)
DP_FLOW_STORED_EXAMPLE_REGISTRY: Final = MappingProxyType(
    {
        (item.example_id, item.revision): item
        for item in DP_FLOW_STORED_DESIGN_CASE_EXAMPLES
    }
)
if len(DP_FLOW_STORED_EXAMPLE_REGISTRY) != len(
    DP_FLOW_STORED_DESIGN_CASE_EXAMPLES
):
    raise RuntimeError("duplicate stored DP-flow design-case example identity")


__all__ = [
    "DPFlowDesignCaseOutcome",
    "DPFlowDesignCaseRequest",
    "DPFlowExecutionOutcome",
    "DPFlowExecutionRequest",
    "DPFlowExecutionTrace",
    "DPFlowKnowledgeLink",
    "DPFlowMethodCatalogueEntry",
    "DPFlowOperation",
    "DPFlowResult",
    "DPFlowStoredDesignCaseExample",
    "DPFlowStoredDesignCaseReplayRequest",
    "DPFlowUncertaintyRequest",
    "DPTransmitterRangeRequest",
    "DP_FLOW_API_CATALOGUE",
    "DP_FLOW_API_REGISTRY",
    "DP_FLOW_KNOWLEDGE_LINKS",
    "DP_FLOW_REQUEST_ADAPTER",
    "DP_FLOW_STORED_DESIGN_CASE_EXAMPLES",
    "DP_FLOW_STORED_EXAMPLE_REGISTRY",
    "DP_FLOW_WORKFLOW_VERSION",
    "GenericAveragingPitotFlowRequest",
    "GenericNozzleFlowRequest",
    "GenericOrificeFlowRequest",
    "GenericVenturiNozzleFlowRequest",
    "GenericVenturiTubeFlowRequest",
    "ORIFICE_BORE_SOLVER_METHOD_ID",
    "ORIFICE_BORE_SOLVER_METHOD_VERSION",
    "OrificeBoreSolveRequest",
    "PermanentPressureLossRequest",
    "build_attempt_fingerprint",
    "build_design_case_fingerprint",
    "build_input_fingerprint",
    "build_result_fingerprint",
    "build_stored_example_fingerprint",
    "validate_execution_request",
]

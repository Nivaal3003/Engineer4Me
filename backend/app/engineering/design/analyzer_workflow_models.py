"""Controlled Step 107 analyzer workflow metadata and worked examples.

The module binds Step 106 assessments to the exact internal ENG-070
governance references they cite and provides immutable, illustrative design
cases.  Reference metadata is inert: it is never dereferenced, executed, or
treated as standards, product-selection, conformity, or project-approval
evidence.  The examples are compiled fixtures, not persisted user designs.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final, Literal, Self

from pydantic import Field, StrictInt, model_validator

from app.engineering.calculations.models import (
    CalculationModel,
    CalculationReference,
    CalculationStatus,
    EngineeringQuantity,
    FingerprintText,
    ReferenceType,
)
from app.engineering.calculations.units import QuantityKind
from app.engineering.design.analyzer_assistant import (
    ANALYZER_ASSISTANT_VERSION,
    ANALYZER_RULESET_VERSION,
    ANALYZER_TECHNOLOGY_TAXONOMY_VERSION,
    assess_analyzer_application,
)
from app.engineering.design.analyzer_models import (
    ANALYZER_APPLICATION_MODEL_VERSION,
    AnalyzerAnalyteFamily,
    AnalyzerAnalyteRequirement,
    AnalyzerApplicationAssessment,
    AnalyzerApplicationKind,
    AnalyzerApplicationRequest,
    AnalyzerConditionSeverity,
    AnalyzerEnvironmentCondition,
    AnalyzerInstallationContext,
    AnalyzerMeasurementObjective,
    AnalyzerMeasurementRequirements,
    AnalyzerProcessContext,
    AnalyzerResponseContributorKind,
    AnalyzerResponseTimeContributor,
    AnalyzerSafetyContext,
    AnalyzerSampleApproach,
    AnalyzerSampleDisposition,
    AnalyzerSamplePhase,
    AnalyzerSampleSystemContext,
    AnalyzerScenarioDisposition,
    AnalyzerTechnology,
    AnalyzerTriState,
    AnalyzerUtility,
    fingerprint_analyzer_payload,
)

ANALYZER_WORKFLOW_VERSION: Final = "1.0.0"
_REFERENCE_SOURCE: Final = (
    "docs/07_Engineering/ENG-070_Phase7_Calculation_Engine_Standard.md"
)
_ANALYZER_REFERENCE_IDS: Final = frozenset(
    {
        "ref.eng-070",
        "ref.e4m-calc-060",
        "ref.e4m-calc-061",
        "ref.e4m-calc-062",
        "ref.e4m-calc-063",
    }
)


class AnalyzerKnowledgeLink(CalculationModel):
    """One inert internal-governance reference used by the assistant."""

    reference: CalculationReference
    retrieval_mode: Literal["inert_metadata_only"] = "inert_metadata_only"
    network_access_performed: Literal[False] = False
    protected_content_embedded: Literal[False] = False
    approved_as_equation_or_factor_source: Literal[False] = False
    approved_as_product_or_selection_source: Literal[False] = False
    manufacturer_data_present: Literal[False] = False
    executable: Literal[False] = False
    conformity_evidence: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False
    final_design_approval_granted: Literal[False] = False

    @model_validator(mode="after")
    def validate_reference_boundary(self) -> Self:
        if self.reference.reference_type is not ReferenceType.ENGINEERING_KNOWLEDGE:
            raise ValueError("analyzer links must be internal engineering knowledge")
        if self.reference.reference_id not in _ANALYZER_REFERENCE_IDS:
            raise ValueError("analyzer link is outside the controlled allow-list")
        if self.reference.verified:
            raise ValueError("internal ENG-070 metadata is not verified evidence")
        if self.reference.source_location != _REFERENCE_SOURCE:
            raise ValueError("analyzer link source location drifted")
        return self


def _reference(
    reference_id: str,
    *,
    title: str,
    part: str,
    relevant_section: str,
    applicability: str,
    implementation_basis: str,
) -> AnalyzerKnowledgeLink:
    return AnalyzerKnowledgeLink(
        reference=CalculationReference(
            reference_id=reference_id,
            reference_type=ReferenceType.ENGINEERING_KNOWLEDGE,
            title=title,
            publisher_or_owner="Engineer4Me",
            document_number="ENG-070",
            edition_or_revision="0.1",
            part=part,
            relevant_section=relevant_section,
            implementation_basis=implementation_basis,
            applicability=applicability,
            source_location=_REFERENCE_SOURCE,
            verified=False,
        )
    )


ANALYZER_KNOWLEDGE_LINKS: Final = tuple(
    sorted(
        (
            _reference(
                "ref.eng-070",
                title="ENG-070 analyzer application assessment governance",
                part="Analyzer application governance",
                relevant_section="E4M-CALC-060 through E4M-CALC-063",
                applicability=(
                    "Vendor-neutral analyzer screening, explicit unknowns, "
                    "scenario evidence, confidence, verification, and "
                    "competent-person escalation."
                ),
                implementation_basis=(
                    "Internal governance metadata only; it does not supply a "
                    "formula, product identity, conformity claim, or approval."
                ),
            ),
            _reference(
                "ref.e4m-calc-060",
                title="E4M-CALC-060 scenario-based recommendation contract",
                part="E4M-CALC-060",
                relevant_section="Scenario-based recommendations",
                applicability=(
                    "Multiple plausible generic technology scenarios remain "
                    "visible; no definitive brand or model is selected."
                ),
                implementation_basis=(
                    "Controls scenario disposition and evidence visibility "
                    "without executing external knowledge."
                ),
            ),
            _reference(
                "ref.e4m-calc-061",
                title="E4M-CALC-061 multidisciplinary context contract",
                part="E4M-CALC-061",
                relevant_section="Analyzer application context",
                applicability=(
                    "Analyte, process, sample-system, interference, response, "
                    "utility, environment, safety, and maintenance context."
                ),
                implementation_basis=(
                    "Controls the structured context boundary without "
                    "inventing missing project facts."
                ),
            ),
            _reference(
                "ref.e4m-calc-062",
                title="E4M-CALC-062 confidence contract",
                part="E4M-CALC-062",
                relevant_section="Evidence-based confidence",
                applicability=(
                    "Confidence reflects completeness, evidence, "
                    "applicability, and unresolved assumptions; it is not a "
                    "probability, performance proof, or approval."
                ),
                implementation_basis=(
                    "Controls deterministic confidence interpretation only."
                ),
            ),
            _reference(
                "ref.e4m-calc-063",
                title="E4M-CALC-063 verification contract",
                part="E4M-CALC-063",
                relevant_section="Evidence and escalation",
                applicability=(
                    "Observations, missing facts, checks, acceptance evidence, "
                    "and competent-person escalation."
                ),
                implementation_basis=(
                    "Controls verification traceability without granting final "
                    "design approval."
                ),
            ),
        ),
        key=lambda item: item.reference.reference_id,
    )
)
ANALYZER_KNOWLEDGE_REGISTRY: Final = MappingProxyType(
    {item.reference.reference_id: item for item in ANALYZER_KNOWLEDGE_LINKS}
)
if len(ANALYZER_KNOWLEDGE_REGISTRY) != len(ANALYZER_KNOWLEDGE_LINKS):
    raise RuntimeError("duplicate analyzer knowledge-link identity")
if frozenset(ANALYZER_KNOWLEDGE_REGISTRY) != _ANALYZER_REFERENCE_IDS:
    raise RuntimeError("analyzer knowledge-link allow-list is incomplete")


def _fresh(model_type, value):
    if not isinstance(value, model_type):
        raise TypeError(f"value must be an instance of {model_type.__name__}")
    return model_type.model_validate(
        value.model_dump(mode="python", round_trip=True, warnings="error")
    )


def resolve_analyzer_knowledge_links(
    assessment: AnalyzerApplicationAssessment,
) -> tuple[AnalyzerKnowledgeLink, ...]:
    """Resolve every emitted ID through the immutable local allow-list."""

    validated = _fresh(AnalyzerApplicationAssessment, assessment)
    reference_ids: set[str] = set()
    for finding in validated.safety_findings:
        reference_ids.update(finding.reference_ids)
    for scenario in validated.scenarios:
        reference_ids.update(scenario.reference_ids)
        for rule in scenario.rule_results:
            reference_ids.update(rule.reference_ids)
    if reference_ids != _ANALYZER_REFERENCE_IDS:
        unknown = reference_ids - _ANALYZER_REFERENCE_IDS
        missing = _ANALYZER_REFERENCE_IDS - reference_ids
        raise ValueError(
            "analyzer assessment knowledge closure failed: "
            f"unknown={sorted(unknown)!r}, missing={sorted(missing)!r}"
        )
    return tuple(
        _fresh(AnalyzerKnowledgeLink, ANALYZER_KNOWLEDGE_REGISTRY[reference_id])
        for reference_id in sorted(reference_ids)
    )


def build_analyzer_integration_fingerprint(
    assessment: AnalyzerApplicationAssessment,
    knowledge_links: tuple[AnalyzerKnowledgeLink, ...],
) -> str:
    return fingerprint_analyzer_payload(
        {
            "schema": "engineer4me.analyzer.assessment-envelope.v1",
            "workflow_version": ANALYZER_WORKFLOW_VERSION,
            "model_version": ANALYZER_APPLICATION_MODEL_VERSION,
            "assistant_version": ANALYZER_ASSISTANT_VERSION,
            "ruleset_version": ANALYZER_RULESET_VERSION,
            "taxonomy_version": ANALYZER_TECHNOLOGY_TAXONOMY_VERSION,
            "assessment": assessment.model_dump(
                mode="json", round_trip=True, warnings="error"
            ),
            "knowledge_links": [
                item.model_dump(mode="json", round_trip=True, warnings="error")
                for item in knowledge_links
            ],
        }
    )


class AnalyzerAssessmentEnvelope(CalculationModel):
    """Step 107 assessment bound to its exact controlled references."""

    workflow_version: Literal["1.0.0"] = ANALYZER_WORKFLOW_VERSION
    model_version: Literal["1.0.0"] = ANALYZER_APPLICATION_MODEL_VERSION
    assistant_version: Literal["1.0.0"] = ANALYZER_ASSISTANT_VERSION
    ruleset_version: Literal["1.0.0"] = ANALYZER_RULESET_VERSION
    taxonomy_version: Literal["1.0.0"] = ANALYZER_TECHNOLOGY_TAXONOMY_VERSION
    request_fingerprint: FingerprintText
    assessment: AnalyzerApplicationAssessment
    knowledge_links: tuple[AnalyzerKnowledgeLink, ...] = Field(
        min_length=5,
        max_length=5,
    )
    integration_fingerprint: FingerprintText
    external_knowledge_access_performed: Literal[False] = False
    persistence_performed: Literal[False] = False
    manufacturer_or_model_selection_performed: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False
    final_design_approval_granted: Literal[False] = False

    @model_validator(mode="after")
    def validate_integration(self) -> Self:
        if self.assessment.assistant_version != self.assistant_version:
            raise ValueError("assessment assistant version drifted")
        if self.assessment.ruleset_version != self.ruleset_version:
            raise ValueError("assessment ruleset version drifted")
        expected_request = fingerprint_analyzer_payload(self.assessment.request)
        if self.request_fingerprint != expected_request:
            raise ValueError("request_fingerprint does not match assessment request")
        resolved = resolve_analyzer_knowledge_links(self.assessment)
        if self.knowledge_links != resolved:
            raise ValueError("knowledge_links do not match assessment references")
        expected = build_analyzer_integration_fingerprint(
            self.assessment,
            self.knowledge_links,
        )
        if self.integration_fingerprint != expected:
            raise ValueError("integration_fingerprint is stale")
        return self


class AnalyzerExpectedScenario(CalculationModel):
    """Small reviewed outcome assertion attached to an illustrative case."""

    technology: AnalyzerTechnology
    disposition: AnalyzerScenarioDisposition


class AnalyzerDesignCaseExample(CalculationModel):
    """Immutable illustrative request and its reviewed Step 106 identity."""

    example_id: str = Field(
        pattern=r"^analyzer-example\.[a-z0-9.-]+$",
        max_length=120,
    )
    revision: StrictInt = Field(ge=1, le=10_000)
    title: str = Field(min_length=3, max_length=240)
    request: AnalyzerApplicationRequest
    request_fingerprint: FingerprintText
    expected_status: CalculationStatus
    expected_scenarios: tuple[AnalyzerExpectedScenario, ...] = Field(
        min_length=1,
        max_length=21,
    )
    expected_assessment_fingerprint: FingerprintText
    example_fingerprint: FingerprintText
    illustrative_only: Literal[True] = True
    persisted: Literal[False] = False
    approved_for_project_use: Literal[False] = False
    manufacturer_or_model_selected: Literal[False] = False
    final_brand_selection: Literal["user_decision_required"] = "user_decision_required"
    standards_conformity_claimed: Literal[False] = False
    final_design_approval_granted: Literal[False] = False

    @model_validator(mode="after")
    def validate_example(self) -> Self:
        if self.revision != 1:
            raise ValueError("compiled Step 107 examples use revision 1")
        expected_order = tuple(
            sorted(self.expected_scenarios, key=lambda item: item.technology.value)
        )
        if self.expected_scenarios != expected_order:
            raise ValueError("expected_scenarios must be ordered by technology")
        if len({item.technology for item in self.expected_scenarios}) != len(
            self.expected_scenarios
        ):
            raise ValueError("expected scenario technologies must be unique")
        if self.request_fingerprint != fingerprint_analyzer_payload(self.request):
            raise ValueError("example request_fingerprint is stale")
        if self.example_fingerprint != build_analyzer_example_fingerprint(
            example_id=self.example_id,
            revision=self.revision,
            request=self.request,
            expected_status=self.expected_status,
            expected_scenarios=self.expected_scenarios,
            expected_assessment_fingerprint=self.expected_assessment_fingerprint,
        ):
            raise ValueError("example_fingerprint is stale")
        return self


def build_analyzer_example_fingerprint(
    *,
    example_id: str,
    revision: int,
    request: AnalyzerApplicationRequest,
    expected_status: CalculationStatus,
    expected_scenarios: tuple[AnalyzerExpectedScenario, ...],
    expected_assessment_fingerprint: str,
) -> str:
    return fingerprint_analyzer_payload(
        {
            "schema": "engineer4me.analyzer.design-case-example.v1",
            "example_id": example_id,
            "revision": revision,
            "request": request.model_dump(
                mode="json", round_trip=True, warnings="error"
            ),
            "expected_status": expected_status.value,
            "expected_scenarios": [
                item.model_dump(mode="json", round_trip=True, warnings="error")
                for item in expected_scenarios
            ],
            "expected_assessment_fingerprint": expected_assessment_fingerprint,
        }
    )


def validate_analyzer_design_case_example(
    example: AnalyzerDesignCaseExample,
) -> AnalyzerApplicationAssessment:
    """Re-run one example and verify its reviewed outcome contract."""

    validated = _fresh(AnalyzerDesignCaseExample, example)
    assessment = assess_analyzer_application(validated.request)
    if assessment.request != validated.request:
        raise ValueError("example assessment request binding failed")
    if assessment.status is not validated.expected_status:
        raise ValueError("example assessment status drifted")
    if assessment.assessment_fingerprint != validated.expected_assessment_fingerprint:
        raise ValueError("example assessment fingerprint drifted")
    by_technology = {item.technology: item for item in assessment.scenarios}
    for expected in validated.expected_scenarios:
        scenario = by_technology.get(expected.technology)
        if scenario is None or scenario.disposition is not expected.disposition:
            raise ValueError("example scenario contract drifted")
    resolve_analyzer_knowledge_links(assessment)
    return _fresh(AnalyzerApplicationAssessment, assessment)


def _quantity(kind: QuantityKind, value: float, unit: str) -> EngineeringQuantity:
    return EngineeringQuantity(quantity_kind=kind.value, value=value, unit=unit)


def _response(
    contributor_id: str,
    kind: AnalyzerResponseContributorKind,
    seconds: float,
) -> AnalyzerResponseTimeContributor:
    return AnalyzerResponseTimeContributor(
        contributor_id=contributor_id,
        kind=kind,
        duration=_quantity(QuantityKind.TIME, seconds, "s"),
        basis="Illustrative declared response contributor",
        source_reference="Step 107 reviewed example basis",
        confirmed=True,
    )


def _complete_request(
    *,
    request_id: str,
    kind: AnalyzerApplicationKind,
    family: AnalyzerAnalyteFamily,
    phase: AnalyzerSamplePhase,
    approach: AnalyzerSampleApproach,
    utilities: tuple[AnalyzerUtility, ...] = (AnalyzerUtility.ELECTRICAL_POWER,),
    cycle_seconds: float | None = None,
) -> AnalyzerApplicationRequest:
    extractive = approach in {
        AnalyzerSampleApproach.EXTRACTIVE,
        AnalyzerSampleApproach.FAST_LOOP,
        AnalyzerSampleApproach.GRAB_SAMPLE,
        AnalyzerSampleApproach.ASPIRATED_DETECTION,
    }
    contributors = [
        _response(
            "response.analyzer",
            AnalyzerResponseContributorKind.ANALYZER_CELL,
            5.0,
        )
    ]
    if cycle_seconds is not None:
        contributors.append(
            _response(
                "response.cycle",
                AnalyzerResponseContributorKind.ANALYSIS_CYCLE,
                cycle_seconds,
            )
        )
    return AnalyzerApplicationRequest(
        request_id=request_id,
        application_kind=kind,
        measurement=AnalyzerMeasurementRequirements(
            objectives=(
                AnalyzerMeasurementObjective.COMPOSITION_ANALYSIS
                if kind is AnalyzerApplicationKind.GAS_CHROMATOGRAPHY
                else AnalyzerMeasurementObjective.SAFETY_DETECTION
                if kind is AnalyzerApplicationKind.GAS_DETECTION
                else AnalyzerMeasurementObjective.PROCESS_CONTROL,
            ),
            analytes=(
                AnalyzerAnalyteRequirement(
                    analyte_id="analyte.primary",
                    display_name="Illustrative primary analyte",
                    family=family,
                    engineering_unit="mol/mol",
                    expected_minimum=0.0,
                    expected_normal=10.0,
                    expected_maximum=20.0,
                    required_detection_limit=0.1,
                    required_accuracy=1.0,
                    source_reference="Illustrative approved process basis",
                ),
            ),
            maximum_total_response_time=_quantity(
                QuantityKind.TIME,
                120.0,
                "s",
            ),
            minimum_availability_percent=95.0,
            continuous_output_required=AnalyzerTriState.YES,
            local_indication_required=AnalyzerTriState.YES,
            automatic_calibration_required=AnalyzerTriState.NO,
        ),
        process=AnalyzerProcessContext(
            sample_phase=phase,
            stream_description="Illustrative representative process stream",
            matrix_components=("Balance component", "Primary analyte"),
            composition_variability=AnalyzerConditionSeverity.NONE,
            particulate_loading=AnalyzerConditionSeverity.NONE,
            liquid_droplets=AnalyzerConditionSeverity.NONE,
            wet_sample=AnalyzerConditionSeverity.NONE,
            corrosivity=AnalyzerConditionSeverity.NONE,
            fouling_tendency=AnalyzerConditionSeverity.NONE,
            reactivity=AnalyzerConditionSeverity.NONE,
            known_interferences_assessed=AnalyzerTriState.YES,
        ),
        sample_system=AnalyzerSampleSystemContext(
            approach=approach,
            delivered_sample_phase=phase,
            extraction_location_reference=(
                "Illustrative process takeoff" if extractive else None
            ),
            representative_sample_confirmed=AnalyzerTriState.YES,
            sample_probe_defined=AnalyzerTriState.YES,
            filtration_defined=AnalyzerTriState.YES,
            pressure_control_defined=AnalyzerTriState.YES,
            temperature_control_defined=AnalyzerTriState.YES,
            phase_preservation_confirmed=AnalyzerTriState.YES,
            materials_compatibility_confirmed=AnalyzerTriState.YES,
            calibration_introduction_defined=AnalyzerTriState.YES,
            sample_line_length=(
                _quantity(QuantityKind.LENGTH, 10.0, "m") if extractive else None
            ),
            sample_line_internal_diameter=(
                _quantity(QuantityKind.LENGTH, 0.01, "m") if extractive else None
            ),
            sample_flow_rate=(
                _quantity(
                    QuantityKind.ACTUAL_VOLUMETRIC_FLOW,
                    0.001,
                    "m3/s",
                )
                if extractive
                else None
            ),
            disposition=(
                AnalyzerSampleDisposition.CLOSED_RECOVERY
                if extractive
                else AnalyzerSampleDisposition.NOT_APPLICABLE
            ),
            disposition_basis_reference=(
                "Illustrative approved recovery basis" if extractive else None
            ),
            return_compatibility_confirmed=(
                AnalyzerTriState.YES if extractive else AnalyzerTriState.UNKNOWN
            ),
            response_time_budget_complete=AnalyzerTriState.YES,
            gc_separation_and_coelution_verified=(
                AnalyzerTriState.YES
                if kind is AnalyzerApplicationKind.GAS_CHROMATOGRAPHY
                else AnalyzerTriState.UNKNOWN
            ),
            gc_sample_loop_representative_confirmed=(
                AnalyzerTriState.YES
                if kind is AnalyzerApplicationKind.GAS_CHROMATOGRAPHY
                else AnalyzerTriState.UNKNOWN
            ),
            gc_calibration_mixture_defined=(
                AnalyzerTriState.YES
                if kind is AnalyzerApplicationKind.GAS_CHROMATOGRAPHY
                else AnalyzerTriState.UNKNOWN
            ),
            gc_carrier_gas_quality_confirmed=(
                AnalyzerTriState.YES
                if kind is AnalyzerApplicationKind.GAS_CHROMATOGRAPHY
                else AnalyzerTriState.UNKNOWN
            ),
            response_time_contributors=tuple(contributors),
        ),
        safety=AnalyzerSafetyContext(
            hazardous_area=AnalyzerTriState.NO,
            toxic_material=AnalyzerTriState.NO,
            flammable_material=AnalyzerTriState.NO,
            oxygen_deficiency_or_enrichment=AnalyzerTriState.NO,
            high_pressure_sampling=AnalyzerTriState.NO,
            high_temperature_sampling=AnalyzerTriState.NO,
            sample_containment_confirmed=AnalyzerTriState.YES,
            safe_vent_or_disposal_confirmed=AnalyzerTriState.YES,
            exposure_control_defined=AnalyzerTriState.YES,
            gas_detection_safety_function=(
                AnalyzerTriState.NO
                if kind is AnalyzerApplicationKind.GAS_DETECTION
                else AnalyzerTriState.UNKNOWN
            ),
            alarm_basis_defined=(
                AnalyzerTriState.YES
                if kind is AnalyzerApplicationKind.GAS_DETECTION
                else AnalyzerTriState.UNKNOWN
            ),
            detector_coverage_basis_defined=(
                AnalyzerTriState.YES
                if kind is AnalyzerApplicationKind.GAS_DETECTION
                else AnalyzerTriState.UNKNOWN
            ),
            detector_response_basis_defined=(
                AnalyzerTriState.YES
                if kind is AnalyzerApplicationKind.GAS_DETECTION
                else AnalyzerTriState.UNKNOWN
            ),
        ),
        installation=AnalyzerInstallationContext(
            available_utilities=utilities,
            utility_availability_confirmed=AnalyzerTriState.YES,
            environment_conditions=(AnalyzerEnvironmentCondition.INDOOR_CONTROLLED,),
            maintenance_access_confirmed=AnalyzerTriState.YES,
            calibration_access_confirmed=AnalyzerTriState.YES,
            shelter_or_enclosure_basis_defined=AnalyzerTriState.YES,
        ),
        application_notes=(
            "Illustrative Step 107 design case; project verification required"
        ),
    )


def _replace_nested(
    request: AnalyzerApplicationRequest,
    field_name: str,
    **updates: object,
) -> AnalyzerApplicationRequest:
    values = request.model_dump(mode="python", round_trip=True, warnings="error")
    nested = values[field_name]
    if not isinstance(nested, dict):
        raise TypeError("example nested field must be a model mapping")
    nested.update(updates)
    return AnalyzerApplicationRequest.model_validate(values)


def _example(
    example_id: str,
    title: str,
    request: AnalyzerApplicationRequest,
    expected: tuple[tuple[AnalyzerTechnology, AnalyzerScenarioDisposition], ...],
) -> AnalyzerDesignCaseExample:
    assessment = assess_analyzer_application(request)
    scenarios = tuple(
        sorted(
            (
                AnalyzerExpectedScenario(technology=technology, disposition=disposition)
                for technology, disposition in expected
            ),
            key=lambda item: item.technology.value,
        )
    )
    by_technology = {item.technology: item for item in assessment.scenarios}
    if any(
        by_technology.get(item.technology) is None
        or by_technology[item.technology].disposition is not item.disposition
        for item in scenarios
    ):
        raise RuntimeError(f"reviewed analyzer example drifted: {example_id}")
    fingerprint = build_analyzer_example_fingerprint(
        example_id=example_id,
        revision=1,
        request=request,
        expected_status=assessment.status,
        expected_scenarios=scenarios,
        expected_assessment_fingerprint=assessment.assessment_fingerprint,
    )
    return AnalyzerDesignCaseExample(
        example_id=example_id,
        revision=1,
        title=title,
        request=request,
        request_fingerprint=fingerprint_analyzer_payload(request),
        expected_status=assessment.status,
        expected_scenarios=scenarios,
        expected_assessment_fingerprint=assessment.assessment_fingerprint,
        example_fingerprint=fingerprint,
    )


_LIQUID_PH = _complete_request(
    request_id="analyzer-example.liquid-ph",
    kind=AnalyzerApplicationKind.LIQUID_PROCESS,
    family=AnalyzerAnalyteFamily.ACIDITY_ALKALINITY,
    phase=AnalyzerSamplePhase.LIQUID,
    approach=AnalyzerSampleApproach.IN_SITU,
)
_PROCESS_GAS_OXYGEN = _complete_request(
    request_id="analyzer-example.process-gas-oxygen",
    kind=AnalyzerApplicationKind.PROCESS_GAS,
    family=AnalyzerAnalyteFamily.OXYGEN,
    phase=AnalyzerSamplePhase.GAS,
    approach=AnalyzerSampleApproach.IN_SITU,
)
_GAS_CHROMATOGRAPHY = _complete_request(
    request_id="analyzer-example.gas-chromatography",
    kind=AnalyzerApplicationKind.GAS_CHROMATOGRAPHY,
    family=AnalyzerAnalyteFamily.MULTI_COMPONENT_COMPOSITION,
    phase=AnalyzerSamplePhase.GAS,
    approach=AnalyzerSampleApproach.EXTRACTIVE,
    utilities=(
        AnalyzerUtility.CALIBRATION_GAS,
        AnalyzerUtility.CARRIER_GAS,
        AnalyzerUtility.ELECTRICAL_POWER,
    ),
    cycle_seconds=60.0,
)
_TOXIC_EXTRACTIVE = _replace_nested(
    _complete_request(
        request_id="analyzer-example.toxic-extractive",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.TOXIC_GAS,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.EXTRACTIVE,
    ),
    "safety",
    toxic_material=AnalyzerTriState.YES,
)
_FLAMMABLE_DETECTION = _replace_nested(
    _complete_request(
        request_id="analyzer-example.flammable-point-detection",
        kind=AnalyzerApplicationKind.GAS_DETECTION,
        family=AnalyzerAnalyteFamily.COMBUSTIBLE_GAS,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.POINT_DETECTOR,
    ),
    "safety",
    hazardous_area=AnalyzerTriState.YES,
    hazardous_area_classification="Illustrative project hazardous-area basis",
    hazardous_area_equipment_certification_confirmed=AnalyzerTriState.YES,
    flammable_material=AnalyzerTriState.YES,
    gas_detection_safety_function=AnalyzerTriState.YES,
    alarm_basis_defined=AnalyzerTriState.YES,
    detector_coverage_basis_defined=AnalyzerTriState.YES,
    detector_response_basis_defined=AnalyzerTriState.YES,
    independence_requirement_defined=AnalyzerTriState.YES,
    proof_test_and_bypass_basis_defined=AnalyzerTriState.YES,
)
_PARTICULATE_GAS = _replace_nested(
    _complete_request(
        request_id="analyzer-example.particulate-process-gas",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.HYDROCARBON,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.EXTRACTIVE,
    ),
    "process",
    particulate_loading=AnalyzerConditionSeverity.HIGH,
    fouling_tendency=AnalyzerConditionSeverity.HIGH,
)
_WET_GAS = _replace_nested(
    _complete_request(
        request_id="analyzer-example.wet-condensing-gas",
        kind=AnalyzerApplicationKind.PROCESS_GAS,
        family=AnalyzerAnalyteFamily.MOISTURE,
        phase=AnalyzerSamplePhase.GAS,
        approach=AnalyzerSampleApproach.EXTRACTIVE,
    ),
    "process",
    normal_temperature=_quantity(QuantityKind.ABSOLUTE_TEMPERATURE, 303.15, "K"),
    dew_point_temperature=_quantity(
        QuantityKind.ABSOLUTE_TEMPERATURE,
        293.15,
        "K",
    ),
    liquid_droplets=AnalyzerConditionSeverity.MODERATE,
    wet_sample=AnalyzerConditionSeverity.HIGH,
)
_CORROSIVE_BLOCKED = _replace_nested(
    _replace_nested(
        _complete_request(
            request_id="analyzer-example.corrosive-liquid-blocked",
            kind=AnalyzerApplicationKind.LIQUID_PROCESS,
            family=AnalyzerAnalyteFamily.CONDUCTIVITY,
            phase=AnalyzerSamplePhase.LIQUID,
            approach=AnalyzerSampleApproach.IN_SITU,
        ),
        "process",
        corrosivity=AnalyzerConditionSeverity.HIGH,
    ),
    "sample_system",
    materials_compatibility_confirmed=AnalyzerTriState.NO,
)
_INSUFFICIENT = AnalyzerApplicationRequest(
    request_id="analyzer-example.insufficient-input"
)


ANALYZER_DESIGN_CASE_EXAMPLES: Final = tuple(
    sorted(
        (
            _example(
                "analyzer-example.liquid-ph",
                "Illustrative liquid pH screening",
                _LIQUID_PH,
                (
                    (
                        AnalyzerTechnology.PH_ELECTRODE,
                        AnalyzerScenarioDisposition.PLAUSIBLE,
                    ),
                ),
            ),
            _example(
                "analyzer-example.process-gas-oxygen",
                "Illustrative process-gas oxygen screening",
                _PROCESS_GAS_OXYGEN,
                (
                    (
                        AnalyzerTechnology.TUNABLE_DIODE_LASER,
                        AnalyzerScenarioDisposition.PLAUSIBLE,
                    ),
                    (
                        AnalyzerTechnology.ZIRCONIA_OXYGEN,
                        AnalyzerScenarioDisposition.PLAUSIBLE,
                    ),
                ),
            ),
            _example(
                "analyzer-example.gas-chromatography",
                "Illustrative multi-component gas analysis screening",
                _GAS_CHROMATOGRAPHY,
                (
                    (
                        AnalyzerTechnology.GAS_CHROMATOGRAPH,
                        AnalyzerScenarioDisposition.PLAUSIBLE,
                    ),
                    (
                        AnalyzerTechnology.MASS_SPECTROMETRY,
                        AnalyzerScenarioDisposition.PLAUSIBLE,
                    ),
                ),
            ),
            _example(
                "analyzer-example.toxic-extractive",
                "Illustrative toxic extractive sample screening",
                _TOXIC_EXTRACTIVE,
                ((AnalyzerTechnology.NDIR_GAS, AnalyzerScenarioDisposition.PLAUSIBLE),),
            ),
            _example(
                "analyzer-example.flammable-point-detection",
                "Illustrative flammable point-detection screening",
                _FLAMMABLE_DETECTION,
                (
                    (
                        AnalyzerTechnology.CATALYTIC_BEAD_GAS_DETECTOR,
                        AnalyzerScenarioDisposition.PLAUSIBLE,
                    ),
                    (
                        AnalyzerTechnology.INFRARED_POINT_GAS_DETECTOR,
                        AnalyzerScenarioDisposition.PLAUSIBLE,
                    ),
                ),
            ),
            _example(
                "analyzer-example.particulate-process-gas",
                "Illustrative particulate process-gas screening",
                _PARTICULATE_GAS,
                ((AnalyzerTechnology.NDIR_GAS, AnalyzerScenarioDisposition.PLAUSIBLE),),
            ),
            _example(
                "analyzer-example.wet-condensing-gas",
                "Illustrative wet and condensing gas screening",
                _WET_GAS,
                (
                    (
                        AnalyzerTechnology.TUNABLE_DIODE_LASER,
                        AnalyzerScenarioDisposition.PLAUSIBLE,
                    ),
                ),
            ),
            _example(
                "analyzer-example.corrosive-liquid-blocked",
                "Illustrative corrosive liquid blocked screening",
                _CORROSIVE_BLOCKED,
                (
                    (
                        AnalyzerTechnology.CONDUCTIVITY_CELL,
                        AnalyzerScenarioDisposition.BLOCKED,
                    ),
                ),
            ),
            _example(
                "analyzer-example.insufficient-input",
                "Illustrative fail-closed insufficient-input screening",
                _INSUFFICIENT,
                (
                    (
                        AnalyzerTechnology.PH_ELECTRODE,
                        AnalyzerScenarioDisposition.INSUFFICIENT_INFORMATION,
                    ),
                ),
            ),
        ),
        key=lambda item: item.example_id,
    )
)
ANALYZER_DESIGN_CASE_REGISTRY: Final = MappingProxyType(
    {(item.example_id, item.revision): item for item in ANALYZER_DESIGN_CASE_EXAMPLES}
)
if len(ANALYZER_DESIGN_CASE_REGISTRY) != len(ANALYZER_DESIGN_CASE_EXAMPLES):
    raise RuntimeError("duplicate analyzer design-case example identity")
for _reviewed_example in ANALYZER_DESIGN_CASE_EXAMPLES:
    validate_analyzer_design_case_example(_reviewed_example)


__all__ = [
    "ANALYZER_DESIGN_CASE_EXAMPLES",
    "ANALYZER_DESIGN_CASE_REGISTRY",
    "ANALYZER_KNOWLEDGE_LINKS",
    "ANALYZER_KNOWLEDGE_REGISTRY",
    "ANALYZER_WORKFLOW_VERSION",
    "AnalyzerAssessmentEnvelope",
    "AnalyzerDesignCaseExample",
    "AnalyzerExpectedScenario",
    "AnalyzerKnowledgeLink",
    "build_analyzer_example_fingerprint",
    "build_analyzer_integration_fingerprint",
    "resolve_analyzer_knowledge_links",
    "validate_analyzer_design_case_example",
]

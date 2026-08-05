"""Frozen Phase 7 end-to-end milestone gates for ten engineering domains.

The suite deliberately separates stateless engineering outcomes from the two
explicit persistence boundaries.  SQLite is used only as an isolated test
store for design and datasheet records; no stateless result is represented as
persisted unless it has crossed the corresponding trusted repository service.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from io import BytesIO
from types import SimpleNamespace
from uuid import UUID

import pytest
from openpyxl import load_workbook
from sqlalchemy import Engine, create_engine, event, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.database import Base
from app.engineering.calculations import (
    ENGINE_VERSION,
    ENGINEERING_METHOD_REGISTRY,
)
from app.engineering.calculations.control_valve import (
    LIQUID_CONTROL_VALVE_SIZING_METHOD_ID,
    LIQUID_CONTROL_VALVE_SIZING_METHOD_VERSION,
    LiquidControlValvePressureState,
    LiquidControlValveProperties,
    LiquidControlValveSizingInput,
    TraceableLiquidValveFactors,
    ValveInstallationBasis,
)
from app.engineering.calculations.control_valve_compressible import (
    CompressibleControlValvePressureState,
    CompressibleControlValveSizingInput,
    CompressibleFlowingProperties,
    TraceableCompressibleValveFactors,
)
from app.engineering.calculations.control_valve_installed import (
    CONTROL_VALVE_INSTALLED_METHOD_VERSION,
    INSTALLED_CONTROL_VALVE_SCREEN_METHOD_ID,
    InstalledCaseRole,
    TraceableDownstreamAcousticState,
    TraceableInstalledValveCandidate,
    TraceableTravelCapacityPoint,
    TravelWindowStatus,
)
from app.engineering.calculations.control_valve_workflow_models import (
    ControlValveDesignCaseRequest,
    ControlValveDesignDisposition,
    ControlValveOperatingPointInput,
    ControlValveOperation,
    ControlValveSafetySeverity,
    InstalledControlValveExecutionRequest,
    LiquidControlValveExecutionRequest,
)
from app.engineering.calculations.engine import CalculationEngine
from app.engineering.calculations.models import (
    CalculationInput,
    CalculationRequest,
    CalculationResult,
    CalculationStatus,
    EngineeringQuantity,
    InputOrigin,
)
from app.engineering.calculations.pressure_relief import (
    API_520_521_STANDARDS_PACK_ID,
    PRESSURE_RELIEF_STANDARDS_PACK_VERSION,
    PressureReliefFlowBasis,
    PressureReliefFluidPhase,
    PressureReliefFluidProperties,
    PressureReliefJurisdictionBasis,
    PressureReliefPressureBasis,
    PressureReliefPressureBasisKind,
    PressureReliefReadinessRequest,
    PressureReliefScenarioBasis,
    PressureReliefScenarioKind,
    PressureReliefStandardsFamily,
)
from app.engineering.calculations.pressure_relief_required_area import (
    LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
    LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION,
    LiquidPressureReliefRequiredAreaInput,
    PressureReliefRequiredAreaCase,
    TraceableLiquidReliefApplicability,
    TraceableReliefAreaCoefficients,
)
from app.engineering.calculations.pressure_relief_workflow_models import (
    LiquidPressureReliefExecutionRequest,
    PressureReliefOperation,
    PressureReliefReadinessAssessmentRequest,
    PressureReliefWorkflowDisposition,
)
from app.engineering.calculations.units import QuantityKind
from app.engineering.design.analyzer_workflow_models import (
    ANALYZER_DESIGN_CASE_EXAMPLES,
)
from app.engineering.design.datasheet_models import (
    DatasheetCalculationLink,
    DatasheetCompletenessState,
    DatasheetContent,
    DatasheetCreateCommand,
    DatasheetFieldOrigin,
    DatasheetFieldState,
    DatasheetFieldValue,
)
from app.engineering.design.datasheet_registry import (
    DATASHEET_TEMPLATES,
    DP_FLOW_TEMPLATE,
    PRESSURE_TRANSMITTER_TEMPLATE,
)
from app.engineering.design.datasheet_service import DatasheetService
from app.engineering.design.level_application_models import (
    LevelApplicationRequest,
    LevelConditionSeverity,
    LevelContactPreference,
    LevelDpArrangement,
    LevelEnvironmentCondition,
    LevelIndustrySector,
    LevelInstallationContext,
    LevelMaintenanceAccess,
    LevelMeasurementObjective,
    LevelMeasurementRequirements,
    LevelMountingPosition,
    LevelProcessContext,
    LevelProcessPhase,
    LevelSafetyContext,
    LevelScenarioDisposition,
    LevelTriState,
    LevelVaporBehavior,
    LevelVesselConfiguration,
    LevelVesselContext,
    LevelVesselGeometry,
)
from app.engineering.design.persistence_models import (
    DesignAnalyzerAssessmentCommand,
    DesignCalculationExecutionCommand,
    DesignCaseCreate,
    DesignContextItem,
    DesignRevisionPayload,
    DesignSourceOrigin,
    DesignVerification,
    EngineeringRunKind,
)
from app.engineering.design.xlsx_renderer import (
    build_datasheet_export_bundle,
)
from app.engineering.engineering_recommendation_engine import (
    EngineeringRecommendationEngine,
)
from app.engineering.knowledge_calculation_adapter import (
    CalculationResultReplayError,
    ControlledCalculationKnowledgeAdapter,
    KnowledgeFingerprintMismatchError,
    KnowledgeMethodBinding,
    fingerprint_knowledge,
    fingerprint_method_definition,
)
from app.engineering.knowledge_models import (
    EngineeringCalculationReference,
    EngineeringDiscipline,
    EngineeringFormula,
    EngineeringKnowledge,
    EvidenceReference,
    EvidenceStrength,
    EvidenceType,
    KnowledgeCategory,
    KnowledgeReview,
    KnowledgeStatus,
    ReviewDecision,
    ReviewType,
    RevisionMetadata,
    SafetyGuidance,
    SafetySeverity,
    StandardApplicability,
    StandardReference,
    VerificationRequirement,
)
from app.engineering.knowledge_service import EngineeringKnowledgeService
from app.engineering.product_selection_requirement_adapter import (
    KnowledgeSafetyBlocksSelectionError,
    ProductRequirementField,
    ProductSelectionRequirementAdapter,
    RequirementDecision,
    SelectionRequirementBinding,
)
from app.engineering.recommendation_models import EngineeringRequirements
from app.models.calculation_run import CalculationRun
from app.models.design_case import DesignCase, DesignCaseRevision
from app.models.engineering_datasheet import (
    EngineeringDatasheet,
    EngineeringDatasheetCalculationLink,
    EngineeringDatasheetRevision,
)
from app.repositories.datasheet_repository import DatasheetRepository
from app.repositories.design_repository import DesignRepository
from app.services.analyzer_application_service import (
    DEFAULT_ANALYZER_APPLICATION_SERVICE,
)
from app.services.calculation_service import CalculationService
from app.services.control_valve_service import DEFAULT_CONTROL_VALVE_SERVICE
from app.services.datasheet_persistence_service import (
    DatasheetPersistenceInputError,
    DatasheetPersistenceService,
)
from app.services.design_service import DesignPersistenceService
from app.services.dp_flow_service import DEFAULT_DP_FLOW_SERVICE
from app.services.level_application_service import (
    DEFAULT_LEVEL_APPLICATION_SERVICE,
)
from app.services.pressure_relief_service import (
    DEFAULT_PRESSURE_RELIEF_SERVICE,
)

FIXED_TIME = datetime(2026, 8, 2, 16, 0, tzinfo=UTC)
FIXED_REQUEST_ID = UUID("11200000-0000-4000-8000-000000000001")
FIXED_CALCULATION_ID = UUID("11200000-0000-4000-8000-000000000002")
CASE_ID = UUID("11200000-0000-4000-8000-000000000003")
DESIGN_REVISION_ID = UUID("11200000-0000-4000-8000-000000000004")
RUN_ID = UUID("11200000-0000-4000-8000-000000000005")
DATASHEET_ID = UUID("11200000-0000-4000-8000-000000000006")
DATASHEET_REVISION_ID = UUID("11200000-0000-4000-8000-000000000007")
LEVEL_RUN_ID = UUID("11200000-0000-4000-8000-000000000008")
ANALYZER_RUN_ID = UUID("11200000-0000-4000-8000-000000000009")
LEVEL_REQUEST_ID = UUID("11200000-0000-4000-8000-000000000010")

KNOWLEDGE_ID = "knowledge.phase7.pressure-selection"
KNOWLEDGE_REVISION = "1.0"
CALCULATION_REFERENCE_ID = "knowledge.calculation.absolute-pressure"
METHOD_ID = "general.pressure.gauge-to-absolute"
METHOD_VERSION = "1.0.0"
CALCULATION_TYPE = "general.pressure.gauge-to-absolute"
KNOWLEDGE_BINDING_ID = "binding.phase7.absolute-pressure"
REQUIREMENT_BINDING_ID = "binding.phase7.process-pressure"
OUTPUT_ID = "absolute-pressure"
FORMULA_SENTINEL = "__import__('os').system('PHASE7_KNOWLEDGE_FORMULA_EXECUTED')"
KNOWN_KNOWLEDGE_FINGERPRINT = (
    "0c51bebd826770d8a7b2a644bb6104d828efc3cb13a91fcd7d2e1521fd87e216"
)
KNOWN_BLOCKING_KNOWLEDGE_FINGERPRINT = (
    "f6594167c538e58bd37068cb8038b27b9ac40b802a874044e745ce7a6b007666"
)
KNOWN_METHOD_DEFINITION_FINGERPRINT = (
    "e106e0371d6edd96abba813c631ba40d56ed0b5973238adf20e43637b5f885d1"
)


def _quantity(
    kind: QuantityKind,
    value: float,
    unit: str,
) -> EngineeringQuantity:
    return EngineeringQuantity(
        quantity_kind=kind.value,
        value=value,
        unit=unit,
    )


def _pressure_request() -> CalculationRequest:
    definition = ENGINEERING_METHOD_REGISTRY.resolve(
        METHOD_ID,
        METHOD_VERSION,
        calculation_type=CALCULATION_TYPE,
    )
    supplied = {
        "gauge-pressure": _quantity(
            QuantityKind.GAUGE_PRESSURE,
            298.675,
            "kPa",
        ),
        "atmospheric-pressure": _quantity(
            QuantityKind.ABSOLUTE_PRESSURE,
            101.325,
            "kPa",
        ),
    }
    return CalculationRequest(
        request_id=FIXED_REQUEST_ID,
        calculation_type=CALCULATION_TYPE,
        method_id=METHOD_ID,
        method_version=METHOD_VERSION,
        requested_at=FIXED_TIME,
        requested_by="Phase 7 milestone engineer",
        inputs=tuple(
            CalculationInput(
                input_id=specification.input_id,
                name=specification.name,
                origin=InputOrigin.USER_SUPPLIED,
                quantity=supplied[specification.input_id],
            )
            for specification in definition.input_specifications
        ),
    )


def _level_calculation_request() -> CalculationRequest:
    method_id = "level.hydrostatic.column-pressure"
    method_version = "1.0.0"
    definition = ENGINEERING_METHOD_REGISTRY.resolve(
        method_id,
        method_version,
    )
    supplied = {
        "density": _quantity(QuantityKind.DENSITY, 900.0, "kg/m3"),
        "vertical-height": _quantity(QuantityKind.LENGTH, 3.5, "m"),
        "gravitational-acceleration": _quantity(
            QuantityKind.ACCELERATION,
            9.80665,
            "m/s2",
        ),
    }
    return CalculationRequest(
        request_id=LEVEL_REQUEST_ID,
        calculation_type=definition.calculation_type,
        method_id=method_id,
        method_version=method_version,
        requested_at=FIXED_TIME,
        requested_by="Phase 7 milestone engineer",
        inputs=tuple(
            CalculationInput(
                input_id=specification.input_id,
                name=specification.name,
                origin=InputOrigin.USER_SUPPLIED,
                quantity=supplied[specification.input_id],
            )
            for specification in definition.input_specifications
        ),
    )


def _calculation_engine() -> CalculationEngine:
    return CalculationEngine(
        registry=ENGINEERING_METHOD_REGISTRY,
        clock=lambda: FIXED_TIME,
        id_factory=lambda: FIXED_CALCULATION_ID,
    )


def _pressure_result():
    return _calculation_engine().execute(_pressure_request())


def _incomplete_pressure_result() -> CalculationResult:
    request = _pressure_request()
    incomplete = request.model_copy(update={"inputs": request.inputs[:1]})
    result = _calculation_engine().execute(incomplete)
    assert result.status is CalculationStatus.INSUFFICIENT_INPUT
    return result


def _tampered_pressure_result() -> CalculationResult:
    result = _pressure_result()
    output = next(item for item in result.outputs if item.output_id == OUTPUT_ID)
    assert output.quantity is not None
    tampered_quantity = output.quantity.model_copy(
        update={"value": output.quantity.value + 10_000.0}
    )
    updated_output = output.model_copy(update={"quantity": tampered_quantity})
    updated_steps = tuple(
        step.model_copy(
            update={
                "output_values": tuple(
                    trace_value.model_copy(update={"quantity": tampered_quantity})
                    if trace_value.value_id in output.source_value_ids
                    else trace_value
                    for trace_value in step.output_values
                )
            }
        )
        for step in result.trace_steps
    )
    tampered = result.model_copy(
        update={
            "outputs": (updated_output,),
            "trace_steps": updated_steps,
        }
    )
    assert tampered.result_fingerprint == result.result_fingerprint
    return tampered


def _approved_review(review_type: ReviewType) -> KnowledgeReview:
    return KnowledgeReview(
        review_type=review_type,
        decision=ReviewDecision.APPROVED,
        reviewer_name="Phase 7 milestone reviewer",
        reviewer_role="Competent engineering reviewer",
        reviewed_at=FIXED_TIME,
    )


def _published_pressure_knowledge(
    *,
    blocking_safety: bool = False,
) -> EngineeringKnowledge:
    return EngineeringKnowledge(
        knowledge_id=KNOWLEDGE_ID,
        title="Controlled absolute-pressure requirement knowledge",
        subject="Pressure-basis calculation and candidate requirement",
        summary=(
            "A reviewed link from an explicit pressure basis to one candidate "
            "product-selection requirement."
        ),
        detailed_guidance=(
            "Execute only the approved application method and preserve a "
            "different user-supplied requirement as an explicit conflict."
        ),
        discipline=EngineeringDiscipline.INSTRUMENTATION,
        categories=(
            KnowledgeCategory.CALCULATION,
            KnowledgeCategory.SELECTION,
        ),
        status=KnowledgeStatus.PUBLISHED,
        safety=SafetyGuidance(
            safety_summary=(
                "Verify gauge, absolute, and atmospheric pressure bases before "
                "using the result."
            ),
            severity=SafetySeverity.WARNING,
            required_site_risk_assessment=True,
            blocks_work_until_resolved=blocking_safety,
        ),
        standards=(
            StandardReference(
                organisation="BIPM",
                standard_number="SI Brochure",
                title="The International System of Units",
                edition="9",
                publication_year=2019,
                clause="Pressure units",
                applicability=StandardApplicability.INFORMATIVE,
            ),
        ),
        evidence=(
            EvidenceReference(
                evidence_id="evidence.phase7.pressure-basis",
                evidence_type=EvidenceType.ENGINEERING_TEXTBOOK,
                title="Reviewed pressure-basis reference",
                strength=EvidenceStrength.HIGH,
                verified=True,
                verified_by="Phase 7 milestone reviewer",
                verified_at=FIXED_TIME,
            ),
        ),
        calculations=(
            EngineeringCalculationReference(
                calculation_id=CALCULATION_REFERENCE_ID,
                title="Approved absolute-pressure candidate calculation",
                purpose=(
                    "Bind exact reviewed method metadata without executing "
                    "knowledge formula text."
                ),
                formulas=(
                    EngineeringFormula(
                        formula_id="formula.phase7.inert.absolute-pressure",
                        name="Inert pressure-basis sentinel",
                        expression=FORMULA_SENTINEL,
                        description=(
                            "Deliberately non-executable knowledge text proving "
                            "that only the allow-listed application method can "
                            "execute."
                        ),
                    ),
                ),
                required_inputs=(
                    "Gauge pressure",
                    "Atmospheric absolute pressure",
                ),
                required_units={
                    "Gauge pressure": "pressure",
                    "Atmospheric absolute pressure": "pressure",
                },
                validation_rules=("Both pressure bases must be explicit.",),
                safety_warnings=("Confirm the atmospheric pressure input.",),
                verification_requirements=(
                    VerificationRequirement(
                        verification_id="verify.phase7.pressure-basis",
                        description="Verify pressure basis and units.",
                        method="Independent calculation review",
                        expected_result="The output is absolute pressure.",
                    ),
                ),
            ),
        ),
        reviews=tuple(
            _approved_review(review_type)
            for review_type in (
                ReviewType.TECHNICAL,
                ReviewType.SAFETY,
                ReviewType.STANDARDS,
                ReviewType.FINAL_APPROVAL,
            )
        ),
        revision_metadata=RevisionMetadata(
            revision=KNOWLEDGE_REVISION,
            created_by="Phase 7 milestone suite",
            created_at=FIXED_TIME,
        ),
        confidence_score=95.0,
    )


def _knowledge_adapter(
    *,
    knowledge_fingerprint: str = KNOWN_KNOWLEDGE_FINGERPRINT,
) -> ControlledCalculationKnowledgeAdapter:
    binding = KnowledgeMethodBinding(
        binding_id=KNOWLEDGE_BINDING_ID,
        knowledge_id=KNOWLEDGE_ID,
        knowledge_revision=KNOWLEDGE_REVISION,
        calculation_reference_id=CALCULATION_REFERENCE_ID,
        method_id=METHOD_ID,
        method_version=METHOD_VERSION,
        calculation_type=CALCULATION_TYPE,
        engine_version=ENGINE_VERSION,
        knowledge_fingerprint=knowledge_fingerprint,
        method_definition_fingerprint=KNOWN_METHOD_DEFINITION_FINGERPRINT,
    )
    return ControlledCalculationKnowledgeAdapter(
        registry=ENGINEERING_METHOD_REGISTRY,
        bindings=(binding,),
    )


def _selection_adapter(
    *,
    knowledge_fingerprint: str = KNOWN_KNOWLEDGE_FINGERPRINT,
) -> ProductSelectionRequirementAdapter:
    return ProductSelectionRequirementAdapter(
        knowledge_adapter=_knowledge_adapter(
            knowledge_fingerprint=knowledge_fingerprint,
        ),
        bindings=(
            SelectionRequirementBinding(
                binding_id=REQUIREMENT_BINDING_ID,
                knowledge_method_binding_id=KNOWLEDGE_BINDING_ID,
                output_id=OUTPUT_ID,
                quantity_kind=QuantityKind.ABSOLUTE_PRESSURE,
                output_unit="Pa",
                target_field=ProductRequirementField.PROCESS_PRESSURE_BAR,
                target_unit="bar",
            ),
        ),
    )


def _selection_requirements() -> EngineeringRequirements:
    return EngineeringRequirements(
        measurement_type="Pressure transmitter",
        process_temperature_c=100.0,
        process_pressure_bar=None,
        ambient_temperature_c=40.0,
        required_accuracy_percent=0.25,
        required_ingress_protection_rating="IP65",
        hazardous_area_required=True,
        required_hazardous_area_approvals=["ATEX"],
        process_medium="Water",
        required_wetted_materials=["316L Stainless Steel"],
        required_process_connections=["1/2 NPT"],
        required_protocols=["HART"],
        installation_environment=["Outdoor"],
    )


def _selection_candidate() -> SimpleNamespace:
    return SimpleNamespace(
        id=112,
        name="Pressure Transmitter",
        model="PT-112",
        model_number="PT-112",
        manufacturer=SimpleNamespace(name="Fixture Instruments"),
        minimum_process_temperature_c=-40.0,
        maximum_process_temperature_c=200.0,
        minimum_process_pressure_bar=0.0,
        maximum_process_pressure_bar=100.0,
        minimum_ambient_temperature_c=-20.0,
        maximum_ambient_temperature_c=70.0,
        accuracy_percent=0.1,
        ingress_protection_rating="IP66",
        hazardous_area_approvals=["ATEX", "IECEx"],
        wetted_materials=["316L Stainless Steel"],
        process_connections=["1/2 NPT"],
        protocols=[SimpleNamespace(name="HART")],
    )


def _level_application_request():
    return {
        "industry": LevelIndustrySector.CHEMICAL,
        "industry_detail": "Batch liquid storage",
        "measurement": LevelMeasurementRequirements(
            objectives=(LevelMeasurementObjective.CONTINUOUS_LEVEL,),
            measurement_span=_quantity(QuantityKind.LENGTH, 5.0, "m"),
            upper_dead_zone_allowance=_quantity(
                QuantityKind.LENGTH,
                0.2,
                "m",
            ),
            lower_dead_zone_allowance=_quantity(
                QuantityKind.LENGTH,
                0.1,
                "m",
            ),
            required_accuracy_percent_of_span=1.0,
            required_response_time=_quantity(QuantityKind.TIME, 2.0, "s"),
            contact_preference=LevelContactPreference.CONTACT_ACCEPTABLE,
            continuous_output_required=LevelTriState.YES,
            local_indication_required=LevelTriState.NO,
        ),
        "process": LevelProcessContext(
            phase=LevelProcessPhase.LIQUID,
            medium_description="Stable process liquid",
            vapor_space_composition="Air and process vapor",
            vapor_space_behavior=LevelVaporBehavior.STABLE,
            minimum_temperature=_quantity(
                QuantityKind.ABSOLUTE_TEMPERATURE,
                0.0,
                "degC",
            ),
            normal_temperature=_quantity(
                QuantityKind.ABSOLUTE_TEMPERATURE,
                25.0,
                "degC",
            ),
            maximum_temperature=_quantity(
                QuantityKind.ABSOLUTE_TEMPERATURE,
                80.0,
                "degC",
            ),
            normal_absolute_pressure=_quantity(
                QuantityKind.ABSOLUTE_PRESSURE,
                110.0,
                "kPa",
            ),
            maximum_absolute_pressure=_quantity(
                QuantityKind.ABSOLUTE_PRESSURE,
                400.0,
                "kPa",
            ),
            bulk_density=_quantity(QuantityKind.DENSITY, 900.0, "kg/m3"),
            lower_fluid_density=_quantity(
                QuantityKind.DENSITY,
                1000.0,
                "kg/m3",
            ),
            upper_fluid_density=_quantity(
                QuantityKind.DENSITY,
                800.0,
                "kg/m3",
            ),
            density_variation_percent=2.0,
            dielectric_constant=4.0,
            dynamic_viscosity=_quantity(
                QuantityKind.DYNAMIC_VISCOSITY,
                5.0,
                "mPa.s",
            ),
            foam=LevelConditionSeverity.NONE,
            turbulence=LevelConditionSeverity.NONE,
            steam=LevelConditionSeverity.NONE,
            condensation=LevelConditionSeverity.NONE,
            dust=LevelConditionSeverity.NONE,
            buildup=LevelConditionSeverity.NONE,
            slurry=LevelConditionSeverity.NONE,
            sticky_material=LevelConditionSeverity.NONE,
            agitation=LevelConditionSeverity.NONE,
            corrosive_service=LevelConditionSeverity.NONE,
            abrasive_service=LevelConditionSeverity.NONE,
            hygienic_service=LevelConditionSeverity.NONE,
        ),
        "vessel": LevelVesselContext(
            configuration=LevelVesselConfiguration.CLOSED,
            geometry=LevelVesselGeometry.VERTICAL_CYLINDER,
            dp_arrangement=LevelDpArrangement.REMOTE_SEALS,
            internal_diameter=_quantity(QuantityKind.LENGTH, 3.0, "m"),
            straight_side_height=_quantity(QuantityKind.LENGTH, 6.0, "m"),
            cylindrical_length=_quantity(QuantityKind.LENGTH, 6.0, "m"),
            lower_level_elevation=_quantity(QuantityKind.LENGTH, 0.5, "m"),
            upper_level_elevation=_quantity(QuantityKind.LENGTH, 5.5, "m"),
            nozzle_diameter=_quantity(QuantityKind.LENGTH, 0.15, "m"),
            nozzle_height=_quantity(QuantityKind.LENGTH, 0.3, "m"),
            nozzle_geometry_confirmed=LevelTriState.YES,
            available_mounting_positions=(
                LevelMountingPosition.TOP,
                LevelMountingPosition.SIDE,
                LevelMountingPosition.EXTERNAL_CHAMBER,
                LevelMountingPosition.NON_INTRUSIVE_EXTERNAL,
            ),
            mounting_constraints="Clear top and side access is available.",
            top_mounting_available=LevelTriState.YES,
            side_connection_available=LevelTriState.YES,
            internal_obstructions=LevelConditionSeverity.NONE,
        ),
        "installation": LevelInstallationContext(
            environments=(LevelEnvironmentCondition.OUTDOOR,),
            maintenance_access=LevelMaintenanceAccess.EASY,
            minimum_ambient_temperature=_quantity(
                QuantityKind.ABSOLUTE_TEMPERATURE,
                -20.0,
                "degC",
            ),
            maximum_ambient_temperature=_quantity(
                QuantityKind.ABSOLUTE_TEMPERATURE,
                50.0,
                "degC",
            ),
            electrical_power_available=LevelTriState.YES,
            instrument_air_available=LevelTriState.NO,
        ),
        "safety": LevelSafetyContext(
            hazardous_area=LevelTriState.NO,
            independent_protection_required=LevelTriState.NO,
            radiometric_source_permitted=LevelTriState.YES,
            radiation_protection_program_confirmed=LevelTriState.YES,
            flammable_material=LevelTriState.NO,
            toxic_material=LevelTriState.NO,
        ),
        "application_notes": ("Step 112 typed multidisciplinary screening fixture."),
    }


def _liquid_control_valve_request() -> LiquidControlValveExecutionRequest:
    sizing_input = LiquidControlValveSizingInput(
        case_id="PHASE7-VALVE-LIQUID",
        actual_volumetric_flow_m3_h=100.0,
        volumetric_flow_basis="actual_at_inlet_conditions",
        flow_source_reference="controlled Step 112 flow record",
        flow_condition_basis="actual liquid volume at declared inlet conditions",
        properties=LiquidControlValveProperties(
            specific_gravity=1.0,
            flowing_temperature_k=293.15,
            vapor_pressure_absolute_pa=20_000.0,
            critical_pressure_absolute_pa=22_064_000.0,
            thermodynamic_pressure_basis="absolute",
            property_source_reference="controlled Step 112 property record",
            condition_basis="properties at the simultaneous inlet condition",
        ),
        pressure_state=LiquidControlValvePressureState(
            upstream_pressure_absolute_pa=1_000_000.0,
            downstream_pressure_absolute_pa=700_000.0,
            pressure_basis="absolute",
            pressure_source_reference="controlled Step 112 pressure record",
            condition_basis="simultaneous steady design pressures",
        ),
        factors=TraceableLiquidValveFactors(
            installation_basis=ValveInstallationBasis.BARE_VALVE,
            bare_valve_pressure_recovery_factor=0.9,
            source_reference="controlled Step 112 candidate factor record",
            applicable_conditions=(
                "exact valve, size, trim, travel, direction, and arrangement"
            ),
            supplied_by="competent control-valve engineer",
        ),
        outlet_inside_diameter_m=0.15,
        outlet_diameter_source_reference="controlled downstream pipe record",
        fluid_phase="liquid",
        rheology="newtonian",
        turbulent_flow_confirmed=True,
        incompressible_flow_confirmed=True,
        single_phase_inlet_confirmed=True,
        suspended_solids_absent_confirmed=True,
    )
    return LiquidControlValveExecutionRequest(
        operation=ControlValveOperation.LIQUID_SIZING,
        method_id=LIQUID_CONTROL_VALVE_SIZING_METHOD_ID,
        method_version=LIQUID_CONTROL_VALVE_SIZING_METHOD_VERSION,
        sizing_input=sizing_input,
    )


def _installed_valve_sizing_input(
    case_id: str,
    mass_flow_kg_h: float,
    travel_percent: float,
) -> CompressibleControlValveSizingInput:
    return CompressibleControlValveSizingInput(
        case_id=case_id,
        mass_flow_kg_h=mass_flow_kg_h,
        mass_flow_source_reference="controlled mass-flow record FLOW-101",
        flow_condition_basis="steady mass rate at the declared flowing state",
        pressure_state=CompressibleControlValvePressureState(
            upstream_pressure_absolute_pa=1_000_000.0,
            downstream_pressure_absolute_pa=800_000.0,
            pressure_basis="absolute",
            pressure_source_reference="controlled operating record OP-101",
            condition_basis=("simultaneous steady upstream and downstream pressures"),
        ),
        properties=CompressibleFlowingProperties(
            fluid_phase="gas",
            fluid_identity="controlled nitrogen basis",
            upstream_temperature_k=300.0,
            upstream_density_kg_m3=10.0,
            isentropic_exponent=1.4,
            compressibility_factor=1.0,
            molecular_mass_kg_kmol=28.0134,
            property_source_reference="controlled property record PROP-101",
            condition_basis="properties at the exact upstream P1 and T1 state",
        ),
        factors=TraceableCompressibleValveFactors(
            candidate_id="CAND-101",
            trim_id="TRIM-101",
            installation_context_id="INSTALLATION-101",
            travel_percent=travel_percent,
            flow_direction="flow to open",
            installation_basis=ValveInstallationBasis.BARE_VALVE,
            bare_valve_pressure_drop_ratio_factor=0.5,
            source_reference="controlled factor record XT-101",
            applicable_conditions=("exact candidate trim travel direction and state"),
            supplied_by="competent control-valve engineer",
        ),
        turbulent_flow_confirmed=True,
        homogeneous_composition_confirmed=True,
        single_phase_inlet_confirmed=True,
        single_phase_outlet_confirmed=True,
        no_condensation_or_phase_change_confirmed=True,
        property_state_aligned_confirmed=True,
    )


def _installed_valve_operating_point(
    case_id: str,
    mass_flow_kg_h: float,
    travel_percent: float,
) -> ControlValveOperatingPointInput:
    return ControlValveOperatingPointInput(
        sizing_input=_installed_valve_sizing_input(
            case_id,
            mass_flow_kg_h,
            travel_percent,
        ),
        downstream_acoustic_state=TraceableDownstreamAcousticState(
            sizing_case_id=case_id,
            candidate_id="CAND-101",
            trim_id="TRIM-101",
            flow_direction="flow to open",
            installation_context_id="INSTALLATION-101",
            downstream_density_kg_m3=8.0,
            downstream_speed_of_sound_m_s=350.0,
            downstream_pipe_inside_diameter_m=0.2,
            source_reference="controlled downstream-state record DOWN-101",
            condition_basis=("exact simultaneous downstream density and sound speed"),
        ),
    )


def _installed_control_valve_request(
    *,
    blocking: bool = True,
) -> InstalledControlValveExecutionRequest:
    candidate = TraceableInstalledValveCandidate(
        candidate_id="CAND-101",
        trim_id="TRIM-101",
        installation_context_id="INSTALLATION-101",
        flow_direction="flow to open",
        capacity_curve=tuple(
            TraceableTravelCapacityPoint(
                travel_percent=travel_percent,
                available_cv=available_cv,
            )
            for travel_percent, available_cv in (
                (10.0, 4.72541838017707),
                (20.0, 9.45083676035414),
                (40.0, 18.90167352070828),
                (60.0, 28.35251028106242),
                (100.0, 56.70502056212484),
            )
        ),
        minimum_controllable_travel_percent=30.0 if blocking else 15.0,
        maximum_recommended_travel_percent=90.0,
        declared_inherent_rangeability=50.0,
        maximum_factor_travel_mismatch_percent=1.0,
        interpolation_basis="caller_supplied_piecewise_linear",
        source_reference="controlled installed characteristic record CURVE-101",
        applicable_conditions=("exact candidate trim direction and installed context"),
        supplied_by="competent control-valve engineer",
    )
    return InstalledControlValveExecutionRequest(
        operation=ControlValveOperation.INSTALLED_SCREEN,
        method_id=INSTALLED_CONTROL_VALVE_SCREEN_METHOD_ID,
        method_version=CONTROL_VALVE_INSTALLED_METHOD_VERSION,
        screen_id="WORKFLOW-INSTALLED-102",
        candidate=candidate,
        minimum_case=_installed_valve_operating_point("CASE-MIN", 1_000.0, 20.0),
        normal_case=_installed_valve_operating_point(
            "CASE-NORMAL",
            2_000.0,
            40.0,
        ),
        maximum_case=_installed_valve_operating_point("CASE-MAX", 3_000.0, 60.0),
        candidate_binding_confirmed=True,
        candidate_binding_source_reference=(
            "controlled Step 102 candidate binding record"
        ),
    )


def _control_valve_design_case_request(
    *,
    blocking: bool = True,
) -> ControlValveDesignCaseRequest:
    return ControlValveDesignCaseRequest(
        design_case_id="E4M-PHASE7-112",
        revision=1,
        title="Phase 7 nitrogen control-valve preliminary design",
        service_description=(
            "Controlled nitrogen service with exact minimum, normal, and maximum cases."
        ),
        installed_execution_request=_installed_control_valve_request(blocking=blocking),
    )


def _liquid_relief_execution_request() -> LiquidPressureReliefExecutionRequest:
    flow_basis = PressureReliefFlowBasis(
        required_relieving_mass_flow_kg_s=5.0,
        load_determination_reference="CALC-PHASE7-RELIEF-LOAD",
        load_determination_basis=(
            "The required flow comes from an independently reviewed blocked-"
            "outlet scenario."
        ),
        supplied_by="Process engineering",
    )
    scenario = PressureReliefScenarioBasis(
        scenario_id="phase7-blocked-outlet",
        scenario_kind=PressureReliefScenarioKind.BLOCKED_OUTLET,
        title="Phase 7 controlled blocked-outlet case",
        protected_equipment_reference="V-112",
        scenario_description=(
            "A credible blocked outlet occurs while the documented feed "
            "continues at the relieving condition."
        ),
        credibility_confirmed=True,
        credibility_basis_reference="HAZOP-PHASE7-NODE-112",
        flow_basis=flow_basis,
    )
    readiness = PressureReliefReadinessRequest(
        request_id="phase7-liquid-relief",
        scenarios=(scenario,),
        pressure_basis=PressureReliefPressureBasis(
            basis_kind=PressureReliefPressureBasisKind.ABSOLUTE,
            set_pressure_pa=1_000_000.0,
            maximum_allowable_working_pressure_pa=1_000_000.0,
            relieving_pressure_pa=1_000_000.0,
            total_backpressure_pa=100_000.0,
            pressure_source_reference="V-112-DESIGN-DATA-REV-A",
        ),
        jurisdiction_basis=PressureReliefJurisdictionBasis(
            jurisdiction_id="ZA-project-jurisdiction",
            authority_having_jurisdiction="Project pressure-equipment authority",
            applicable_design_code_reference="PROJECT-DESIGN-CODE-REV-A",
            standards_family=PressureReliefStandardsFamily.API_520_521,
            exact_edition_and_amendment_reference=(
                "CONTROLLED-STANDARD-REGISTER-REV-A"
            ),
            jurisdiction_source_reference="PROJECT-CODE-BASIS-REV-A",
        ),
        fluid_properties=PressureReliefFluidProperties(
            phase=PressureReliefFluidPhase.LIQUID,
            relieving_temperature_k=300.0,
            liquid_density_kg_m3=1_000.0,
            property_source_reference="PROCESS-DATASHEET-RELIEF-REV-A",
            condition_basis=(
                "Properties apply at the declared relieving pressure and temperature."
            ),
        ),
        selected_standards_pack_id=API_520_521_STANDARDS_PACK_ID,
        selected_standards_pack_version=PRESSURE_RELIEF_STANDARDS_PACK_VERSION,
        competency_requirement_acknowledged=True,
        proposed_reviewer_evidence_reference="REVIEW-ASSIGNMENT-PRV-112",
    )
    sizing_input = LiquidPressureReliefRequiredAreaInput(
        case=PressureReliefRequiredAreaCase(
            readiness_request=readiness,
            scenario_id=scenario.scenario_id,
            method_basis_reference="CONTROLLED-STANDARD-REGISTER-REV-A",
            application_basis=(
                "The generic equation is selected for the separately reviewed "
                "scenario inside its stated applicability boundary."
            ),
            supplied_by="Pressure-systems engineer",
            device_inlet_pressure_basis_confirmed=True,
            downstream_system_basis_confirmed=True,
        ),
        coefficients=TraceableReliefAreaCoefficients(
            coefficient_set_id="coefficients.phase7.reviewed",
            discharge_coefficient=0.8,
            discharge_coefficient_source_reference="COEFF-CD-REV-A",
            discharge_coefficient_role="capacity_discharge_coefficient",
            combined_correction_factor=1.0,
            combined_correction_factor_source_reference="COEFF-K-REV-A",
            combined_correction_factor_role="combined_correction_factor",
            standards_basis_reference="CONTROLLED-STANDARD-REGISTER-REV-A",
            applicable_conditions=(
                "The supplied coefficients apply only to this declared fluid, "
                "pressure, temperature, backpressure, and installation basis."
            ),
            supplied_by="Pressure-systems engineer",
            all_required_corrections_included=True,
            double_counting_review_completed=True,
        ),
        applicability=TraceableLiquidReliefApplicability(
            vapor_pressure_absolute_pa=50_000.0,
            vapor_pressure_source_reference="FLUID-PROPERTY-RECORD-REV-A",
            confirmation_reference="LIQUID-APPLICABILITY-REVIEW-REV-A",
            single_phase_incompressible_confirmed=True,
            nonflashing_noncavitating_confirmed=True,
            newtonian_or_calibrated_coefficient_confirmed=True,
        ),
    )
    return LiquidPressureReliefExecutionRequest(
        operation=PressureReliefOperation.LIQUID_REQUIRED_AREA,
        method_id=LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_ID,
        method_version=LIQUID_PRESSURE_RELIEF_REQUIRED_AREA_METHOD_VERSION,
        sizing_input=sizing_input,
    )


class _Ids:
    def __init__(self, *values: UUID) -> None:
        self._values = iter(values)

    def __call__(self) -> UUID:
        return next(self._values)


@dataclass(frozen=True)
class _PersistenceContext:
    engine: Engine
    session: Session
    design_repository: DesignRepository
    design_service: DesignPersistenceService
    datasheet_service: DatasheetPersistenceService


@pytest.fixture
def persistence() -> Iterator[_PersistenceContext]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(
        engine,
        tables=(
            DesignCase.__table__,
            DesignCaseRevision.__table__,
            CalculationRun.__table__,
            EngineeringDatasheet.__table__,
            EngineeringDatasheetRevision.__table__,
            EngineeringDatasheetCalculationLink.__table__,
        ),
    )
    with Session(engine) as session:
        design_repository = DesignRepository(session)
        calculation_service = CalculationService(engine=_calculation_engine())
        design_service = DesignPersistenceService(
            repository=design_repository,
            calculation_service=calculation_service,
            clock=lambda: FIXED_TIME,
            id_factory=_Ids(
                CASE_ID,
                DESIGN_REVISION_ID,
                RUN_ID,
                LEVEL_RUN_ID,
                ANALYZER_RUN_ID,
            ),
        )
        datasheet_service = DatasheetPersistenceService(
            repository=DatasheetRepository(session),
            design_repository=design_repository,
            clock=lambda: FIXED_TIME,
            id_factory=_Ids(DATASHEET_REVISION_ID),
        )
        yield _PersistenceContext(
            engine=engine,
            session=session,
            design_repository=design_repository,
            design_service=design_service,
            datasheet_service=datasheet_service,
        )
    engine.dispose()


def _create_design_case(context: _PersistenceContext):
    return context.design_service.create_case(
        DesignCaseCreate(
            case_reference="E4M-PHASE7-112",
            case_type="multidiscipline-milestone",
            payload=DesignRevisionPayload(
                title="Phase 7 controlled milestone design",
                discipline="process-instrumentation",
                industry="Chemical processing",
                source_origins=(
                    DesignSourceOrigin(
                        source_id="source.phase7.process-basis",
                        origin=InputOrigin.DOCUMENT_EXTRACTED,
                        description="Reviewed Phase 7 process design basis",
                        reference_ids=("process-datasheet.phase7.rev-a",),
                    ),
                ),
                plant_context=(
                    DesignContextItem(
                        field_id="maximum-process-pressure",
                        label="Maximum process pressure",
                        value="4.0",
                        unit="bar(a)",
                        origin=InputOrigin.DOCUMENT_EXTRACTED,
                        source_origin_ids=("source.phase7.process-basis",),
                    ),
                    DesignContextItem(
                        field_id="normal-process-temperature",
                        label="Normal process temperature",
                        value="25.0",
                        unit="degC",
                        origin=InputOrigin.DOCUMENT_EXTRACTED,
                        source_origin_ids=("source.phase7.process-basis",),
                    ),
                ),
                equipment_context=(
                    DesignContextItem(
                        field_id="protected-equipment",
                        label="Protected equipment reference",
                        value="V-112",
                        origin=InputOrigin.DOCUMENT_EXTRACTED,
                        source_origin_ids=("source.phase7.process-basis",),
                    ),
                ),
                required_verifications=(
                    DesignVerification(
                        verification_id="verify.phase7.process-basis",
                        action=(
                            "Confirm normal, maximum, and relieving process "
                            "conditions against the approved design basis."
                        ),
                        responsible_discipline="Process engineering",
                        safety_critical=True,
                        source_origin_ids=("source.phase7.process-basis",),
                    ),
                    DesignVerification(
                        verification_id="verify.phase7.instrumentation",
                        action=(
                            "Verify pressure, level, DP-flow, valve, and analyzer "
                            "application evidence."
                        ),
                        responsible_discipline="Instrumentation engineering",
                        safety_critical=True,
                        source_origin_ids=("source.phase7.process-basis",),
                    ),
                    DesignVerification(
                        verification_id="verify.phase7.mechanical-integrity",
                        action=(
                            "Verify vessel, piping, control-valve, and relief "
                            "mechanical integrity boundaries."
                        ),
                        responsible_discipline="Mechanical/Piping engineering",
                        safety_critical=True,
                        source_origin_ids=("source.phase7.process-basis",),
                    ),
                    DesignVerification(
                        verification_id="verify.phase7.electrical-automation",
                        action=(
                            "Verify power, communications, automation, and "
                            "fail-safe integration requirements."
                        ),
                        responsible_discipline="Electrical/Automation engineering",
                        safety_critical=True,
                        source_origin_ids=("source.phase7.process-basis",),
                    ),
                    DesignVerification(
                        verification_id="verify.phase7.process-safety",
                        action=(
                            "Verify hazard-study safeguards, relief scenarios, "
                            "and independent protection requirements."
                        ),
                        responsible_discipline="Process Safety engineering",
                        safety_critical=True,
                        source_origin_ids=("source.phase7.process-basis",),
                    ),
                    DesignVerification(
                        verification_id="verify.phase7.maintenance-reliability",
                        action=(
                            "Verify maintainability, proof-test access, spare "
                            "strategy, and reliability assumptions."
                        ),
                        responsible_discipline="Maintenance/Reliability engineering",
                        safety_critical=True,
                        source_origin_ids=("source.phase7.process-basis",),
                    ),
                ),
            ),
            change_reason="Create the frozen Phase 7 milestone case.",
            created_by="Phase 7 milestone engineer",
        )
    )


def _persist_pressure_run(context: _PersistenceContext):
    return context.design_service.execute_calculation(
        CASE_ID,
        DesignCalculationExecutionCommand(
            design_revision_number=1,
            calculation=_pressure_request(),
            created_by="Phase 7 milestone engineer",
        ),
    )


def _persist_level_run(context: _PersistenceContext):
    return context.design_service.execute_calculation(
        CASE_ID,
        DesignCalculationExecutionCommand(
            design_revision_number=1,
            calculation=_level_calculation_request(),
            created_by="Phase 7 milestone engineer",
        ),
    )


def _analyzer_example():
    return next(
        item
        for item in ANALYZER_DESIGN_CASE_EXAMPLES
        if item.example_id == "analyzer-example.process-gas-oxygen"
    )


def _persist_analyzer_run(context: _PersistenceContext):
    example = _analyzer_example()
    return context.design_service.assess_analyzer(
        CASE_ID,
        DesignAnalyzerAssessmentCommand(
            design_revision_number=1,
            request=example.request,
            created_by="Phase 7 milestone engineer",
        ),
    )


def _pressure_datasheet_content(
    design,
    execution,
    *,
    calculation_link: DatasheetCalculationLink | None = None,
    field_value: EngineeringQuantity | None = None,
) -> tuple[DatasheetContent, DatasheetCalculationLink]:
    output = next(
        item for item in execution.result.outputs if item.output_id == OUTPUT_ID
    )
    link = calculation_link or DatasheetCalculationLink.from_engineering_run(
        link_id="link.phase7.maximum-pressure",
        run=execution.run,
        output_id=output.output_id,
    )
    value = output.quantity if field_value is None else field_value
    assert value is not None
    return (
        DatasheetContent(
            datasheet_id=DATASHEET_ID,
            design_case_id=CASE_ID,
            design_revision_id=DESIGN_REVISION_ID,
            design_revision_number=1,
            design_revision_fingerprint=design.current_revision_fingerprint,
            template_id=PRESSURE_TRANSMITTER_TEMPLATE.template_id,
            template_version=PRESSURE_TRANSMITTER_TEMPLATE.template_version,
            template_fingerprint=(PRESSURE_TRANSMITTER_TEMPLATE.template_fingerprint),
            title="Phase 7 pressure transmitter datasheet",
            field_values=(
                DatasheetFieldValue(
                    field_id="maximum_process_pressure",
                    state=DatasheetFieldState.KNOWN,
                    origin=DatasheetFieldOrigin.CALCULATED,
                    value=value,
                    calculation_link_ids=(link.link_id,),
                ),
            ),
            calculation_links=(link,),
        ),
        link,
    )


def test_shared_phase7_composition_preserves_one_case_and_safety_boundaries(
    persistence: _PersistenceContext,
) -> None:
    design = _create_design_case(persistence)
    pressure_execution = _persist_pressure_run(persistence)
    pressure_output = next(
        item
        for item in pressure_execution.result.outputs
        if item.output_id == OUTPUT_ID
    )

    knowledge_service = EngineeringKnowledgeService()
    knowledge_service.register(_published_pressure_knowledge())
    knowledge = knowledge_service.get(KNOWLEDGE_ID)
    link = _knowledge_adapter().resolve_link(
        knowledge,
        CALCULATION_REFERENCE_ID,
    )
    validated_pressure = _knowledge_adapter().validate_result(
        link,
        pressure_execution.result,
    )
    adaptation = _selection_adapter().adapt(
        knowledge,
        CALCULATION_REFERENCE_ID,
        validated_pressure,
        _selection_requirements(),
    )
    recommendation = EngineeringRecommendationEngine.recommend_products(
        (_selection_candidate(),),
        adaptation.build_selection_requirements(),
    )

    content, supplied_datasheet_link = _pressure_datasheet_content(
        design,
        pressure_execution,
    )
    stored_datasheet = persistence.datasheet_service.create(
        CASE_ID,
        DatasheetCreateCommand(
            content=content,
            change_reason="Bind the shared Phase 7 pressure result.",
            created_by="Phase 7 milestone engineer",
        ),
    )
    reopened_datasheet = persistence.datasheet_service.get(
        CASE_ID,
        DATASHEET_ID,
    )
    export = persistence.datasheet_service.export(
        CASE_ID,
        DATASHEET_ID,
        1,
    )

    level_application = DEFAULT_LEVEL_APPLICATION_SERVICE.assess(
        LevelApplicationRequest.model_validate(_level_application_request())
    )
    level_execution = _persist_level_run(persistence)

    dp_example = next(
        item
        for item in DEFAULT_DP_FLOW_SERVICE.get_design_case_examples()
        if item.example_id == "dp-example.liquid-orifice"
    )
    dp_application = dp_example.design_case.application_request.model_copy(
        update={
            "assessment_id": "E4M-PHASE7-112",
            "project_notes": ("Shared Phase 7 V-112 process-basis screening.",),
        }
    )
    dp_design_case = dp_example.design_case.model_copy(
        update={"application_request": dp_application}
    )
    dp_outcome = DEFAULT_DP_FLOW_SERVICE.evaluate_design_case(dp_design_case)

    valve_outcome = DEFAULT_CONTROL_VALVE_SERVICE.evaluate_design_case(
        _control_valve_design_case_request(blocking=False)
    )

    relief_request = _liquid_relief_execution_request()
    relief_preflight = DEFAULT_PRESSURE_RELIEF_SERVICE.assess_readiness(
        PressureReliefReadinessAssessmentRequest(
            readiness_request=relief_request.sizing_input.case.readiness_request
        )
    )
    relief_outcome = DEFAULT_PRESSURE_RELIEF_SERVICE.execute(relief_request)

    analyzer_execution = _persist_analyzer_run(persistence)
    stored_runs = persistence.design_service.list_runs(
        CASE_ID,
        offset=0,
        limit=10,
    )

    assert design.design_case_id == CASE_ID
    assert pressure_execution.run.design_revision_id == DESIGN_REVISION_ID
    assert pressure_output.quantity is not None
    assert pressure_output.quantity.value == 400_000.0
    assert link.knowledge_fingerprint == KNOWN_KNOWLEDGE_FINGERPRINT
    assert adaptation.candidate_requirements.process_pressure_bar == 4.0
    assert recommendation.summary.products_recommended == 1
    assert not hasattr(recommendation, "selected_product")

    stored_link = stored_datasheet.current.revision.snapshot.content.calculation_links[
        0
    ]
    assert supplied_datasheet_link.repository_provenance_verified is False
    assert stored_link.repository_provenance_verified is True
    assert reopened_datasheet.current == stored_datasheet.current
    assert export.json_bytes and export.workbook_bytes
    assert export.descriptor.final_design_approval_granted is False

    assert level_application.status is CalculationStatus.COMPLETED_WITH_WARNINGS
    assert level_application.verification_steps
    assert level_execution.result.status is CalculationStatus.COMPLETED
    assert level_execution.run.design_revision_id == DESIGN_REVISION_ID

    assert dp_outcome.selected_generic_option_id == (
        "generic.orifice.concentric-square-edge"
    )
    assert dp_outcome.approved_for_project_use is False

    assert valve_outcome.disposition is (
        ControlValveDesignDisposition.PRELIMINARY_SCREEN_COMPLETE_REVIEW_REQUIRED
    )
    assert valve_outcome.selection_ready is False
    assert valve_outcome.final_brand_selection == "user_decision_required"

    assert tuple(
        item.finding_id for item in relief_preflight.result.blocking_findings
    ) == ("pressure-relief.no-approved-method",)
    assert relief_outcome.result.authorization.readiness_gate_result == (
        relief_preflight.result
    )
    assert relief_outcome.result.status is CalculationStatus.COMPLETED_WITH_WARNINGS
    assert relief_outcome.ready_for_device_selection is False

    assert analyzer_execution.run.design_revision_id == DESIGN_REVISION_ID
    assert len(analyzer_execution.assessment.assessment.scenarios) == 8
    assert analyzer_execution.assessment.assessment.missing_information
    assert analyzer_execution.assessment.persistence_performed is False
    assert analyzer_execution.persistence_performed is True
    assert stored_runs.total == 3
    assert {item.run_id for item in stored_runs.items} == {
        RUN_ID,
        LEVEL_RUN_ID,
        ANALYZER_RUN_ID,
    }
    assert all(
        item.final_design_approval_granted is False for item in stored_runs.items
    )


def test_pressure_calculation_is_exact_and_deterministic() -> None:
    first = _pressure_result()
    second = _pressure_result()
    output = next(item for item in first.outputs if item.output_id == OUTPUT_ID)

    assert first == second
    assert first.status is CalculationStatus.COMPLETED
    assert output.quantity is not None
    assert output.quantity.quantity_kind == QuantityKind.ABSOLUTE_PRESSURE.value
    assert output.quantity.value == 400_000.0
    assert output.quantity.unit == "Pa"
    assert first.result_fingerprint == second.result_fingerprint


def test_published_knowledge_link_replays_exact_approved_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = EngineeringKnowledgeService()
    registered = service.register(_published_pressure_knowledge())
    knowledge = service.get(KNOWLEDGE_ID)
    adapter = _knowledge_adapter()
    result = _pressure_result()

    def reject_formula_execution(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("knowledge formula text was executed")

    monkeypatch.setattr("os.system", reject_formula_execution)

    link = adapter.resolve_link(knowledge, CALCULATION_REFERENCE_ID)
    validated = adapter.validate_result(link, result)
    definition = ENGINEERING_METHOD_REGISTRY.resolve(
        METHOD_ID,
        METHOD_VERSION,
        calculation_type=CALCULATION_TYPE,
    )

    assert registered == knowledge
    assert registered is not knowledge
    assert fingerprint_knowledge(knowledge) == KNOWN_KNOWLEDGE_FINGERPRINT
    assert (
        fingerprint_method_definition(definition) == KNOWN_METHOD_DEFINITION_FINGERPRINT
    )
    assert validated == result
    assert link.approved_for_execution
    assert link.knowledge_id == KNOWLEDGE_ID
    assert link.method_id == METHOD_ID
    assert link.method_version == METHOD_VERSION
    assert link.engine_version == ENGINE_VERSION
    assert link.verified_evidence_ids == ("evidence.phase7.pressure-basis",)
    assert link.knowledge_formula_ids == ("formula.phase7.inert.absolute-pressure",)
    assert link.link_fingerprint == (
        "f615c1c1fbcca375bb8286bfac34739c95a76675815434a99b3ad602b0c4ec05"
    )
    assert FORMULA_SENTINEL not in link.model_dump_json()


def test_selection_adapter_applies_only_a_missing_pressure_requirement() -> None:
    knowledge = _published_pressure_knowledge()
    requirements = EngineeringRequirements(
        measurement_type="Pressure transmitter",
        process_pressure_bar=None,
        process_medium="Water",
    )

    adaptation = _selection_adapter().adapt(
        knowledge,
        CALCULATION_REFERENCE_ID,
        _pressure_result(),
        requirements,
    )
    decision = adaptation.decisions[0]

    assert requirements.process_pressure_bar is None
    assert decision.decision is RequirementDecision.APPLIED_TO_MISSING
    assert decision.calculated_value == 4.0
    assert decision.effective_value == 4.0
    assert not adaptation.has_conflicts
    assert adaptation.candidate_requirements.process_pressure_bar == 4.0


def test_selection_adapter_retains_a_conflicting_user_requirement() -> None:
    knowledge = _published_pressure_knowledge()
    requirements = EngineeringRequirements(
        measurement_type="Pressure transmitter",
        process_pressure_bar=4.5,
        process_medium="Water",
    )

    adaptation = _selection_adapter().adapt(
        knowledge,
        CALCULATION_REFERENCE_ID,
        _pressure_result(),
        requirements,
    )
    decision = adaptation.decisions[0]

    assert decision.decision is RequirementDecision.USER_VALUE_RETAINED
    assert decision.conflict
    assert adaptation.has_conflicts
    assert adaptation.user_requirements.process_pressure_bar == 4.5
    assert adaptation.candidate_requirements.process_pressure_bar == 4.5


def test_calculated_requirement_handoff_remains_decision_support() -> None:
    knowledge = _published_pressure_knowledge()
    requirements = _selection_requirements()
    adaptation = _selection_adapter().adapt(
        knowledge,
        CALCULATION_REFERENCE_ID,
        _pressure_result(),
        requirements,
    )
    selection_requirements = adaptation.build_selection_requirements()

    response = EngineeringRecommendationEngine.recommend_products(
        (_selection_candidate(),),
        selection_requirements,
    )

    assert requirements.process_pressure_bar is None
    assert selection_requirements.process_pressure_bar == 4.0
    assert response.requirements.process_pressure_bar == 4.0
    assert response.summary.products_evaluated == 1
    assert response.summary.products_recommended == 1
    assert len(response.recommendations) == 1
    assert response.recommendations[0].evaluation.product_id == 112
    assert {finding.code for finding in response.general_safety_findings}.issuperset(
        {
            "GENERAL_ENGINEERING_VERIFICATION_REQUIRED",
            "GENERAL_HAZARDOUS_AREA_VERIFICATION_REQUIRED",
            "GENERAL_PROCESS_COMPATIBILITY_VERIFICATION_REQUIRED",
        }
    )
    assert "decision support" in response.disclaimer
    assert not hasattr(response, "selected_product")
    assert not hasattr(response, "final_brand_selection")


def test_dp_flow_liquid_orifice_case_is_stateless_and_vendor_neutral() -> None:
    example = next(
        item
        for item in DEFAULT_DP_FLOW_SERVICE.get_design_case_examples()
        if item.example_id == "dp-example.liquid-orifice"
    )

    first = DEFAULT_DP_FLOW_SERVICE.evaluate_design_case(example.design_case)
    second = DEFAULT_DP_FLOW_SERVICE.evaluate_design_case(example.design_case)

    assert first == second
    assert first.execution_mode == "stateless"
    assert not first.illustrative_only
    assert first.selected_generic_option_id == (
        "generic.orifice.concentric-square-edge"
    )
    assert first.calculation.trace.method_id == (
        example.design_case.execution_request.method_id
    )
    assert first.calculation.coefficient_derivation_performed is False
    assert first.manufacturer_declared_best is False
    assert first.final_brand_selection == "user_decision_required"
    assert first.standards_conformity_claimed is False
    assert first.approved_for_project_use is False


def test_level_application_is_complete_but_requires_engineering_review() -> None:
    request = LevelApplicationRequest.model_validate(_level_application_request())
    first = DEFAULT_LEVEL_APPLICATION_SERVICE.assess(request)
    second = DEFAULT_LEVEL_APPLICATION_SERVICE.assess(request)

    assert first == second
    assert first.status is CalculationStatus.COMPLETED_WITH_WARNINGS
    assert first.missing_information == ()
    assert any(
        scenario.disposition
        in {
            LevelScenarioDisposition.PREFERRED,
            LevelScenarioDisposition.PLAUSIBLE,
        }
        for scenario in first.scenarios
    )
    assert first.verification_steps
    assert "does not select a product" in first.disclaimer


def test_control_valve_sizing_never_becomes_product_selection() -> None:
    request = _liquid_control_valve_request()
    first = DEFAULT_CONTROL_VALVE_SERVICE.execute(request)
    second = DEFAULT_CONTROL_VALVE_SERVICE.execute(request)

    assert first == second
    assert first.normalized_request == request
    assert first.result.required_cv > 0.0
    assert first.result.warnings
    assert first.result.selection_ready is False
    assert first.selection_ready is False
    assert first.independent_review_required is True
    assert first.manufacturer_selection_performed is False
    assert first.exact_product_selected is False
    assert first.standards_conformity_claimed is False


def test_installed_control_valve_design_case_blocks_unsafe_candidate() -> None:
    request = _control_valve_design_case_request()

    first = DEFAULT_CONTROL_VALVE_SERVICE.evaluate_design_case(request)
    second = DEFAULT_CONTROL_VALVE_SERVICE.evaluate_design_case(request)
    result = first.calculation.result
    trace = first.calculation.trace

    assert first == second
    assert first.normalized_design_case == request
    assert first.calculation.normalized_request == (request.installed_execution_request)
    assert tuple(
        (
            item.evidence.role,
            item.evidence.case_id,
            item.required_travel_percent,
            item.travel_window_status,
        )
        for item in result.case_results
    ) == (
        (
            InstalledCaseRole.MINIMUM,
            "CASE-MIN",
            20.0,
            TravelWindowStatus.BELOW_MINIMUM_TRAVEL,
        ),
        (
            InstalledCaseRole.NORMAL,
            "CASE-NORMAL",
            40.0,
            TravelWindowStatus.WITHIN_SUPPLIED_WINDOW,
        ),
        (
            InstalledCaseRole.MAXIMUM,
            "CASE-MAX",
            60.0,
            TravelWindowStatus.WITHIN_SUPPLIED_WINDOW,
        ),
    )
    assert all(item.inverse_solution_verified for item in result.case_results)
    assert result.candidate_capacity_and_travel_screen_passed is False
    assert first.disposition is ControlValveDesignDisposition.BLOCKED
    assert first.safety_findings[0].severity is ControlValveSafetySeverity.BLOCKING
    assert all(item.safety_first for item in first.safety_findings)
    assert (
        result.input_fingerprint,
        result.result_fingerprint,
        trace.normalized_input_fingerprint,
        trace.result_fingerprint,
        trace.attempt_fingerprint,
        first.design_case_fingerprint,
    ) == (
        "5a24d472ed6a7065c541ab0ecd34f2bee2be8c9b1bb09da4f9b84c67abf7910f",
        "1af7159c0af285628a1dd25fc6ad30d22055002a13c576d0c184d7ca5e077008",
        "6d7594058e5ab6e65c7f220a60504baa828f8d0c7f78184a4a694b0ed42ad3ac",
        "a636c38f939e4292612df8b0968249c6b620a1c945efd82975892bae524bac3c",
        "f96a22399b2e9ab2bf29abc5de6bc8374689b447bed81392b6a9f1c7c7773a67",
        "d729de00ab8142a073c18a17edd068a00015103d7ecc5429a4a7b5d25e86be52",
    )
    assert first.selection_ready is False
    assert first.independent_review_required is True
    assert first.manufacturer_selection_performed is False
    assert first.manufacturer_declared_best is False
    assert first.exact_product_selected is False
    assert first.final_brand_selection == "user_decision_required"
    assert first.approved_for_project_use is False
    assert first.standards_conformity_claimed is False


def test_pressure_relief_readiness_fails_closed_on_missing_basis() -> None:
    request = PressureReliefReadinessAssessmentRequest(
        readiness_request=PressureReliefReadinessRequest(
            request_id="phase7-relief-incomplete"
        )
    )

    first = DEFAULT_PRESSURE_RELIEF_SERVICE.assess_readiness(request)
    second = DEFAULT_PRESSURE_RELIEF_SERVICE.assess_readiness(request)

    assert first == second
    assert first.disposition is PressureReliefWorkflowDisposition.READINESS_BLOCKED
    assert first.result.status is CalculationStatus.BLOCKED
    assert first.safety_findings
    assert all(item.safety_first for item in first.safety_findings)
    assert first.ready_for_required_area_execution is False
    assert first.device_selected is False
    assert first.orifice_selected is False
    assert first.manufacturer_selection_performed is False
    assert first.final_design_approval_granted is False


def test_pressure_relief_required_area_is_preliminary_and_unselected() -> None:
    request = _liquid_relief_execution_request()
    readiness_request = PressureReliefReadinessAssessmentRequest(
        readiness_request=request.sizing_input.case.readiness_request
    )

    preflight = DEFAULT_PRESSURE_RELIEF_SERVICE.assess_readiness(readiness_request)
    first = DEFAULT_PRESSURE_RELIEF_SERVICE.execute(request)
    second = DEFAULT_PRESSURE_RELIEF_SERVICE.execute(request)

    assert preflight.result.request_id == "phase7-liquid-relief"
    assert tuple(item.finding_id for item in preflight.result.blocking_findings) == (
        "pressure-relief.no-approved-method",
    )
    assert preflight.result.request_fingerprint == (
        first.result.authorization.readiness_request_fingerprint
    )
    assert first.result.authorization.readiness_gate_result == preflight.result
    assert first.result.authorization.replaced_finding_id == (
        preflight.result.blocking_findings[0].finding_id
    )
    assert first == second
    assert first.disposition is (
        PressureReliefWorkflowDisposition.PRELIMINARY_REQUIRED_AREA_COMPLETE_REVIEW_REQUIRED
    )
    assert first.result.status is CalculationStatus.COMPLETED_WITH_WARNINGS
    assert first.result.required_area_m2 > 0.0
    assert first.result.authorization.executable is True
    assert first.result.authorization.replaced_finding_id == (
        "pressure-relief.no-approved-method"
    )
    assert first.audit.calculation_performed is True
    assert first.preliminary_engineering_decision_support is True
    assert first.independent_review_required is True
    assert first.ready_for_device_selection is False
    assert first.device_selected is False
    assert first.orifice_selected is False
    assert first.manufacturer_selection_performed is False
    assert first.standards_conformity_claimed is False
    assert first.final_design_approval_granted is False
    assert first.approved_for_project_use is False
    assert first.audit.persistence_performed is False
    assert first.audit.network_access_performed is False


def test_analyzer_assessment_has_no_false_persistence_or_selection() -> None:
    example = _analyzer_example()

    first = DEFAULT_ANALYZER_APPLICATION_SERVICE.assess(example.request)
    second = DEFAULT_ANALYZER_APPLICATION_SERVICE.assess(example.request)

    assert first == second
    assert first.request_fingerprint == example.request_fingerprint
    assert first.assessment.assessment_fingerprint == (
        example.expected_assessment_fingerprint
    )
    assert len(first.assessment.scenarios) == 8
    assert len(first.assessment.verification_steps) == 10
    assert {item.field_id for item in first.assessment.missing_information} == {
        "sample_system.disposition_basis_reference",
        "sample_system.transport_response_basis",
    }
    assert all(
        scenario.verification_requirement_ids for scenario in first.assessment.scenarios
    )
    assert len(first.knowledge_links) == 5
    assert first.persistence_performed is False
    assert first.external_knowledge_access_performed is False
    assert first.manufacturer_or_model_selection_performed is False
    assert first.standards_conformity_claimed is False
    assert first.final_design_approval_granted is False


def test_design_case_and_calculation_run_persist_only_at_trusted_boundary(
    persistence: _PersistenceContext,
) -> None:
    design = _create_design_case(persistence)
    pressure_execution = _persist_pressure_run(persistence)
    level_execution = _persist_level_run(persistence)
    analyzer_execution = _persist_analyzer_run(persistence)
    runs = persistence.design_service.list_runs(CASE_ID, offset=0, limit=10)

    assert design.design_case_id == CASE_ID
    assert design.revision.payload.source_origins
    assert design.revision.payload.plant_context
    assert design.revision.payload.equipment_context
    assert {
        item.responsible_discipline
        for item in design.revision.payload.required_verifications
    } == {
        "Process engineering",
        "Instrumentation engineering",
        "Mechanical/Piping engineering",
        "Electrical/Automation engineering",
        "Process Safety engineering",
        "Maintenance/Reliability engineering",
    }
    assert all(
        item.safety_critical for item in design.revision.payload.required_verifications
    )

    assert pressure_execution.run.run_id == RUN_ID
    assert pressure_execution.run.payload.kind is EngineeringRunKind.CALCULATION
    assert pressure_execution.result == pressure_execution.run.payload.result
    assert pressure_execution.persistence_performed is True

    assert level_execution.run.run_id == LEVEL_RUN_ID
    assert level_execution.run.payload.kind is EngineeringRunKind.CALCULATION
    assert level_execution.result == level_execution.run.payload.result
    assert level_execution.result.method_id == "level.hydrostatic.column-pressure"
    assert level_execution.result.status is CalculationStatus.COMPLETED
    assert level_execution.persistence_performed is True

    assert analyzer_execution.run.run_id == ANALYZER_RUN_ID
    assert analyzer_execution.run.payload.kind is EngineeringRunKind.ANALYZER_ASSESSMENT
    assert analyzer_execution.assessment == analyzer_execution.run.payload.envelope
    assert analyzer_execution.assessment.persistence_performed is False
    assert (
        analyzer_execution.assessment.manufacturer_or_model_selection_performed is False
    )
    assert analyzer_execution.persistence_performed is True

    persisted_runs = (
        pressure_execution.run,
        level_execution.run,
        analyzer_execution.run,
    )
    assert {item.design_revision_id for item in persisted_runs} == {DESIGN_REVISION_ID}
    assert {item.design_revision_number for item in persisted_runs} == {1}
    assert {item.design_revision_fingerprint for item in persisted_runs} == {
        design.current_revision_fingerprint
    }
    assert all(item.persistence_performed for item in runs.items)
    assert runs.total == 3
    assert persistence.session.scalar(select(func.count(DesignCase.id))) == 1
    assert persistence.session.scalar(select(func.count(CalculationRun.id))) == 3


def test_stateless_datasheet_is_blocked_and_exports_only_in_memory() -> None:
    content = DatasheetContent(
        datasheet_id=DATASHEET_ID,
        design_case_id=CASE_ID,
        design_revision_id=DESIGN_REVISION_ID,
        design_revision_number=1,
        design_revision_fingerprint="1" * 64,
        template_id=DP_FLOW_TEMPLATE.template_id,
        template_version=DP_FLOW_TEMPLATE.template_version,
        template_fingerprint=DP_FLOW_TEMPLATE.template_fingerprint,
        title="Phase 7 stateless DP-flow datasheet",
    )
    service = DatasheetService()

    snapshot = service.evaluate(content)
    history = service.create_history(
        DatasheetCreateCommand(
            content=content,
            change_reason="Create an explicitly incomplete draft.",
            created_by="Phase 7 milestone engineer",
        ),
        revision_id=DATASHEET_REVISION_ID,
        created_at=FIXED_TIME,
    )
    bundle = build_datasheet_export_bundle(history.revisions[0])

    assert snapshot.completeness.state is DatasheetCompletenessState.BLOCKED
    assert len(snapshot.content.field_values) == len(DP_FLOW_TEMPLATE.fields)
    assert snapshot.content.calculation_links == ()
    assert all(
        item.state is DatasheetFieldState.UNKNOWN
        for item in snapshot.content.field_values
    )
    assert bundle.json_bytes
    assert bundle.workbook_bytes
    assert bundle.descriptor.formula_cells_present is False
    assert bundle.descriptor.final_design_approval_granted is False
    assert bundle.descriptor.standards_conformity_claimed is False


def test_persistent_datasheet_upgrades_only_a_stored_run_link(
    persistence: _PersistenceContext,
) -> None:
    design = _create_design_case(persistence)
    execution = _persist_pressure_run(persistence)
    content, link = _pressure_datasheet_content(design, execution)

    stored = persistence.datasheet_service.create(
        CASE_ID,
        DatasheetCreateCommand(
            content=content,
            change_reason="Bind one stored calculation output.",
            created_by="Phase 7 milestone engineer",
        ),
    )
    stored_link = stored.current.revision.snapshot.content.calculation_links[0]
    reopened = persistence.datasheet_service.get(CASE_ID, DATASHEET_ID)
    json_export = persistence.datasheet_service.export_json(
        CASE_ID,
        DATASHEET_ID,
        1,
    )
    workbook_export = persistence.datasheet_service.export_workbook(
        CASE_ID,
        DATASHEET_ID,
        1,
    )
    document = json.loads(json_export.content)
    exported_link = document["revision"]["snapshot"]["content"]["calculation_links"][0]
    workbook = load_workbook(
        BytesIO(workbook_export.content),
        data_only=False,
        keep_links=False,
    )

    try:
        workbook_row = tuple(cell.value for cell in workbook["Calculations"][2])
        assert link.repository_provenance_verified is False
        assert stored_link.repository_provenance_verified is True
        assert stored_link.run_id == RUN_ID
        assert reopened.current == stored.current
        assert exported_link["link_id"] == link.link_id
        assert exported_link["run_id"] == str(RUN_ID)
        assert exported_link["repository_provenance_verified"] is True
        assert workbook_row[0] == link.link_id
        assert workbook_row[1] == str(RUN_ID)
        assert workbook_row[18] is True
        assert (
            stored.current.revision.snapshot.completeness.unverified_calculation_field_ids
            == ()
        )
        assert json_export.checksum_sha256 == stored.current.export.json_sha256
        assert workbook_export.checksum_sha256 == stored.current.export.workbook_sha256
        assert (
            persistence.session.scalar(select(func.count(EngineeringDatasheet.id))) == 1
        )
        assert (
            persistence.session.scalar(
                select(func.count()).select_from(EngineeringDatasheetCalculationLink)
            )
            == 1
        )
    finally:
        workbook.close()


def test_tampered_cross_boundary_evidence_fails_closed(
    persistence: _PersistenceContext,
) -> None:
    knowledge = _published_pressure_knowledge()
    knowledge_payload = knowledge.model_dump(mode="python", round_trip=True)
    knowledge_payload["summary"] = "Tampered knowledge must not self-authorize."
    tampered_knowledge = EngineeringKnowledge.model_validate(knowledge_payload)
    blocking_knowledge = _published_pressure_knowledge(blocking_safety=True)

    assert (
        fingerprint_knowledge(blocking_knowledge)
        == KNOWN_BLOCKING_KNOWLEDGE_FINGERPRINT
    )
    with pytest.raises(
        KnowledgeSafetyBlocksSelectionError,
        match="blocks selection",
    ):
        _selection_adapter(
            knowledge_fingerprint=KNOWN_BLOCKING_KNOWLEDGE_FINGERPRINT,
        ).adapt(
            blocking_knowledge,
            CALCULATION_REFERENCE_ID,
            _pressure_result(),
            EngineeringRequirements(),
        )
    with pytest.raises(KnowledgeFingerprintMismatchError, match="fingerprint"):
        _selection_adapter().adapt(
            tampered_knowledge,
            CALCULATION_REFERENCE_ID,
            _pressure_result(),
            EngineeringRequirements(),
        )
    with pytest.raises(ValueError, match="completed"):
        _selection_adapter().adapt(
            knowledge,
            CALCULATION_REFERENCE_ID,
            _incomplete_pressure_result(),
            EngineeringRequirements(),
        )
    with pytest.raises(
        CalculationResultReplayError,
        match="replay|output|trace",
    ):
        _selection_adapter().adapt(
            knowledge,
            CALCULATION_REFERENCE_ID,
            _tampered_pressure_result(),
            EngineeringRequirements(),
        )

    design = _create_design_case(persistence)
    execution = _persist_pressure_run(persistence)
    content, link = _pressure_datasheet_content(design, execution)
    assert link.output.quantity is not None
    forged_quantity = link.output.quantity.model_copy(
        update={"value": link.output.quantity.value + 1.0}
    )
    forged_output = link.output.model_copy(update={"quantity": forged_quantity})
    forged_link = link.model_copy(update={"output": forged_output})
    forged_content, _ = _pressure_datasheet_content(
        design,
        execution,
        calculation_link=forged_link,
        field_value=forged_quantity,
    )
    with pytest.raises(
        DatasheetPersistenceInputError,
        match="evidence does not match",
    ):
        persistence.datasheet_service.create(
            CASE_ID,
            DatasheetCreateCommand(
                content=forged_content,
                change_reason="Reject a forged calculation output.",
                created_by="Phase 7 milestone engineer",
            ),
        )

    foreign_link = link.model_copy(
        update={"run_id": UUID("11200000-0000-4000-8000-000000000099")}
    )
    foreign_content, _ = _pressure_datasheet_content(
        design,
        execution,
        calculation_link=foreign_link,
    )
    with pytest.raises(
        DatasheetPersistenceInputError,
        match="could not be verified",
    ):
        persistence.datasheet_service.create(
            CASE_ID,
            DatasheetCreateCommand(
                content=foreign_content,
                change_reason="Reject a foreign calculation run.",
                created_by="Phase 7 milestone engineer",
            ),
        )

    stale_fingerprint = "9" * 64
    stale_link = link.model_copy(
        update={"design_revision_fingerprint": stale_fingerprint}
    )
    stale_content = content.model_copy(
        update={
            "design_revision_fingerprint": stale_fingerprint,
            "calculation_links": (stale_link,),
        }
    )
    with pytest.raises(DatasheetPersistenceInputError, match="stale"):
        persistence.datasheet_service.create(
            CASE_ID,
            DatasheetCreateCommand(
                content=stale_content,
                change_reason="Reject stale revision evidence.",
                created_by="Phase 7 milestone engineer",
            ),
        )

    assert persistence.session.scalar(select(func.count(EngineeringDatasheet.id))) == 0


def test_frozen_milestone_catalogue_has_all_six_datasheet_domains() -> None:
    assert tuple(template.template_id for template in DATASHEET_TEMPLATES) == (
        "instrument.pressure-transmitter",
        "instrument.level-transmitter",
        "instrument.dp-flow",
        "valve.control",
        "valve.pressure-relief",
        "analyzer.process",
    )
    assert all(template.template_version == "1.0.0" for template in DATASHEET_TEMPLATES)

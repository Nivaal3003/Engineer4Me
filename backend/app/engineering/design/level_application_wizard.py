"""Deterministic, safety-first level-application design wizard.

The wizard screens generic technology families and records the evidence that
must be verified before detailed design.  It does not select products, query a
catalogue, execute any Step 95 calculation, or perform database, network,
dynamic-expression, or voice operations.
"""

from __future__ import annotations

from datetime import UTC
from datetime import datetime
from hashlib import sha256
import json
from typing import Any
from typing import Final

from app.engineering.calculations.models import CalculationReference
from app.engineering.calculations.models import CalculationStatus
from app.engineering.calculations.models import FindingCategory
from app.engineering.calculations.models import FindingSeverity
from app.engineering.calculations.models import ReferenceType
from app.engineering.design.level_application_models import (
    LevelApplicationAssessment,
)
from app.engineering.design.level_application_models import (
    LevelApplicationRequest,
)
from app.engineering.design.level_application_models import LevelConditionSeverity
from app.engineering.design.level_application_models import LevelConfidenceBand
from app.engineering.design.level_application_models import LevelContactPreference
from app.engineering.design.level_application_models import LevelDpArrangement
from app.engineering.design.level_application_models import (
    LevelEnvironmentCondition,
)
from app.engineering.design.level_application_models import LevelIndustrySector
from app.engineering.design.level_application_models import LevelMaintenanceAccess
from app.engineering.design.level_application_models import (
    LevelMeasurementObjective,
)
from app.engineering.design.level_application_models import (
    LevelMissingInformation,
)
from app.engineering.design.level_application_models import LevelMountingPosition
from app.engineering.design.level_application_models import LevelProcessPhase
from app.engineering.design.level_application_models import LevelProtectionFunction
from app.engineering.design.level_application_models import LevelRuleStatus
from app.engineering.design.level_application_models import LevelScenarioDisposition
from app.engineering.design.level_application_models import (
    LevelScenarioRuleResult,
)
from app.engineering.design.level_application_models import LevelTechnology
from app.engineering.design.level_application_models import (
    LevelTechnologyScenario,
)
from app.engineering.design.level_application_models import LevelTriState
from app.engineering.design.level_application_models import LevelVaporBehavior
from app.engineering.design.level_application_models import (
    LevelVerificationPriority,
)
from app.engineering.design.level_application_models import LevelVerificationStep
from app.engineering.design.level_application_models import (
    LevelVesselConfiguration,
)
from app.engineering.design.level_application_models import LevelVesselGeometry
from app.engineering.design.level_application_models import LevelWizardFinding
from app.engineering.design.level_application_models import canonical_quantity_value


LEVEL_APPLICATION_WIZARD_VERSION = "1.0.0"
LEVEL_APPLICATION_RULESET_VERSION = "1.0.0"

_REFERENCE_REVIEWED_AT = datetime(2026, 7, 31, 0, 0, tzinfo=UTC)
_REFERENCE_REVIEWER = "Engineer4Me Phase 7 controlled-reference review"

_ALL_TECHNOLOGIES = tuple(LevelTechnology)
_CONTACT_TECHNOLOGIES = frozenset(
    {
        LevelTechnology.GUIDED_WAVE_RADAR,
        LevelTechnology.DIFFERENTIAL_PRESSURE,
        LevelTechnology.HYDROSTATIC_PRESSURE,
        LevelTechnology.CAPACITANCE,
        LevelTechnology.DISPLACER,
        LevelTechnology.MAGNETIC_FLOAT,
        LevelTechnology.VIBRATING_FORK,
        LevelTechnology.ROTARY_PADDLE,
    }
)
_POINT_TECHNOLOGIES = frozenset(
    {LevelTechnology.VIBRATING_FORK, LevelTechnology.ROTARY_PADDLE}
)
_INTERFACE_TECHNOLOGIES = frozenset(
    {
        LevelTechnology.GUIDED_WAVE_RADAR,
        LevelTechnology.DIFFERENTIAL_PRESSURE,
        LevelTechnology.CAPACITANCE,
        LevelTechnology.DISPLACER,
        LevelTechnology.RADIOMETRIC,
    }
)
_SOLIDS_TECHNOLOGIES = frozenset(
    {
        LevelTechnology.NON_CONTACT_RADAR,
        LevelTechnology.GUIDED_WAVE_RADAR,
        LevelTechnology.ULTRASONIC,
        LevelTechnology.CAPACITANCE,
        LevelTechnology.VIBRATING_FORK,
        LevelTechnology.ROTARY_PADDLE,
        LevelTechnology.RADIOMETRIC,
    }
)
_MECHANICAL_TECHNOLOGIES = frozenset(
    {
        LevelTechnology.DISPLACER,
        LevelTechnology.MAGNETIC_FLOAT,
        LevelTechnology.VIBRATING_FORK,
        LevelTechnology.ROTARY_PADDLE,
    }
)

_TECHNOLOGY_TITLES = {
    LevelTechnology.NON_CONTACT_RADAR: "Non-contact radar scenario",
    LevelTechnology.GUIDED_WAVE_RADAR: "Guided-wave radar scenario",
    LevelTechnology.DIFFERENTIAL_PRESSURE: "Differential-pressure scenario",
    LevelTechnology.HYDROSTATIC_PRESSURE: "Hydrostatic-pressure scenario",
    LevelTechnology.ULTRASONIC: "Ultrasonic scenario",
    LevelTechnology.CAPACITANCE: "Capacitance scenario",
    LevelTechnology.DISPLACER: "Displacer scenario",
    LevelTechnology.MAGNETIC_FLOAT: "Magnetic-float scenario",
    LevelTechnology.VIBRATING_FORK: "Vibrating-fork scenario",
    LevelTechnology.ROTARY_PADDLE: "Rotary-paddle scenario",
    LevelTechnology.RADIOMETRIC: "Radiometric scenario",
    LevelTechnology.TANK_GAUGING: "Tank-gauging scenario",
}


class LevelApplicationWizardError(RuntimeError):
    """Raised when the static wizard cannot construct a valid assessment."""


def _controlled_reference(
    *,
    reference_id: str,
    reference_type: ReferenceType,
    title: str,
    owner: str,
    document_number: str,
    edition: str,
    part: str,
    source_location: str,
    applicability: str,
) -> CalculationReference:
    return CalculationReference(
        reference_id=reference_id,
        reference_type=reference_type,
        title=title,
        publisher_or_owner=owner,
        document_number=document_number,
        edition_or_revision=edition,
        part=part,
        corrigenda_status=(
            "Reference identity reviewed on 2026-07-31; project users must "
            "reconfirm current amendments and corrigenda."
        ),
        relevant_section=(
            "Project-applicable clauses to be identified by the competent "
            "reviewer; no protected requirements are reproduced here."
        ),
        implementation_basis=(
            "Used only as an escalation and verification reference. The "
            "wizard does not claim or certify compliance."
        ),
        applicability=applicability,
        source_location=source_location,
        verified=True,
        verified_by=_REFERENCE_REVIEWER,
        verified_at=_REFERENCE_REVIEWED_AT,
    )


_REFERENCES: Final = (
    CalculationReference(
        reference_id="ref.eng-070",
        reference_type=ReferenceType.ENGINEERING_KNOWLEDGE,
        title="ENG-070 level application assessment governance",
        publisher_or_owner="Engineer4Me",
        document_number="ENG-070",
        edition_or_revision="Phase 7",
        relevant_section="E4M-CALC-060 through E4M-CALC-063",
        implementation_basis=(
            "Vendor-neutral application screening, explicit uncertainty, "
            "scenario evidence, and competent-person escalation."
        ),
        verified=False,
    ),
    CalculationReference(
        reference_id="ref.e4m-calc-060",
        reference_type=ReferenceType.ENGINEERING_KNOWLEDGE,
        title="E4M-CALC-060 scenario-based recommendation contract",
        publisher_or_owner="Engineer4Me",
        document_number="E4M-CALC-060",
        edition_or_revision="1.0.0",
        applicability="Multiple generic technology scenarios with explicit recommendation dispositions.",
        verified=False,
    ),
    CalculationReference(
        reference_id="ref.e4m-calc-061",
        reference_type=ReferenceType.ENGINEERING_KNOWLEDGE,
        title="E4M-CALC-061 multidisciplinary context contract",
        publisher_or_owner="Engineer4Me",
        document_number="E4M-CALC-061",
        edition_or_revision="1.0.0",
        applicability="Industry, process, vessel, installation, environmental, and safety context.",
        verified=False,
    ),
    CalculationReference(
        reference_id="ref.e4m-calc-062",
        reference_type=ReferenceType.ENGINEERING_KNOWLEDGE,
        title="E4M-CALC-062 confidence contract",
        publisher_or_owner="Engineer4Me",
        document_number="E4M-CALC-062",
        edition_or_revision="1.0.0",
        applicability="Confidence based on completeness, evidence, applicability, and explicit assumptions.",
        verified=False,
    ),
    CalculationReference(
        reference_id="ref.e4m-calc-063",
        reference_type=ReferenceType.ENGINEERING_KNOWLEDGE,
        title="E4M-CALC-063 scenario evidence contract",
        publisher_or_owner="Engineer4Me",
        document_number="E4M-CALC-063",
        edition_or_revision="1.0.0",
        applicability="Observations, assumptions, escalation, and evidence.",
        verified=False,
    ),
    _controlled_reference(
        reference_id="ref.api-2350-5",
        reference_type=ReferenceType.NATIONAL_STANDARD,
        title="Overfill Prevention for Storage Tanks in Petroleum Facilities",
        owner="American Petroleum Institute",
        document_number="API Standard 2350",
        edition="5th edition",
        part="Complete standard",
        source_location=(
            "https://www.api.org/products-and-services/standards/"
            "important-standards-announcements/standard-2350"
        ),
        applicability=(
            "Potentially relevant to petroleum storage-tank overfill "
            "applications; applicability and current edition require review."
        ),
    ),
    _controlled_reference(
        reference_id="ref.iec-61511-1",
        reference_type=ReferenceType.INTERNATIONAL_STANDARD,
        title=(
            "Functional safety - Safety instrumented systems for the process "
            "industry sector - Part 1"
        ),
        owner="International Electrotechnical Commission",
        document_number="IEC 61511-1",
        edition="2016+AMD1:2017 CSV; stability date 2029",
        part="Part 1",
        source_location="https://webstore.iec.ch/en/publication/61289",
        applicability=(
            "Potentially relevant when a level device participates in a "
            "safety instrumented function; lifecycle analysis remains external."
        ),
    ),
    _controlled_reference(
        reference_id="ref.iec-60079-0-2026",
        reference_type=ReferenceType.INTERNATIONAL_STANDARD,
        title="Explosive atmospheres - Part 0: Equipment - General requirements",
        owner="International Electrotechnical Commission",
        document_number="IEC 60079-0",
        edition="2026 edition 8.0",
        part="Part 0",
        source_location="https://webstore.iec.ch/en/publication/71519",
        applicability=(
            "Potentially relevant to equipment in explosive atmospheres; "
            "classification, protection concepts, certification, and local "
            "law require competent review."
        ),
    ),
)


def _verification(
    verification_id: str,
    priority: LevelVerificationPriority,
    description: str,
    acceptance_criteria: str,
    competency: str,
    *,
    independent: bool = False,
    evidence: tuple[str, ...] = (),
) -> LevelVerificationStep:
    return LevelVerificationStep(
        verification_id=verification_id,
        priority=priority,
        description=description,
        acceptance_criteria=acceptance_criteria,
        required_competency=competency,
        independent=independent,
        evidence_required=evidence,
    )


_VERIFICATION_CATALOGUE: Final = {
    item.verification_id: item
    for item in (
        _verification(
            "verify.measurement-objectives",
            LevelVerificationPriority.IMPORTANT,
            "Confirm every operating, alarm, trip, interface, and inventory objective.",
            "Approved requirements identify each function and its independence needs.",
            "Process control and instrumentation engineer",
            evidence=("Approved measurement and safeguarding requirements",),
        ),
        _verification(
            "verify.process-properties",
            LevelVerificationPriority.IMPORTANT,
            "Confirm phase, density, dielectric behavior, viscosity, temperature, and pressure envelopes.",
            "Process data cover normal, startup, shutdown, cleaning, and credible upset cases.",
            "Process engineer",
            evidence=("Approved process datasheet", "Representative material data"),
        ),
        _verification(
            "verify.process-disturbances",
            LevelVerificationPriority.IMPORTANT,
            "Verify foam, turbulence, steam, condensation, dust, buildup, slurry, and agitation severity.",
            "Recorded severity and duration are supported by site observations or representative tests.",
            "Process and instrumentation engineer",
            evidence=("Operating history or representative test record",),
        ),
        _verification(
            "verify.vapor-space",
            LevelVerificationPriority.IMPORTANT,
            "Confirm vapor-space composition and variation across all operating modes.",
            "Composition and behavior are defined sufficiently to evaluate signal propagation.",
            "Process engineer",
            evidence=("Vapor composition and operating-envelope record",),
        ),
        _verification(
            "verify.nozzle-mounting",
            LevelVerificationPriority.IMPORTANT,
            "Survey nozzle geometry, dead zones, clearances, obstructions, and available mounting positions.",
            "As-built dimensions demonstrate a feasible measurement path and maintainable mounting.",
            "Instrumentation designer",
            evidence=("As-built vessel drawing", "Site survey record"),
        ),
        _verification(
            "verify.dp-arrangement",
            LevelVerificationPriority.IMPORTANT,
            "Confirm DP tapping elevations, reference-leg or seal arrangement, fill fluids, and density envelope.",
            "Arrangement inputs are approved before any linked Step 95 method is separately executed.",
            "Instrumentation engineer",
            evidence=("Approved hook-up drawing", "Approved process density data"),
        ),
        _verification(
            "verify.tank-geometry",
            LevelVerificationPriority.IMPORTANT,
            "Confirm vessel geometry and dimensional basis for any inventory conversion.",
            "Certified or field-verified dimensions match the intended supporting calculation.",
            "Mechanical and instrumentation engineer",
            evidence=("Certified tank table or verified vessel drawing",),
        ),
        _verification(
            "verify.hazardous-area",
            LevelVerificationPriority.SAFETY_CRITICAL,
            "Confirm hazardous-area classification, gas or dust group, temperature class, EPL or category, and jurisdictional approvals.",
            "A competent hazardous-area reviewer approves the installation and confirms current governing documents.",
            "Authorised hazardous-area engineer",
            independent=True,
            evidence=("Approved area-classification dossier", "Certification schedule"),
        ),
        _verification(
            "verify.independent-protection",
            LevelVerificationPriority.SAFETY_CRITICAL,
            "Define and independently assess every trip or overfill protection function and its required independence.",
            "The lifecycle, architecture, independence, proof-test, and risk-reduction basis are approved outside this wizard.",
            "Functional-safety engineer",
            independent=True,
            evidence=("Approved safeguarding or SIF lifecycle record",),
        ),
        _verification(
            "verify.high-level-protection-path",
            LevelVerificationPriority.SAFETY_CRITICAL,
            "Verify every declared high-high trip or overfill path from sensing point through final response.",
            "Approved evidence confirms the high-level setpoint basis, independence, response path, proof test, bypass control, and final action for the declared function.",
            "Functional-safety and process safeguarding engineer",
            independent=True,
            evidence=("Approved high-level protection cause-and-effect and test record",),
        ),
        _verification(
            "verify.low-level-protection-path",
            LevelVerificationPriority.SAFETY_CRITICAL,
            "Verify every declared low-low trip or dry-run protection path from sensing point through final response.",
            "Approved evidence confirms the low-level setpoint basis, independence, response path, proof test, bypass control, and final action for the declared function.",
            "Functional-safety and rotating-equipment safeguarding engineer",
            independent=True,
            evidence=("Approved low-level protection cause-and-effect and test record",),
        ),
        _verification(
            "verify.radiometric-governance",
            LevelVerificationPriority.SAFETY_CRITICAL,
            "Confirm source licensing, radiation protection, custody, shielding, access control, and disposal obligations.",
            "The authorised radiation protection authority approves the complete source lifecycle.",
            "Radiation protection adviser or officer",
            independent=True,
            evidence=("Current source licence", "Radiation protection program"),
        ),
        _verification(
            "verify.hygienic-service",
            LevelVerificationPriority.IMPORTANT,
            "Confirm cleanability, drainability, wetted materials, seals, surface finish, and required hygienic approvals.",
            "The site hygiene authority approves the installation and cleaning validation basis.",
            "Hygienic process and quality engineer",
            evidence=("Hygienic design review", "Cleaning validation requirement"),
        ),
        _verification(
            "verify.environment",
            LevelVerificationPriority.IMPORTANT,
            "Confirm ambient, ingress, vibration, corrosion, electromagnetic, access, and maintainability constraints.",
            "The equipment specification covers every verified site environmental envelope.",
            "Instrumentation and electrical engineer",
            evidence=("Site environmental and installation survey",),
        ),
        _verification(
            "verify.technology-validation",
            LevelVerificationPriority.IMPORTANT,
            "Validate the shortlisted generic technology in representative service before final selection.",
            "Documented application review or representative trial resolves every listed limitation and escalation condition.",
            "Competent instrumentation engineer",
            independent=True,
            evidence=("Signed technology application review", "Representative test where required"),
        ),
    )
}


def _rule(
    rule_id: str,
    status: LevelRuleStatus,
    weight: float,
    explanation: str,
    *,
    category: FindingCategory = FindingCategory.APPLICABILITY,
    missing: tuple[str, ...] = (),
    verification: tuple[str, ...] = (),
    references: tuple[str, ...] = (
        "ref.e4m-calc-060",
        "ref.e4m-calc-061",
        "ref.eng-070",
    ),
) -> LevelScenarioRuleResult:
    awarded = weight if status is LevelRuleStatus.PASSED else (
        weight * 0.55 if status is LevelRuleStatus.CAUTION else 0.0
    )
    return LevelScenarioRuleResult(
        rule_id=rule_id,
        status=status,
        category=category,
        weight=float(weight),
        awarded_weight=float(awarded),
        explanation=explanation,
        missing_field_ids=missing,
        verification_requirement_ids=verification,
        reference_ids=references,
    )


def _condition_rule(
    *,
    rule_id: str,
    label: str,
    field_id: str,
    severity: LevelConditionSeverity,
    weight: float,
    technology: LevelTechnology,
    high_is_failure: bool,
) -> LevelScenarioRuleResult:
    if severity is LevelConditionSeverity.UNKNOWN:
        return _rule(
            rule_id,
            LevelRuleStatus.MISSING_INFORMATION,
            weight,
            f"{label} severity is unknown for {technology.value}.",
            missing=(field_id,),
            verification=("verify.process-disturbances",),
        )
    if severity in (LevelConditionSeverity.NONE, LevelConditionSeverity.LOW):
        return _rule(
            rule_id,
            LevelRuleStatus.PASSED,
            weight,
            f"Recorded {label} severity is {severity.value}.",
            verification=("verify.process-disturbances",),
        )
    if severity is LevelConditionSeverity.HIGH and high_is_failure:
        return _rule(
            rule_id,
            LevelRuleStatus.FAILED,
            weight,
            f"High {label} can defeat or destabilize this technology family.",
            verification=("verify.process-disturbances",),
        )
    return _rule(
        rule_id,
        LevelRuleStatus.CAUTION,
        weight,
        f"{severity.value.title()} {label} requires application validation.",
        verification=("verify.process-disturbances",),
    )


def _protection_verification_ids(
    request: LevelApplicationRequest,
) -> tuple[str, ...]:
    verification_ids = {"verify.independent-protection"}
    functions = set(request.safety.independent_protection_functions)
    objectives = set(request.measurement.objectives)
    if functions.intersection(
        {
            LevelProtectionFunction.HIGH_HIGH_TRIP,
            LevelProtectionFunction.OVERFILL_PREVENTION,
        }
    ) or objectives.intersection(
        {
            LevelMeasurementObjective.HIGH_HIGH_LEVEL_TRIP,
            LevelMeasurementObjective.OVERFILL_PREVENTION,
        }
    ):
        verification_ids.add("verify.high-level-protection-path")
    if functions.intersection(
        {
            LevelProtectionFunction.LOW_LOW_TRIP,
            LevelProtectionFunction.DRY_RUN_PROTECTION,
        }
    ) or LevelMeasurementObjective.LOW_LOW_LEVEL_TRIP in objectives:
        verification_ids.add("verify.low-level-protection-path")
    return tuple(sorted(verification_ids))


def _objective_rule(
    request: LevelApplicationRequest,
    technology: LevelTechnology,
) -> LevelScenarioRuleResult:
    objectives = request.measurement.objectives
    if not objectives:
        return _rule(
            "common.measurement-objective",
            LevelRuleStatus.MISSING_INFORMATION,
            18.0,
            "No measurement objective has been confirmed.",
            missing=("measurement.objectives",),
            verification=("verify.measurement-objectives",),
        )
    objective_set = set(objectives)
    continuous_or_inventory_objectives = {
        LevelMeasurementObjective.CONTINUOUS_LEVEL,
        LevelMeasurementObjective.INTERFACE_LEVEL,
        LevelMeasurementObjective.INVENTORY,
    }
    point_objectives = {
        LevelMeasurementObjective.HIGH_LEVEL_ALARM,
        LevelMeasurementObjective.HIGH_HIGH_LEVEL_TRIP,
        LevelMeasurementObjective.LOW_LEVEL_ALARM,
        LevelMeasurementObjective.LOW_LOW_LEVEL_TRIP,
        LevelMeasurementObjective.OVERFILL_PREVENTION,
    }
    independent_point_layer = (
        request.safety.independent_protection_required is LevelTriState.YES
        and bool(request.safety.independent_protection_functions)
    )
    has_continuous_or_inventory = bool(
        objective_set.intersection(continuous_or_inventory_objectives)
    )
    has_point_need = bool(objective_set.intersection(point_objectives)) or (
        independent_point_layer
    )
    if technology in _POINT_TECHNOLOGIES:
        if not has_point_need:
            return _rule(
                "common.measurement-objective",
                LevelRuleStatus.NOT_APPLICABLE,
                18.0,
                "A point-level technology cannot satisfy the confirmed continuous or inventory objective by itself.",
                verification=("verify.measurement-objectives",),
            )
        if has_continuous_or_inventory or independent_point_layer:
            return _rule(
                "common.measurement-objective",
                LevelRuleStatus.CAUTION,
                18.0,
                "This point-level technology is screened only as a separate alarm or independent protective layer alongside the continuous or interface measurement scenario.",
                category=FindingCategory.SAFETY,
                verification=(
                    "verify.measurement-objectives",
                    "verify.independent-protection",
                ),
                references=(
                    "ref.e4m-calc-060",
                    "ref.e4m-calc-061",
                    "ref.eng-070",
                    "ref.iec-61511-1",
                ),
            )
        return _rule(
            "common.measurement-objective",
            LevelRuleStatus.PASSED,
            18.0,
            "The point-level technology addresses the confirmed alarm or trip objective at screening level.",
            verification=("verify.measurement-objectives",),
        )
    if (
        LevelMeasurementObjective.INTERFACE_LEVEL in objectives
        and technology not in _INTERFACE_TECHNOLOGIES
    ):
        return _rule(
            "common.measurement-objective",
            LevelRuleStatus.NOT_APPLICABLE,
            18.0,
            "This generic technology family is not screened as an interface-level option.",
            verification=("verify.measurement-objectives",),
        )
    if has_point_need and not has_continuous_or_inventory:
        return _rule(
            "common.measurement-objective",
            LevelRuleStatus.CAUTION,
            18.0,
            "A continuous technology may support the point objective, but independence and failure-mode requirements need separate review.",
            verification=("verify.measurement-objectives", "verify.independent-protection"),
        )
    return _rule(
        "common.measurement-objective",
        LevelRuleStatus.PASSED,
        18.0,
        "The generic technology family can address the confirmed objective at screening level.",
        verification=("verify.measurement-objectives",),
    )


def _phase_rule(
    request: LevelApplicationRequest,
    technology: LevelTechnology,
) -> LevelScenarioRuleResult:
    phase = request.process.phase
    if phase is LevelProcessPhase.UNKNOWN:
        return _rule(
            "common.process-phase",
            LevelRuleStatus.MISSING_INFORMATION,
            16.0,
            "The process phase is unknown.",
            missing=("process.phase",),
            verification=("verify.process-properties",),
        )
    if phase is LevelProcessPhase.BULK_SOLID and technology not in _SOLIDS_TECHNOLOGIES:
        return _rule(
            "common.process-phase",
            LevelRuleStatus.NOT_APPLICABLE,
            16.0,
            "This technology family is not screened for bulk-solid level service.",
            verification=("verify.process-properties",),
        )
    point_layer_needed = bool(
        set(request.measurement.objectives).intersection(
            {
                LevelMeasurementObjective.HIGH_LEVEL_ALARM,
                LevelMeasurementObjective.HIGH_HIGH_LEVEL_TRIP,
                LevelMeasurementObjective.LOW_LEVEL_ALARM,
                LevelMeasurementObjective.LOW_LOW_LEVEL_TRIP,
                LevelMeasurementObjective.OVERFILL_PREVENTION,
            }
        )
    ) or (
        request.safety.independent_protection_required is LevelTriState.YES
        and bool(request.safety.independent_protection_functions)
    )
    if (
        phase is LevelProcessPhase.LIQUID_LIQUID_INTERFACE
        and technology not in _INTERFACE_TECHNOLOGIES
        and not (
            technology in _POINT_TECHNOLOGIES and point_layer_needed
        )
    ):
        return _rule(
            "common.process-phase",
            LevelRuleStatus.NOT_APPLICABLE,
            16.0,
            "This technology family is not screened for liquid-liquid interface service.",
            verification=("verify.process-properties",),
        )
    if technology is LevelTechnology.ROTARY_PADDLE and phase is not LevelProcessPhase.BULK_SOLID:
        return _rule(
            "common.process-phase",
            LevelRuleStatus.NOT_APPLICABLE,
            16.0,
            "Rotary-paddle screening is limited to bulk-solid service.",
            verification=("verify.process-properties",),
        )
    return _rule(
        "common.process-phase",
        LevelRuleStatus.PASSED,
        16.0,
        f"The {phase.value} phase is within this family's screening scope.",
        verification=("verify.process-properties",),
    )


def _contact_rule(
    request: LevelApplicationRequest,
    technology: LevelTechnology,
) -> LevelScenarioRuleResult:
    preference = request.measurement.contact_preference
    if preference is LevelContactPreference.UNKNOWN:
        return _rule(
            "common.process-contact",
            LevelRuleStatus.MISSING_INFORMATION,
            8.0,
            "The process-contact constraint is unknown.",
            missing=("measurement.contact_preference",),
            verification=("verify.measurement-objectives",),
        )
    if (
        preference is LevelContactPreference.NON_CONTACT_REQUIRED
        and technology in _CONTACT_TECHNOLOGIES
    ):
        return _rule(
            "common.process-contact",
            LevelRuleStatus.NOT_APPLICABLE,
            8.0,
            "A contact technology conflicts with the confirmed non-contact requirement.",
            verification=("verify.measurement-objectives",),
        )
    if (
        preference is LevelContactPreference.NON_CONTACT_PREFERRED
        and technology in _CONTACT_TECHNOLOGIES
    ):
        return _rule(
            "common.process-contact",
            LevelRuleStatus.CAUTION,
            8.0,
            "The technology contacts the process despite a non-contact preference.",
            verification=("verify.measurement-objectives",),
        )
    return _rule(
        "common.process-contact",
        LevelRuleStatus.PASSED,
        8.0,
        "The technology is consistent with the recorded process-contact constraint.",
        verification=("verify.measurement-objectives",),
    )


def _hazard_rule(request: LevelApplicationRequest) -> LevelScenarioRuleResult:
    safety = request.safety
    refs = ("ref.eng-070", "ref.e4m-calc-061", "ref.iec-60079-0-2026")
    if safety.hazardous_area is LevelTriState.UNKNOWN:
        return _rule(
            "safety.hazardous-area",
            LevelRuleStatus.MISSING_INFORMATION,
            14.0,
            "Hazardous-area status is unknown and cannot be treated as non-hazardous.",
            category=FindingCategory.SAFETY,
            missing=("safety.hazardous_area",),
            verification=("verify.hazardous-area",),
            references=refs,
        )
    if (
        safety.hazardous_area is LevelTriState.YES
        and safety.hazardous_area_classification is None
    ):
        return _rule(
            "safety.hazardous-area",
            LevelRuleStatus.BLOCKED,
            14.0,
            "Hazardous service is confirmed but the classification basis is absent.",
            category=FindingCategory.SAFETY,
            verification=("verify.hazardous-area",),
            references=refs,
        )
    return _rule(
        "safety.hazardous-area",
        LevelRuleStatus.PASSED,
        14.0,
        "Hazardous-area status is explicit; certification remains a competent-person verification.",
        category=FindingCategory.SAFETY,
        verification=("verify.hazardous-area",),
        references=refs,
    )


def _independence_rule(request: LevelApplicationRequest) -> LevelScenarioRuleResult:
    safety = request.safety
    refs = ("ref.eng-070", "ref.e4m-calc-061", "ref.iec-61511-1")
    protection_verification_ids = _protection_verification_ids(request)
    if safety.independent_protection_required is LevelTriState.UNKNOWN:
        return _rule(
            "safety.independent-protection",
            LevelRuleStatus.MISSING_INFORMATION,
            14.0,
            "Independent-protection requirements are unknown.",
            category=FindingCategory.SAFETY,
            missing=("safety.independent_protection_required",),
            verification=("verify.independent-protection",),
            references=refs,
        )
    if (
        safety.independent_protection_required is LevelTriState.YES
        and not safety.independent_protection_functions
    ):
        return _rule(
            "safety.independent-protection",
            LevelRuleStatus.BLOCKED,
            14.0,
            "Independent protection is required but the functions are undefined.",
            category=FindingCategory.SAFETY,
            verification=("verify.independent-protection",),
            references=refs,
        )
    if safety.independent_protection_required is LevelTriState.YES:
        return _rule(
            "safety.independent-protection",
            LevelRuleStatus.CAUTION,
            14.0,
            "Technology screening does not establish independence, integrity, or risk reduction.",
            category=FindingCategory.SAFETY,
            verification=protection_verification_ids,
            references=refs,
        )
    return _rule(
        "safety.independent-protection",
        LevelRuleStatus.PASSED,
        14.0,
        "No independent protective function is declared for this application.",
        category=FindingCategory.SAFETY,
        verification=("verify.independent-protection",),
        references=refs,
    )


def _industry_rule(
    request: LevelApplicationRequest,
    technology: LevelTechnology,
) -> LevelScenarioRuleResult:
    industry = request.industry
    if industry is LevelIndustrySector.UNKNOWN:
        return _rule(
            "context.industry",
            LevelRuleStatus.MISSING_INFORMATION,
            5.0,
            "Industry context is unknown.",
            missing=("industry",),
            verification=("verify.environment",),
        )
    hygienic = industry in {
        LevelIndustrySector.FOOD_AND_BEVERAGE,
        LevelIndustrySector.PHARMACEUTICAL,
    }
    if hygienic and request.process.hygienic_service is LevelConditionSeverity.UNKNOWN:
        return _rule(
            "context.industry",
            LevelRuleStatus.MISSING_INFORMATION,
            5.0,
            "The hygienic design duty is not defined for this industry context.",
            missing=("process.hygienic_service",),
            verification=("verify.hygienic-service",),
        )
    if hygienic and technology in _CONTACT_TECHNOLOGIES:
        return _rule(
            "context.industry",
            LevelRuleStatus.CAUTION,
            5.0,
            "A contacting technology in hygienic service needs explicit cleanability and materials review.",
            verification=("verify.hygienic-service",),
        )
    if (
        request.process.hygienic_service
        in {
            LevelConditionSeverity.MODERATE,
            LevelConditionSeverity.HIGH,
        }
        and technology in _CONTACT_TECHNOLOGIES
    ):
        return _rule(
            "context.industry",
            LevelRuleStatus.CAUTION,
            5.0,
            "The declared hygienic service requires cleanability, wetted-material, seal, and cleaning validation regardless of industry label.",
            verification=("verify.hygienic-service",),
        )
    if industry in {
        LevelIndustrySector.MINING_AND_MINERALS,
        LevelIndustrySector.CEMENT,
    } and technology in _MECHANICAL_TECHNOLOGIES:
        return _rule(
            "context.industry",
            LevelRuleStatus.CAUTION,
            5.0,
            "Mechanical exposure to dust and abrasion needs representative-service validation.",
            verification=("verify.process-disturbances",),
        )
    return _rule(
        "context.industry",
        LevelRuleStatus.PASSED,
        5.0,
        f"No additional screening conflict was identified for {industry.value}.",
        verification=("verify.environment",),
    )


def _environment_rule(
    request: LevelApplicationRequest,
    technology: LevelTechnology,
) -> LevelScenarioRuleResult:
    environments = request.installation.environments
    if not environments:
        return _rule(
            "context.environment",
            LevelRuleStatus.MISSING_INFORMATION,
            5.0,
            "Installation environmental conditions have not been confirmed.",
            missing=("installation.environments",),
            verification=("verify.environment",),
        )
    ambient_missing = tuple(
        field_id
        for field_id, value in (
            (
                "installation.minimum_ambient_temperature",
                request.installation.minimum_ambient_temperature,
            ),
            (
                "installation.maximum_ambient_temperature",
                request.installation.maximum_ambient_temperature,
            ),
        )
        if value is None
    )
    if ambient_missing:
        return _rule(
            "context.environment",
            LevelRuleStatus.MISSING_INFORMATION,
            5.0,
            "The installation environment is identified but its ambient temperature envelope is incomplete.",
            missing=ambient_missing,
            verification=("verify.environment",),
        )
    minimum_ambient = canonical_quantity_value(
        request.installation.minimum_ambient_temperature
    )
    maximum_ambient = canonical_quantity_value(
        request.installation.maximum_ambient_temperature
    )
    extreme_ambient = bool(
        minimum_ambient is not None
        and minimum_ambient < 233.15
        or maximum_ambient is not None
        and maximum_ambient > 333.15
    )
    severe_for_mechanical = {
        LevelEnvironmentCondition.HIGH_VIBRATION,
        LevelEnvironmentCondition.HIGH_DUST,
        LevelEnvironmentCondition.CORROSIVE_ATMOSPHERE,
        LevelEnvironmentCondition.COASTAL_OR_MARINE,
    }
    universal_caution = {
        LevelEnvironmentCondition.COASTAL_OR_MARINE,
        LevelEnvironmentCondition.WASHDOWN,
        LevelEnvironmentCondition.FLOOD_PRONE,
        LevelEnvironmentCondition.HIGH_VIBRATION,
        LevelEnvironmentCondition.HIGH_ELECTROMAGNETIC_INTERFERENCE,
        LevelEnvironmentCondition.CORROSIVE_ATMOSPHERE,
        LevelEnvironmentCondition.HIGH_DUST,
        LevelEnvironmentCondition.EXTREME_COLD,
        LevelEnvironmentCondition.EXTREME_HEAT,
        LevelEnvironmentCondition.LIMITED_CLEARANCE,
        LevelEnvironmentCondition.REMOTE_LOCATION,
    }
    if (
        extreme_ambient
        or universal_caution.intersection(environments)
        or technology in _MECHANICAL_TECHNOLOGIES
        and severe_for_mechanical.intersection(environments)
    ):
        return _rule(
            "context.environment",
            LevelRuleStatus.CAUTION,
            5.0,
            f"Recorded environment or ambient envelope ({minimum_ambient} K to {maximum_ambient} K) requires explicit enclosure, compatibility, access, or maintenance validation.",
            verification=("verify.environment",),
        )
    return _rule(
        "context.environment",
        LevelRuleStatus.PASSED,
        5.0,
        f"Recorded environmental constraints and ambient envelope ({minimum_ambient} K to {maximum_ambient} K) remain subject to enclosure and installation verification.",
        verification=("verify.environment",),
    )


def _mounting_rule(
    request: LevelApplicationRequest,
    technology: LevelTechnology,
) -> LevelScenarioRuleResult:
    available = request.vessel.available_mounting_positions
    if not available:
        return _rule(
            "installation.mounting",
            LevelRuleStatus.MISSING_INFORMATION,
            5.0,
            "Available mounting positions and constraints are not defined.",
            missing=("vessel.available_mounting_positions",),
            verification=("verify.nozzle-mounting",),
        )
    needs_top = technology in {
        LevelTechnology.NON_CONTACT_RADAR,
        LevelTechnology.GUIDED_WAVE_RADAR,
        LevelTechnology.ULTRASONIC,
        LevelTechnology.TANK_GAUGING,
    }
    if needs_top and LevelMountingPosition.TOP not in available:
        return _rule(
            "installation.mounting",
            LevelRuleStatus.FAILED,
            5.0,
            "No top mounting position is recorded for a technology normally screened from above.",
            verification=("verify.nozzle-mounting",),
        )
    return _rule(
        "installation.mounting",
        LevelRuleStatus.PASSED,
        5.0,
        "At least one potentially compatible generic mounting position is recorded.",
        verification=("verify.nozzle-mounting",),
    )


def _property_rule(
    *,
    rule_id: str,
    present: bool,
    field_id: str,
    label: str,
    weight: float,
    caution: bool = False,
) -> LevelScenarioRuleResult:
    if not present:
        return _rule(
            rule_id,
            LevelRuleStatus.MISSING_INFORMATION,
            weight,
            f"{label} is required to assess this technology family.",
            missing=(field_id,),
            verification=("verify.process-properties",),
        )
    return _rule(
        rule_id,
        LevelRuleStatus.CAUTION if caution else LevelRuleStatus.PASSED,
        weight,
        (
            f"{label} is present but still needs application-specific validation."
            if caution
            else f"{label} is explicitly provided for screening."
        ),
        verification=("verify.process-properties",),
    )


def _technology_rules(
    request: LevelApplicationRequest,
    technology: LevelTechnology,
) -> list[LevelScenarioRuleResult]:
    process = request.process
    rules: list[LevelScenarioRuleResult] = []
    if technology is LevelTechnology.NON_CONTACT_RADAR:
        rules.extend(
            [
                _property_rule(
                    rule_id="radar.dielectric",
                    present=process.dielectric_constant is not None,
                    field_id="process.dielectric_constant",
                    label="Dielectric behavior",
                    weight=7.0,
                    caution=(process.dielectric_constant or 99.0) < 1.4,
                ),
                _condition_rule(
                    rule_id="radar.foam",
                    label="foam",
                    field_id="process.foam",
                    severity=process.foam,
                    weight=6.0,
                    technology=technology,
                    high_is_failure=True,
                ),
                _condition_rule(
                    rule_id="radar.turbulence",
                    label="turbulence",
                    field_id="process.turbulence",
                    severity=process.turbulence,
                    weight=4.0,
                    technology=technology,
                    high_is_failure=False,
                ),
            ]
        )
    elif technology is LevelTechnology.GUIDED_WAVE_RADAR:
        rules.extend(
            [
                _property_rule(
                    rule_id="gwr.dielectric",
                    present=process.dielectric_constant is not None,
                    field_id="process.dielectric_constant",
                    label="Dielectric behavior",
                    weight=7.0,
                ),
                _condition_rule(
                    rule_id="gwr.buildup",
                    label="probe buildup",
                    field_id="process.buildup",
                    severity=process.buildup,
                    weight=7.0,
                    technology=technology,
                    high_is_failure=True,
                ),
                _condition_rule(
                    rule_id="gwr.slurry",
                    label="slurry exposure",
                    field_id="process.slurry",
                    severity=process.slurry,
                    weight=3.0,
                    technology=technology,
                    high_is_failure=False,
                ),
            ]
        )
    elif technology in {
        LevelTechnology.DIFFERENTIAL_PRESSURE,
        LevelTechnology.HYDROSTATIC_PRESSURE,
    }:
        density_variation = process.density_variation_percent
        rules.append(
            _property_rule(
                rule_id="pressure.density",
                present=process.bulk_density is not None,
                field_id="process.bulk_density",
                label="Bulk fluid density",
                weight=9.0,
            )
        )
        rules.append(
            _rule(
                "pressure.density-variation",
                LevelRuleStatus.MISSING_INFORMATION
                if density_variation is None
                else LevelRuleStatus.FAILED
                if density_variation > 10.0
                else LevelRuleStatus.PASSED,
                5.0,
                "Density variation is unknown for pressure-derived level screening."
                if density_variation is None
                else "Density variation exceeds ten percent and can materially shift inferred level."
                if density_variation > 10.0
                else "Density variation is explicitly bounded for pressure-derived level screening.",
                missing=("process.density_variation_percent",)
                if density_variation is None
                else (),
                verification=("verify.process-properties",),
            )
        )
        if technology is LevelTechnology.HYDROSTATIC_PRESSURE:
            configuration = request.vessel.configuration
            rules.append(
                _rule(
                    "hydrostatic.vessel-configuration",
                    LevelRuleStatus.MISSING_INFORMATION
                    if configuration is LevelVesselConfiguration.UNKNOWN
                    else LevelRuleStatus.FAILED
                    if configuration
                    in {
                        LevelVesselConfiguration.PRESSURIZED,
                        LevelVesselConfiguration.VACUUM,
                    }
                    else LevelRuleStatus.CAUTION
                    if configuration is LevelVesselConfiguration.CLOSED
                    else LevelRuleStatus.PASSED,
                    7.0,
                    "Vessel pressure-boundary configuration is unknown."
                    if configuration is LevelVesselConfiguration.UNKNOWN
                    else "Standalone hydrostatic screening cannot resolve pressurized or vacuum vapor-space compensation."
                    if configuration
                    in {
                        LevelVesselConfiguration.PRESSURIZED,
                        LevelVesselConfiguration.VACUUM,
                    }
                    else "A closed vessel requires explicit vapor-pressure compensation review."
                    if configuration is LevelVesselConfiguration.CLOSED
                    else "The open vessel configuration is compatible with standalone hydrostatic screening.",
                    missing=("vessel.configuration",)
                    if configuration is LevelVesselConfiguration.UNKNOWN
                    else (),
                    verification=("verify.process-properties",),
                )
            )
        if technology is LevelTechnology.DIFFERENTIAL_PRESSURE:
            arrangement = request.vessel.dp_arrangement
            rules.append(
                _rule(
                    "dp.arrangement",
                    LevelRuleStatus.MISSING_INFORMATION
                    if arrangement is LevelDpArrangement.UNKNOWN
                    else LevelRuleStatus.NOT_APPLICABLE
                    if arrangement is LevelDpArrangement.NOT_APPLICABLE
                    else LevelRuleStatus.PASSED,
                    8.0,
                    "DP arrangement is unknown."
                    if arrangement is LevelDpArrangement.UNKNOWN
                    else "Differential-pressure measurement is explicitly not applicable."
                    if arrangement is LevelDpArrangement.NOT_APPLICABLE
                    else f"The {arrangement.value} arrangement is explicit.",
                    missing=("vessel.dp_arrangement",)
                    if arrangement is LevelDpArrangement.UNKNOWN
                    else (),
                    verification=("verify.dp-arrangement",),
                )
            )
        rules.append(
            _condition_rule(
                rule_id="pressure.slurry-buildup",
                label="slurry or impulse-path buildup",
                field_id="process.slurry",
                severity=process.slurry,
                weight=4.0,
                technology=technology,
                high_is_failure=True,
            )
        )
    elif technology is LevelTechnology.ULTRASONIC:
        for suffix, label, field_id, severity, failure in (
            ("foam", "foam", "process.foam", process.foam, True),
            ("steam", "steam", "process.steam", process.steam, True),
            ("condensation", "condensation", "process.condensation", process.condensation, True),
            ("turbulence", "turbulence", "process.turbulence", process.turbulence, True),
        ):
            rules.append(
                _condition_rule(
                    rule_id=f"ultrasonic.{suffix}",
                    label=label,
                    field_id=field_id,
                    severity=severity,
                    weight=4.25,
                    technology=technology,
                    high_is_failure=failure,
                )
            )
    elif technology is LevelTechnology.CAPACITANCE:
        rules.extend(
            [
                _property_rule(
                    rule_id="capacitance.dielectric",
                    present=process.dielectric_constant is not None,
                    field_id="process.dielectric_constant",
                    label="Dielectric behavior and variation",
                    weight=9.0,
                ),
                _condition_rule(
                    rule_id="capacitance.buildup",
                    label="coating or buildup",
                    field_id="process.buildup",
                    severity=process.buildup,
                    weight=8.0,
                    technology=technology,
                    high_is_failure=True,
                ),
            ]
        )
    elif technology in {
        LevelTechnology.DISPLACER,
        LevelTechnology.MAGNETIC_FLOAT,
    }:
        variation = process.density_variation_percent
        rules.extend(
            [
                _property_rule(
                    rule_id="mechanical.density",
                    present=process.bulk_density is not None,
                    field_id="process.bulk_density",
                    label="Fluid density and variation",
                    weight=8.0,
                ),
                _condition_rule(
                    rule_id="mechanical.sticky-slurry",
                    label="sticky or slurry service",
                    field_id="process.sticky_material",
                    severity=process.sticky_material,
                    weight=6.0,
                    technology=technology,
                    high_is_failure=True,
                ),
                _rule(
                    "mechanical.density-variation",
                    LevelRuleStatus.MISSING_INFORMATION
                    if variation is None
                    else LevelRuleStatus.FAILED
                    if variation > 10.0
                    else LevelRuleStatus.PASSED,
                    4.0,
                    "Density variation is unknown for a buoyancy-dependent technology."
                    if variation is None
                    else "Density variation exceeds ten percent and can shift buoyancy response."
                    if variation > 10.0
                    else "Density variation is explicitly bounded for buoyancy screening.",
                    missing=("process.density_variation_percent",)
                    if variation is None
                    else (),
                    verification=("verify.process-properties",),
                ),
                _rule(
                    "mechanical.maintenance-access",
                    LevelRuleStatus.MISSING_INFORMATION
                    if request.installation.maintenance_access is LevelMaintenanceAccess.UNKNOWN
                    else LevelRuleStatus.CAUTION
                    if request.installation.maintenance_access
                    in {
                        LevelMaintenanceAccess.DIFFICULT,
                        LevelMaintenanceAccess.INACCESSIBLE_DURING_OPERATION,
                    }
                    else LevelRuleStatus.PASSED,
                    3.0,
                    "Maintenance access must support inspection of moving or buoyant elements.",
                    missing=("installation.maintenance_access",)
                    if request.installation.maintenance_access is LevelMaintenanceAccess.UNKNOWN
                    else (),
                    verification=("verify.environment",),
                ),
            ]
        )
    elif technology in {
        LevelTechnology.VIBRATING_FORK,
        LevelTechnology.ROTARY_PADDLE,
    }:
        rules.extend(
            [
                _condition_rule(
                    rule_id="point.buildup",
                    label="buildup",
                    field_id="process.buildup",
                    severity=process.buildup,
                    weight=9.0,
                    technology=technology,
                    high_is_failure=True,
                ),
                _condition_rule(
                    rule_id="point.dust-or-slurry",
                    label="dust or slurry exposure",
                    field_id=(
                        "process.dust"
                        if technology is LevelTechnology.ROTARY_PADDLE
                        else "process.slurry"
                    ),
                    severity=(
                        process.dust
                        if technology is LevelTechnology.ROTARY_PADDLE
                        else process.slurry
                    ),
                    weight=8.0,
                    technology=technology,
                    high_is_failure=False,
                ),
            ]
        )
    elif technology is LevelTechnology.RADIOMETRIC:
        permitted = request.safety.radiometric_source_permitted
        program = request.safety.radiation_protection_program_confirmed
        refs = ("ref.eng-070", "ref.e4m-calc-061")
        if permitted is LevelTriState.UNKNOWN:
            status = LevelRuleStatus.MISSING_INFORMATION
            missing = ("safety.radiometric_source_permitted",)
            explanation = "Permission for a radiometric source is unknown."
        elif permitted is LevelTriState.NO:
            status = LevelRuleStatus.NOT_APPLICABLE
            missing = ()
            explanation = "Radiometric sources are not permitted for this application."
        elif program is LevelTriState.UNKNOWN:
            status = LevelRuleStatus.MISSING_INFORMATION
            missing = ("safety.radiation_protection_program_confirmed",)
            explanation = "A radiation protection program has not been confirmed."
        elif program is LevelTriState.NO:
            status = LevelRuleStatus.BLOCKED
            missing = ()
            explanation = "No approved radiation protection program is available."
        else:
            status = LevelRuleStatus.CAUTION
            missing = ()
            explanation = "Source use is permitted, but the complete regulated lifecycle still requires approval."
        rules.append(
            _rule(
                "radiometric.governance",
                status,
                17.0,
                explanation,
                category=FindingCategory.SAFETY,
                missing=missing,
                verification=("verify.radiometric-governance",),
                references=refs,
            )
        )
    elif technology is LevelTechnology.TANK_GAUGING:
        geometry = request.vessel.geometry
        rules.extend(
            [
                _rule(
                    "tank-gauging.geometry",
                    LevelRuleStatus.MISSING_INFORMATION
                    if geometry is LevelVesselGeometry.UNKNOWN
                    else LevelRuleStatus.CAUTION
                    if geometry is LevelVesselGeometry.IRREGULAR
                    else LevelRuleStatus.PASSED,
                    9.0,
                    "Vessel geometry is unknown."
                    if geometry is LevelVesselGeometry.UNKNOWN
                    else "Irregular geometry requires a certified tank table."
                    if geometry is LevelVesselGeometry.IRREGULAR
                    else f"The {geometry.value} geometry is explicit.",
                    missing=("vessel.geometry",)
                    if geometry is LevelVesselGeometry.UNKNOWN
                    else (),
                    verification=("verify.tank-geometry",),
                ),
                _condition_rule(
                    rule_id="tank-gauging.foam",
                    label="foam and disturbed surface",
                    field_id="process.foam",
                    severity=process.foam,
                    weight=8.0,
                    technology=technology,
                    high_is_failure=False,
                ),
            ]
        )
    return rules


def _context_completion_rules(
    request: LevelApplicationRequest,
    technology: LevelTechnology,
) -> list[LevelScenarioRuleResult]:
    """Evaluate multidisciplinary facts shared by technology rules."""

    rules: list[LevelScenarioRuleResult] = []
    objectives = set(request.measurement.objectives)
    continuous_objectives = {
        LevelMeasurementObjective.CONTINUOUS_LEVEL,
        LevelMeasurementObjective.INTERFACE_LEVEL,
        LevelMeasurementObjective.INVENTORY,
    }
    response_objectives = {
        LevelMeasurementObjective.HIGH_LEVEL_ALARM,
        LevelMeasurementObjective.HIGH_HIGH_LEVEL_TRIP,
        LevelMeasurementObjective.LOW_LEVEL_ALARM,
        LevelMeasurementObjective.LOW_LOW_LEVEL_TRIP,
        LevelMeasurementObjective.OVERFILL_PREVENTION,
    }
    measurement_missing_list: list[str] = []
    if not objectives:
        measurement_missing_list.append("measurement.objectives")
    elif objectives.intersection(continuous_objectives):
        if request.measurement.measurement_span is None:
            measurement_missing_list.append("measurement.measurement_span")
        if request.measurement.required_accuracy_percent_of_span is None:
            measurement_missing_list.append(
                "measurement.required_accuracy_percent_of_span"
            )
    if (
        objectives.intersection(response_objectives)
        and request.measurement.required_response_time is None
    ):
        measurement_missing_list.append("measurement.required_response_time")
    measurement_missing = tuple(measurement_missing_list)
    rules.append(
        _rule(
            "requirements.performance-envelope",
            LevelRuleStatus.MISSING_INFORMATION
            if measurement_missing
            else LevelRuleStatus.PASSED,
            6.0,
            "Objective-dependent span, accuracy, or response requirements are incomplete."
            if measurement_missing
            else "Objective-dependent performance requirements are explicit or not applicable.",
            missing=measurement_missing,
            verification=("verify.measurement-objectives",),
        )
    )

    vessel_missing: list[str] = []
    if request.vessel.configuration is LevelVesselConfiguration.UNKNOWN:
        vessel_missing.append("vessel.configuration")
    if request.vessel.geometry is LevelVesselGeometry.UNKNOWN:
        vessel_missing.append("vessel.geometry")
    tank_dimensions_required = (
        technology is LevelTechnology.TANK_GAUGING
        or LevelMeasurementObjective.INVENTORY in objectives
    )
    if (
        tank_dimensions_required
        and request.vessel.geometry is LevelVesselGeometry.VERTICAL_CYLINDER
    ):
        for field_id, value in (
            ("vessel.internal_diameter", request.vessel.internal_diameter),
            (
                "vessel.straight_side_height",
                request.vessel.straight_side_height,
            ),
        ):
            if value is None:
                vessel_missing.append(field_id)
    if (
        tank_dimensions_required
        and request.vessel.geometry is LevelVesselGeometry.HORIZONTAL_CYLINDER
    ):
        for field_id, value in (
            ("vessel.internal_diameter", request.vessel.internal_diameter),
            ("vessel.cylindrical_length", request.vessel.cylindrical_length),
        ):
            if value is None:
                vessel_missing.append(field_id)
    high_level_need = bool(
        objectives.intersection(
            {
                LevelMeasurementObjective.HIGH_LEVEL_ALARM,
                LevelMeasurementObjective.HIGH_HIGH_LEVEL_TRIP,
                LevelMeasurementObjective.OVERFILL_PREVENTION,
            }
        )
        or set(request.safety.independent_protection_functions).intersection(
            {
                LevelProtectionFunction.HIGH_HIGH_TRIP,
                LevelProtectionFunction.OVERFILL_PREVENTION,
            }
        )
    )
    low_level_need = bool(
        objectives.intersection(
            {
                LevelMeasurementObjective.LOW_LEVEL_ALARM,
                LevelMeasurementObjective.LOW_LOW_LEVEL_TRIP,
            }
        )
        or set(request.safety.independent_protection_functions).intersection(
            {
                LevelProtectionFunction.LOW_LOW_TRIP,
                LevelProtectionFunction.DRY_RUN_PROTECTION,
            }
        )
    )
    if (
        technology not in _POINT_TECHNOLOGIES
        and objectives.intersection(continuous_objectives)
    ):
        high_level_need = True
        low_level_need = True
    if high_level_need and request.vessel.upper_level_elevation is None:
        vessel_missing.append("vessel.upper_level_elevation")
    if low_level_need and request.vessel.lower_level_elevation is None:
        vessel_missing.append("vessel.lower_level_elevation")
    diameter = canonical_quantity_value(request.vessel.internal_diameter)
    height = canonical_quantity_value(request.vessel.straight_side_height)
    cylinder_length = canonical_quantity_value(
        request.vessel.cylindrical_length
    )
    lower_elevation = canonical_quantity_value(
        request.vessel.lower_level_elevation
    )
    upper_elevation = canonical_quantity_value(
        request.vessel.upper_level_elevation
    )
    rules.append(
        _rule(
            "vessel.geometry-and-range",
            LevelRuleStatus.MISSING_INFORMATION
            if vessel_missing
            else LevelRuleStatus.CAUTION
            if request.vessel.geometry
            in {LevelVesselGeometry.IRREGULAR, LevelVesselGeometry.SPHERE}
            else LevelRuleStatus.PASSED,
            5.0,
            "Vessel configuration, geometry, required dimensions, or measurement elevations are incomplete."
            if vessel_missing
            else (
                f"The {request.vessel.geometry.value} geometry requires a certified geometry or tank-table review; "
                f"recorded diameter {diameter} m, height {height} m, length {cylinder_length} m, "
                f"and level elevations {lower_elevation} m to {upper_elevation} m."
            )
            if request.vessel.geometry
            in {LevelVesselGeometry.IRREGULAR, LevelVesselGeometry.SPHERE}
            else (
                "Tank dimensions are not required for this scoped point-level screening; "
                f"available level elevations are {lower_elevation} m to {upper_elevation} m."
            )
            if not tank_dimensions_required
            else (
                f"Recorded {request.vessel.configuration.value} {request.vessel.geometry.value} geometry has diameter "
                f"{diameter} m, height {height} m, length {cylinder_length} m, and level elevations "
                f"{lower_elevation} m to {upper_elevation} m."
            ),
            missing=tuple(vessel_missing),
            verification=("verify.tank-geometry",),
        )
    )

    automation_missing = tuple(
        field_id
        for field_id, value in (
            (
                "measurement.continuous_output_required",
                request.measurement.continuous_output_required,
            ),
            (
                "measurement.local_indication_required",
                request.measurement.local_indication_required,
            ),
        )
        if value is LevelTriState.UNKNOWN
    )
    point_output_conflict = (
        technology in _POINT_TECHNOLOGIES
        and request.measurement.continuous_output_required
        is LevelTriState.YES
    )
    parallel_continuous_architecture = bool(
        objectives.intersection(continuous_objectives)
    )
    rules.append(
        _rule(
            "requirements.automation-and-indication",
            LevelRuleStatus.MISSING_INFORMATION
            if automation_missing
            else LevelRuleStatus.CAUTION
            if point_output_conflict and parallel_continuous_architecture
            else LevelRuleStatus.FAILED
            if point_output_conflict
            else LevelRuleStatus.PASSED,
            3.0,
            "Continuous-output and local-indication requirements are incomplete."
            if automation_missing
            else "The point-level device can only be a parallel layer; a separate continuous technology must satisfy the continuous-output requirement."
            if point_output_conflict and parallel_continuous_architecture
            else "A point-level technology cannot satisfy the explicit continuous-output requirement by itself."
            if point_output_conflict
            else "Continuous-output and local-indication requirements are explicit.",
            missing=automation_missing,
            verification=("verify.measurement-objectives",),
        )
    )

    protective_objectives = objectives.intersection(
        {
            LevelMeasurementObjective.HIGH_HIGH_LEVEL_TRIP,
            LevelMeasurementObjective.LOW_LOW_LEVEL_TRIP,
            LevelMeasurementObjective.OVERFILL_PREVENTION,
        }
    )
    if protective_objectives:
        required_function_map = {
            LevelMeasurementObjective.HIGH_HIGH_LEVEL_TRIP: (
                LevelProtectionFunction.HIGH_HIGH_TRIP
            ),
            LevelMeasurementObjective.LOW_LOW_LEVEL_TRIP: (
                LevelProtectionFunction.LOW_LOW_TRIP
            ),
            LevelMeasurementObjective.OVERFILL_PREVENTION: (
                LevelProtectionFunction.OVERFILL_PREVENTION
            ),
        }
        required_functions = {
            required_function_map[item] for item in protective_objectives
        }
        declared_functions = set(
            request.safety.independent_protection_functions
        )
        independence = request.safety.independent_protection_required
        response_seconds = canonical_quantity_value(
            request.measurement.required_response_time
        )
        missing_protective_fields = (
            ("measurement.required_response_time",)
            if response_seconds is None
            else ()
        )
        if independence is LevelTriState.UNKNOWN:
            missing_protective_fields = tuple(
                sorted(
                    {
                        *missing_protective_fields,
                        "safety.independent_protection_required",
                    }
                )
            )
        function_mismatch = bool(
            independence is LevelTriState.YES
            and not required_functions.issubset(declared_functions)
        )
        rules.append(
            _rule(
                "safety.protective-objective-path",
                LevelRuleStatus.MISSING_INFORMATION
                if missing_protective_fields
                else LevelRuleStatus.FAILED
                if independence is LevelTriState.NO or function_mismatch
                else LevelRuleStatus.CAUTION,
                8.0,
                "Protective response time or independence is undefined."
                if missing_protective_fields
                else "A trip or overfill objective conflicts with independent_protection_required=no."
                if independence is LevelTriState.NO
                else "Declared independent protection functions do not cover every protective objective."
                if function_mismatch
                else (
                    f"The stated response time of {response_seconds} s must be "
                    "verified against approved process dynamics and time-to-hazard; this wizard defines no universal acceptance threshold."
                ),
                category=FindingCategory.SAFETY,
                missing=missing_protective_fields,
                verification=_protection_verification_ids(request),
                references=(
                    "ref.e4m-calc-061",
                    "ref.eng-070",
                    "ref.iec-61511-1",
                ),
            )
        )

    process_envelope_missing = tuple(
        field_id
        for field_id, value in (
            ("process.minimum_temperature", request.process.minimum_temperature),
            ("process.normal_temperature", request.process.normal_temperature),
            ("process.maximum_temperature", request.process.maximum_temperature),
            (
                "process.normal_absolute_pressure",
                request.process.normal_absolute_pressure,
            ),
            (
                "process.maximum_absolute_pressure",
                request.process.maximum_absolute_pressure,
            ),
        )
        if value is None
    )
    minimum_temperature = canonical_quantity_value(
        request.process.minimum_temperature
    )
    normal_temperature = canonical_quantity_value(
        request.process.normal_temperature
    )
    maximum_temperature = canonical_quantity_value(
        request.process.maximum_temperature
    )
    normal_pressure = canonical_quantity_value(
        request.process.normal_absolute_pressure
    )
    maximum_pressure = canonical_quantity_value(
        request.process.maximum_absolute_pressure
    )
    severe_process_envelope = bool(
        not process_envelope_missing
        and (
            minimum_temperature is not None
            and minimum_temperature < 233.15
            or maximum_temperature is not None
            and maximum_temperature > 473.15
            or maximum_pressure is not None
            and maximum_pressure > 5_000_000.0
        )
    )
    rules.append(
        _rule(
            "process.temperature-pressure-envelope",
            LevelRuleStatus.MISSING_INFORMATION
            if process_envelope_missing
            else LevelRuleStatus.CAUTION
            if severe_process_envelope
            else LevelRuleStatus.PASSED,
            6.0,
            "The full process temperature and absolute-pressure envelope is incomplete."
            if process_envelope_missing
            else (
                "The explicit process envelope requires high-severity application validation: "
                f"temperature {minimum_temperature} K normal {normal_temperature} K to {maximum_temperature} K, "
                f"absolute pressure normal {normal_pressure} Pa to {maximum_pressure} Pa."
            )
            if severe_process_envelope
            else (
                f"The explicit process envelope is {minimum_temperature} K normal {normal_temperature} K to "
                f"{maximum_temperature} K and {normal_pressure} Pa normal to {maximum_pressure} Pa absolute."
            ),
            missing=process_envelope_missing,
            verification=("verify.process-properties",),
        )
    )

    if (
        technology in _CONTACT_TECHNOLOGIES
        and request.process.phase is not LevelProcessPhase.BULK_SOLID
    ):
        viscosity_missing = request.process.dynamic_viscosity is None
        viscosity_value = canonical_quantity_value(
            request.process.dynamic_viscosity
        )
        high_viscosity = bool(
            viscosity_value is not None and viscosity_value > 1.0
        )
        rules.append(
            _rule(
                "process.dynamic-viscosity",
                LevelRuleStatus.MISSING_INFORMATION
                if viscosity_missing
                else LevelRuleStatus.CAUTION
                if high_viscosity
                else LevelRuleStatus.PASSED,
                3.0,
                "Dynamic viscosity is unknown for a contacting technology."
                if viscosity_missing
                else f"Dynamic viscosity is {viscosity_value} Pa.s and requires high-viscosity application validation."
                if high_viscosity
                else f"Dynamic viscosity is explicitly {viscosity_value} Pa.s for contacting-technology review.",
                missing=("process.dynamic_viscosity",)
                if viscosity_missing
                else (),
                verification=("verify.process-properties",),
            )
        )

    if (
        LevelMeasurementObjective.INTERFACE_LEVEL
        in request.measurement.objectives
        or request.process.phase
        in {
            LevelProcessPhase.LIQUID_LIQUID_INTERFACE,
            LevelProcessPhase.MULTIPHASE,
        }
    ):
        interface_missing = tuple(
            field_id
            for field_id, value in (
                (
                    "process.lower_fluid_density",
                    request.process.lower_fluid_density,
                ),
                (
                    "process.upper_fluid_density",
                    request.process.upper_fluid_density,
                ),
            )
            if value is None
        )
        rules.append(
            _rule(
                "interface.density-pair",
                LevelRuleStatus.MISSING_INFORMATION
                if interface_missing
                else LevelRuleStatus.PASSED,
                8.0,
                "Both interface-fluid densities are required."
                if interface_missing
                else "Both ordered interface-fluid densities are explicit.",
                missing=interface_missing,
                verification=("verify.process-properties",),
            )
        )
        variation = request.process.density_variation_percent
        rules.append(
            _rule(
                "interface.density-variation",
                LevelRuleStatus.MISSING_INFORMATION
                if variation is None
                else LevelRuleStatus.FAILED
                if variation > 10.0
                else LevelRuleStatus.PASSED,
                4.0,
                "Interface density variation is unknown."
                if variation is None
                else "Interface density variation exceeds ten percent and needs operating-envelope validation."
                if variation > 10.0
                else "Interface density variation is explicitly bounded for screening.",
                missing=("process.density_variation_percent",)
                if variation is None
                else (),
                verification=("verify.process-properties",),
            )
        )

    if technology in _CONTACT_TECHNOLOGIES | _MECHANICAL_TECHNOLOGIES:
        for suffix, label, field_id, severity in (
            (
                "corrosion",
                "corrosive service",
                "process.corrosive_service",
                request.process.corrosive_service,
            ),
            (
                "abrasion",
                "abrasive service",
                "process.abrasive_service",
                request.process.abrasive_service,
            ),
        ):
            rules.append(
                _condition_rule(
                    rule_id=f"materials.{suffix}",
                    label=label,
                    field_id=field_id,
                    severity=severity,
                    weight=2.5,
                    technology=technology,
                    high_is_failure=False,
                )
            )

    if technology in {
        LevelTechnology.NON_CONTACT_RADAR,
        LevelTechnology.GUIDED_WAVE_RADAR,
        LevelTechnology.ULTRASONIC,
        LevelTechnology.DISPLACER,
        LevelTechnology.MAGNETIC_FLOAT,
        LevelTechnology.TANK_GAUGING,
    }:
        rules.append(
            _condition_rule(
                rule_id="process.agitation",
                label="agitation",
                field_id="process.agitation",
                severity=request.process.agitation,
                weight=3.0,
                technology=technology,
                high_is_failure=False,
            )
        )

    if technology in {
        LevelTechnology.NON_CONTACT_RADAR,
        LevelTechnology.GUIDED_WAVE_RADAR,
        LevelTechnology.ULTRASONIC,
        LevelTechnology.TANK_GAUGING,
    }:
        rules.append(
            _condition_rule(
                rule_id="vessel.internal-obstructions",
                label="internal obstructions",
                field_id="vessel.internal_obstructions",
                severity=request.vessel.internal_obstructions,
                weight=3.0,
                technology=technology,
                high_is_failure=True,
            )
        )

    mounting_constraints_missing = request.vessel.mounting_constraints is None
    rules.append(
        _rule(
            "installation.mounting-constraints",
            LevelRuleStatus.MISSING_INFORMATION
            if mounting_constraints_missing
            else LevelRuleStatus.PASSED,
            3.0,
            "Mounting constraints and available clearances are not described."
            if mounting_constraints_missing
            else "Mounting constraints are explicitly described.",
            missing=("vessel.mounting_constraints",)
            if mounting_constraints_missing
            else (),
            verification=("verify.nozzle-mounting",),
        )
    )

    access = request.installation.maintenance_access
    rules.append(
        _rule(
            "installation.maintenance-access",
            LevelRuleStatus.MISSING_INFORMATION
            if access is LevelMaintenanceAccess.UNKNOWN
            else LevelRuleStatus.CAUTION
            if access
            in {
                LevelMaintenanceAccess.DIFFICULT,
                LevelMaintenanceAccess.INACCESSIBLE_DURING_OPERATION,
            }
            else LevelRuleStatus.PASSED,
            3.0,
            "Maintenance access is unknown."
            if access is LevelMaintenanceAccess.UNKNOWN
            else "Restricted access requires remote diagnostics and planned maintainability controls."
            if access
            in {
                LevelMaintenanceAccess.DIFFICULT,
                LevelMaintenanceAccess.INACCESSIBLE_DURING_OPERATION,
            }
            else "Maintenance access is explicit and not severely restricted.",
            missing=("installation.maintenance_access",)
            if access is LevelMaintenanceAccess.UNKNOWN
            else (),
            verification=("verify.environment",),
        )
    )

    electrical_power = request.installation.electrical_power_available
    instrument_air = request.installation.instrument_air_available
    powered_electronic_technologies = {
        LevelTechnology.NON_CONTACT_RADAR,
        LevelTechnology.GUIDED_WAVE_RADAR,
        LevelTechnology.HYDROSTATIC_PRESSURE,
        LevelTechnology.ULTRASONIC,
        LevelTechnology.CAPACITANCE,
        LevelTechnology.VIBRATING_FORK,
        LevelTechnology.ROTARY_PADDLE,
        LevelTechnology.RADIOMETRIC,
        LevelTechnology.TANK_GAUGING,
    }
    flexible_utility_technologies = {
        LevelTechnology.DIFFERENTIAL_PRESSURE,
        LevelTechnology.DISPLACER,
    }
    utility_missing: tuple[str, ...] = ()
    utility_failure = False
    utility_caution = False
    if technology in powered_electronic_technologies:
        if electrical_power is LevelTriState.UNKNOWN:
            utility_missing = ("installation.electrical_power_available",)
        elif electrical_power is LevelTriState.NO:
            utility_failure = True
    elif technology in flexible_utility_technologies:
        if (
            electrical_power is LevelTriState.UNKNOWN
            and instrument_air is LevelTriState.UNKNOWN
        ):
            utility_missing = (
                "installation.electrical_power_available",
                "installation.instrument_air_available",
            )
        elif (
            electrical_power is LevelTriState.NO
            and instrument_air is LevelTriState.NO
        ):
            utility_failure = True
        elif (
            electrical_power is LevelTriState.UNKNOWN
            or instrument_air is LevelTriState.UNKNOWN
        ):
            utility_caution = True
    elif (
        request.measurement.continuous_output_required is LevelTriState.YES
    ):
        if (
            electrical_power is LevelTriState.UNKNOWN
            and instrument_air is LevelTriState.UNKNOWN
        ):
            utility_missing = (
                "installation.electrical_power_available",
                "installation.instrument_air_available",
            )
        elif (
            electrical_power is LevelTriState.NO
            and instrument_air is LevelTriState.NO
        ):
            utility_failure = True
    elif request.measurement.continuous_output_required is LevelTriState.UNKNOWN:
        utility_missing = ("measurement.continuous_output_required",)
    rules.append(
        _rule(
            "installation.utilities",
            LevelRuleStatus.MISSING_INFORMATION
            if utility_missing
            else LevelRuleStatus.FAILED
            if utility_failure
            else LevelRuleStatus.CAUTION
            if utility_caution
            else LevelRuleStatus.PASSED,
            4.0,
            "Required power or utility availability is unknown."
            if utility_missing
            else "No compatible electrical-power or instrument-air utility is recorded for the required output."
            if utility_failure
            else "One utility path is available while the alternative remains unconfirmed; detailed interface review is required."
            if utility_caution
            else (
                f"Utility states are explicit: electrical power {electrical_power.value}, "
                f"instrument air {instrument_air.value}."
            ),
            missing=utility_missing,
            verification=("verify.environment",),
        )
    )

    hazardous = request.safety.hazardous_area
    approval_missing_ids = (
        ("safety.hazardous_area",)
        if hazardous is LevelTriState.UNKNOWN
        else ("safety.required_approvals",)
        if hazardous is LevelTriState.YES
        and not request.safety.required_approvals
        else ()
    )
    rules.append(
        _rule(
            "safety.required-approvals",
            LevelRuleStatus.MISSING_INFORMATION
            if approval_missing_ids
            else LevelRuleStatus.PASSED,
            3.0,
            "Required hazardous-area approvals are not listed."
            if approval_missing_ids
            else "Required approval context is explicit for this screening stage.",
            category=FindingCategory.SAFETY,
            missing=approval_missing_ids,
            verification=("verify.hazardous-area",),
            references=("ref.eng-070", "ref.iec-60079-0-2026"),
        )
    )

    material_hazard_missing = tuple(
        field_id
        for field_id, value in (
            ("safety.flammable_material", request.safety.flammable_material),
            ("safety.toxic_material", request.safety.toxic_material),
        )
        if value is LevelTriState.UNKNOWN
    )
    hazardous_material_present = (
        request.safety.flammable_material is LevelTriState.YES
        or request.safety.toxic_material is LevelTriState.YES
    )
    rules.append(
        _rule(
            "safety.material-hazards",
            LevelRuleStatus.MISSING_INFORMATION
            if material_hazard_missing
            else LevelRuleStatus.CAUTION
            if hazardous_material_present
            else LevelRuleStatus.PASSED,
            4.0,
            "Flammable and toxic material status is incomplete."
            if material_hazard_missing
            else "Flammable or toxic service requires containment and failure-mode review."
            if hazardous_material_present
            else "Flammable and toxic material states are explicitly recorded as absent.",
            category=FindingCategory.SAFETY,
            missing=material_hazard_missing,
            verification=("verify.process-properties", "verify.hazardous-area"),
            references=("ref.eng-070", "ref.e4m-calc-061"),
        )
    )
    return rules


def _vapor_and_nozzle_rules(
    request: LevelApplicationRequest,
    technology: LevelTechnology,
) -> list[LevelScenarioRuleResult]:
    rules: list[LevelScenarioRuleResult] = []
    if technology in {
        LevelTechnology.NON_CONTACT_RADAR,
        LevelTechnology.ULTRASONIC,
        LevelTechnology.TANK_GAUGING,
    }:
        behavior = request.process.vapor_space_behavior
        vapor_missing = tuple(
            field_id
            for field_id, missing in (
                (
                    "process.vapor_space_behavior",
                    behavior is LevelVaporBehavior.UNKNOWN,
                ),
                (
                    "process.vapor_space_composition",
                    request.process.vapor_space_composition is None,
                ),
            )
            if missing
        )
        if vapor_missing:
            rules.append(
                _rule(
                    "signal-path.vapor-space",
                    LevelRuleStatus.MISSING_INFORMATION,
                    4.0,
                    "Vapor-space composition or behavior is unknown.",
                    missing=vapor_missing,
                    verification=("verify.vapor-space",),
                )
            )
        elif behavior in {
            LevelVaporBehavior.CONDENSING,
            LevelVaporBehavior.STEAM_SERVICE,
            LevelVaporBehavior.DUST_LADEN,
            LevelVaporBehavior.VARIABLE_COMPOSITION,
        }:
            rules.append(
                _rule(
                    "signal-path.vapor-space",
                    LevelRuleStatus.CAUTION,
                    4.0,
                    f"The {behavior.value} vapor space requires representative signal-path validation.",
                    verification=("verify.vapor-space",),
                )
            )
        else:
            rules.append(
                _rule(
                    "signal-path.vapor-space",
                    LevelRuleStatus.PASSED,
                    4.0,
                    "The recorded vapor-space behavior presents no screening conflict.",
                    verification=("verify.vapor-space",),
                )
            )
        nozzle_missing = tuple(
            field_id
            for field_id, missing in (
                (
                    "vessel.nozzle_geometry_confirmed",
                    request.vessel.nozzle_geometry_confirmed
                    is LevelTriState.UNKNOWN,
                ),
                (
                    "vessel.nozzle_diameter",
                    request.vessel.nozzle_diameter is None,
                ),
                (
                    "vessel.nozzle_height",
                    request.vessel.nozzle_height is None,
                ),
            )
            if missing
        )
        nozzle_diameter = canonical_quantity_value(
            request.vessel.nozzle_diameter
        )
        nozzle_height = canonical_quantity_value(request.vessel.nozzle_height)
        if nozzle_missing:
            rules.append(
                _rule(
                    "signal-path.nozzle",
                    LevelRuleStatus.MISSING_INFORMATION,
                    4.0,
                    "Nozzle confirmation, diameter, or height evidence is incomplete.",
                    missing=nozzle_missing,
                    verification=("verify.nozzle-mounting",),
                )
            )
        elif request.vessel.nozzle_geometry_confirmed is LevelTriState.NO:
            rules.append(
                _rule(
                    "signal-path.nozzle",
                    LevelRuleStatus.FAILED,
                    4.0,
                    "The nozzle geometry is explicitly unconfirmed or unsuitable.",
                    verification=("verify.nozzle-mounting",),
                )
            )
        else:
            rules.append(
                _rule(
                    "signal-path.nozzle",
                    LevelRuleStatus.PASSED,
                    4.0,
                    f"Nozzle geometry is confirmed with diameter {nozzle_diameter} m and height {nozzle_height} m, subject to as-built review.",
                    verification=("verify.nozzle-mounting",),
                )
            )
        if (
            request.measurement.upper_dead_zone_allowance is None
            or request.measurement.lower_dead_zone_allowance is None
        ):
            missing = tuple(
                field_id
                for field_id, value in (
                    (
                        "measurement.upper_dead_zone_allowance",
                        request.measurement.upper_dead_zone_allowance,
                    ),
                    (
                        "measurement.lower_dead_zone_allowance",
                        request.measurement.lower_dead_zone_allowance,
                    ),
                )
                if value is None
            )
            rules.append(
                _rule(
                    "signal-path.dead-zones",
                    LevelRuleStatus.MISSING_INFORMATION,
                    3.0,
                    "Upper and lower dead-zone allowances are incomplete.",
                    missing=missing,
                    verification=("verify.nozzle-mounting",),
                )
            )
        else:
            rules.append(
                _rule(
                    "signal-path.dead-zones",
                    LevelRuleStatus.PASSED,
                    3.0,
                    "Both dead-zone allowances are explicit.",
                    verification=("verify.nozzle-mounting",),
                )
            )
    return rules


def _method_links(
    request: LevelApplicationRequest,
    technology: LevelTechnology,
) -> tuple[str, ...]:
    links: set[str] = set()
    range_ready = (
        request.measurement.measurement_span is not None
        and request.vessel.lower_level_elevation is not None
        and request.vessel.upper_level_elevation is not None
    )
    if technology is LevelTechnology.DIFFERENTIAL_PRESSURE:
        if (
            not range_ready
            or request.process.bulk_density is None
            or request.process.density_variation_percent is None
            or request.process.density_variation_percent > 10.0
            or request.vessel.configuration is LevelVesselConfiguration.UNKNOWN
            or request.vessel.dp_arrangement
            in {
                LevelDpArrangement.UNKNOWN,
                LevelDpArrangement.NOT_APPLICABLE,
            }
        ):
            return ()
        links.add("level.dp.endpoint-range")
        arrangement_links = {
            LevelDpArrangement.OPEN_VESSEL: "level.dp.open-vessel-range",
            LevelDpArrangement.CLOSED_DRY_LEG: "level.dp.closed-dry-leg-range",
            LevelDpArrangement.CLOSED_WET_LEG: "level.dp.closed-wet-leg-range",
            LevelDpArrangement.REMOTE_SEALS: "level.dp.remote-seal-range",
        }
        method_id = arrangement_links.get(request.vessel.dp_arrangement)
        if method_id is not None:
            links.add(method_id)
        if (
            request.process.phase
            in {
                LevelProcessPhase.LIQUID_LIQUID_INTERFACE,
                LevelProcessPhase.MULTIPHASE,
            }
            and request.process.lower_fluid_density is not None
            and request.process.upper_fluid_density is not None
        ):
            links.add("level.dp.interface-range")
    elif technology is LevelTechnology.HYDROSTATIC_PRESSURE:
        if (
            range_ready
            and request.process.bulk_density is not None
            and request.process.density_variation_percent is not None
            and request.process.density_variation_percent <= 10.0
            and request.vessel.configuration
            not in {
                LevelVesselConfiguration.UNKNOWN,
                LevelVesselConfiguration.PRESSURIZED,
                LevelVesselConfiguration.VACUUM,
            }
        ):
            links.add("level.hydrostatic.column-pressure")
    elif technology is LevelTechnology.TANK_GAUGING:
        geometry_links = {
            LevelVesselGeometry.VERTICAL_CYLINDER: "level.tank.vertical-cylinder",
            LevelVesselGeometry.HORIZONTAL_CYLINDER: "level.tank.horizontal-cylinder",
        }
        method_id = geometry_links.get(request.vessel.geometry)
        geometry_ready = (
            request.vessel.internal_diameter is not None
            and (
                request.vessel.geometry
                is LevelVesselGeometry.VERTICAL_CYLINDER
                and request.vessel.straight_side_height is not None
                or request.vessel.geometry
                is LevelVesselGeometry.HORIZONTAL_CYLINDER
                and request.vessel.cylindrical_length is not None
            )
        )
        if method_id is not None and range_ready and geometry_ready:
            links.add(method_id)
    return tuple(sorted(links))


def _confidence_band(score: float) -> LevelConfidenceBand:
    if score < 20.0:
        return LevelConfidenceBand.VERY_LOW
    if score < 40.0:
        return LevelConfidenceBand.LOW
    if score < 60.0:
        return LevelConfidenceBand.MODERATE
    if score < 80.0:
        return LevelConfidenceBand.HIGH
    return LevelConfidenceBand.VERY_HIGH


def _score_rules(
    rules: tuple[LevelScenarioRuleResult, ...],
) -> tuple[float, float, LevelScenarioDisposition]:
    if any(item.status is LevelRuleStatus.BLOCKED for item in rules):
        return 0.0, 0.0, LevelScenarioDisposition.BLOCKED
    if any(item.status is LevelRuleStatus.NOT_APPLICABLE for item in rules):
        return 0.0, 0.0, LevelScenarioDisposition.NOT_APPLICABLE
    total = sum(item.weight for item in rules)
    awarded = sum(item.awarded_weight for item in rules)
    evidence_factors = {
        LevelRuleStatus.PASSED: 0.80,
        LevelRuleStatus.CAUTION: 0.60,
        LevelRuleStatus.FAILED: 0.35,
        LevelRuleStatus.MISSING_INFORMATION: 0.0,
    }
    evidence_weight = sum(
        item.weight * evidence_factors[item.status]
        for item in rules
        if item.status in evidence_factors
    )
    suitability = round(100.0 * awarded / total, 6) if total else 0.0
    # User-entered facts are unverified screening evidence and every generic
    # scenario retains unresolved family-level assumptions.  The evidence and
    # assumption factors deliberately prevent cosmetic 100% confidence.
    confidence = (
        round(100.0 * evidence_weight / total * 0.90, 6)
        if total
        else 0.0
    )
    if any(item.status is LevelRuleStatus.MISSING_INFORMATION for item in rules):
        disposition = LevelScenarioDisposition.INSUFFICIENT_INFORMATION
    elif any(item.status is LevelRuleStatus.FAILED for item in rules):
        suitability = min(suitability, 54.999999)
        disposition = LevelScenarioDisposition.CONDITIONAL
    elif any(
        item.category is FindingCategory.SAFETY
        and item.status is LevelRuleStatus.CAUTION
        for item in rules
    ):
        suitability = min(suitability, 74.999999)
        disposition = (
            LevelScenarioDisposition.PLAUSIBLE
            if suitability >= 55.0
            else LevelScenarioDisposition.CONDITIONAL
        )
    elif suitability >= 75.0:
        disposition = LevelScenarioDisposition.PREFERRED
    elif suitability >= 55.0:
        disposition = LevelScenarioDisposition.PLAUSIBLE
    else:
        disposition = LevelScenarioDisposition.CONDITIONAL
    return suitability, confidence, disposition


def _findings(request: LevelApplicationRequest) -> tuple[LevelWizardFinding, ...]:
    findings: list[LevelWizardFinding] = []
    safety = request.safety
    if (
        safety.hazardous_area is LevelTriState.YES
        and safety.hazardous_area_classification is None
    ):
        findings.append(
            LevelWizardFinding(
                finding_id="finding.hazardous-area-classification",
                category=FindingCategory.SAFETY,
                severity=FindingSeverity.CRITICAL,
                title="Hazardous-area classification is missing",
                message=(
                    "No equipment suitability conclusion is safe until the "
                    "hazardous-area classification and jurisdictional basis "
                    "are approved."
                ),
                blocking=True,
                required_action=(
                    "Obtain an approved hazardous-area dossier and competent "
                    "review before continuing selection."
                ),
                verification_requirement_ids=("verify.hazardous-area",),
                affected_technologies=_ALL_TECHNOLOGIES,
                reference_ids=(
                    "ref.e4m-calc-061",
                    "ref.eng-070",
                    "ref.iec-60079-0-2026",
                ),
            )
        )
    if (
        safety.independent_protection_required is LevelTriState.YES
        and not safety.independent_protection_functions
    ):
        findings.append(
            LevelWizardFinding(
                finding_id="finding.independent-protection-undefined",
                category=FindingCategory.SAFETY,
                severity=FindingSeverity.CRITICAL,
                title="Independent protective functions are undefined",
                message=(
                    "Technology screening cannot establish an independent "
                    "protection layer or safety instrumented function."
                ),
                blocking=True,
                required_action=(
                    "Define every protective function and complete an "
                    "independent functional-safety lifecycle assessment."
                ),
                verification_requirement_ids=("verify.independent-protection",),
                affected_technologies=_ALL_TECHNOLOGIES,
                reference_ids=(
                    "ref.e4m-calc-061",
                    "ref.eng-070",
                    "ref.iec-61511-1",
                ),
            )
        )
    elif safety.independent_protection_required is LevelTriState.YES:
        findings.append(
            LevelWizardFinding(
                finding_id="finding.independent-protection-review",
                category=FindingCategory.SAFETY,
                severity=FindingSeverity.WARNING,
                title="Independent protection requires separate lifecycle review",
                message=(
                    "No suitability score demonstrates independence, integrity, "
                    "diagnostic coverage, proof-test performance, or risk reduction."
                ),
                blocking=False,
                required_action=(
                    "Complete the required functional-safety and independence "
                    "review before design commitment."
                ),
                verification_requirement_ids=("verify.independent-protection",),
                affected_technologies=_ALL_TECHNOLOGIES,
                reference_ids=(
                    "ref.e4m-calc-061",
                    "ref.eng-070",
                    "ref.iec-61511-1",
                ),
            )
        )
    protective_objectives = set(request.measurement.objectives).intersection(
        {
            LevelMeasurementObjective.HIGH_HIGH_LEVEL_TRIP,
            LevelMeasurementObjective.LOW_LOW_LEVEL_TRIP,
            LevelMeasurementObjective.OVERFILL_PREVENTION,
        }
    )
    if (
        protective_objectives
        and safety.independent_protection_required is LevelTriState.NO
    ):
        findings.append(
            LevelWizardFinding(
                finding_id="finding.protective-objective-not-independent",
                category=FindingCategory.SAFETY,
                severity=FindingSeverity.WARNING,
                title="Protective level objective lacks declared independence",
                message=(
                    "A trip or overfill objective is declared while independent "
                    "protection is explicitly recorded as not required."
                ),
                blocking=False,
                required_action=(
                    "Confirm the safeguarding architecture, independence basis, "
                    "response path, and approved time-to-hazard assessment."
                ),
                verification_requirement_ids=(
                    _protection_verification_ids(request)
                ),
                affected_technologies=_ALL_TECHNOLOGIES,
                reference_ids=("ref.eng-070", "ref.iec-61511-1"),
            )
        )
    if LevelMeasurementObjective.OVERFILL_PREVENTION in request.measurement.objectives:
        overfill_reference_ids = (
            (
                "ref.api-2350-5",
                "ref.eng-070",
            )
            if request.industry
            in {
                LevelIndustrySector.OIL_AND_GAS,
                LevelIndustrySector.PETROCHEMICAL,
            }
            else ("ref.eng-070",)
        )
        findings.append(
            LevelWizardFinding(
                finding_id="finding.overfill-governance",
                category=FindingCategory.SAFETY,
                severity=FindingSeverity.WARNING,
                title="Overfill prevention requires a site-specific safeguards review",
                message=(
                    "This screening does not establish alarm independence, response "
                    "time, operating procedures, or overfill prevention compliance."
                ),
                blocking=False,
                required_action=(
                    "Confirm the current applicable overfill prevention basis and "
                    "complete an independent safeguards review."
                ),
                verification_requirement_ids=("verify.independent-protection",),
                affected_technologies=_ALL_TECHNOLOGIES,
                reference_ids=overfill_reference_ids,
            )
        )
    if (
        safety.radiometric_source_permitted is LevelTriState.YES
        and safety.radiation_protection_program_confirmed is LevelTriState.NO
    ):
        findings.append(
            LevelWizardFinding(
                finding_id="finding.radiometric-program-unavailable",
                category=FindingCategory.SAFETY,
                severity=FindingSeverity.WARNING,
                title="Radiometric protection program is unavailable",
                message=(
                    "The radiometric scenario is blocked because an approved "
                    "radiation protection program is explicitly unavailable."
                ),
                blocking=False,
                required_action=(
                    "Exclude radiometric technology or obtain all required "
                    "licensing and radiation protection approvals."
                ),
                verification_requirement_ids=(
                    "verify.radiometric-governance",
                ),
                affected_technologies=(LevelTechnology.RADIOMETRIC,),
                reference_ids=("ref.eng-070",),
            )
        )
    if (
        safety.flammable_material is LevelTriState.YES
        or safety.toxic_material is LevelTriState.YES
    ):
        findings.append(
            LevelWizardFinding(
                finding_id="finding.hazardous-material-service",
                category=FindingCategory.SAFETY,
                severity=FindingSeverity.WARNING,
                title="Flammable or toxic material service is confirmed",
                message=(
                    "Containment, emissions, failure modes, isolation, and "
                    "maintenance exposure require a site-specific safety review."
                ),
                blocking=False,
                required_action=(
                    "Complete the process safety, materials, and hazardous-area "
                    "reviews before product selection."
                ),
                verification_requirement_ids=(
                    "verify.hazardous-area",
                    "verify.process-properties",
                ),
                affected_technologies=_ALL_TECHNOLOGIES,
                reference_ids=("ref.eng-070",),
            )
        )
    severity_order = {
        FindingSeverity.CRITICAL: 0,
        FindingSeverity.ERROR: 1,
        FindingSeverity.WARNING: 2,
        FindingSeverity.CAUTION: 3,
        FindingSeverity.INFORMATION: 4,
    }
    return tuple(
        sorted(
            findings,
            key=lambda item: (severity_order[item.severity], item.finding_id),
        )
    )


def _scenario(
    request: LevelApplicationRequest,
    technology: LevelTechnology,
    findings: tuple[LevelWizardFinding, ...],
) -> LevelTechnologyScenario:
    rules = tuple(
        [
            _objective_rule(request, technology),
            _phase_rule(request, technology),
            _contact_rule(request, technology),
            _hazard_rule(request),
            _independence_rule(request),
            _industry_rule(request, technology),
            _environment_rule(request, technology),
            _mounting_rule(request, technology),
        ]
        + _context_completion_rules(request, technology)
        + _technology_rules(request, technology)
        + _vapor_and_nozzle_rules(request, technology)
    )
    suitability, confidence, disposition = _score_rules(rules)
    missing = tuple(
        sorted(
            {
                field_id
                for rule in rules
                for field_id in rule.missing_field_ids
            }
        )
    )
    verification = tuple(
        sorted(
            {
                "verify.technology-validation",
                *(
                    requirement_id
                    for rule in rules
                    for requirement_id in rule.verification_requirement_ids
                ),
            }
        )
    )
    finding_ids = tuple(
        sorted(
            item.finding_id
            for item in findings
            if not item.affected_technologies
            or technology in item.affected_technologies
        )
    )
    reference_ids = tuple(
        sorted(
            {
                "ref.e4m-calc-060",
                "ref.e4m-calc-061",
                "ref.eng-070",
                "ref.e4m-calc-062",
                "ref.e4m-calc-063",
                *(
                    reference_id
                    for rule in rules
                    for reference_id in rule.reference_ids
                ),
            }
        )
    )
    reasons = tuple(
        rule.explanation
        for rule in rules
        if rule.status in (LevelRuleStatus.PASSED, LevelRuleStatus.CAUTION)
    ) or ("No positive screening reason is established yet.",)
    limitations = tuple(
        rule.explanation
        for rule in rules
        if rule.status
        in (
            LevelRuleStatus.FAILED,
            LevelRuleStatus.MISSING_INFORMATION,
            LevelRuleStatus.NOT_APPLICABLE,
            LevelRuleStatus.BLOCKED,
        )
    ) or ("No additional limitation was identified by the static ruleset.",)
    observation_items = [
        f"Recorded process phase: {request.process.phase.value}.",
        f"Recorded industry: {request.industry.value}.",
        f"Recorded vessel configuration: {request.vessel.configuration.value}.",
    ]
    protection_functions = tuple(
        item.value
        for item in request.safety.independent_protection_functions
    )
    if protection_functions:
        observation_items.append(
            "Declared independent protection functions: "
            f"{', '.join(protection_functions)}."
        )
    if (
        technology in _POINT_TECHNOLOGIES
        and protection_functions
    ):
        observation_items.append(
            "This point-level scenario represents a separate protection-layer candidate alongside the continuous measurement architecture."
        )
    observations = tuple(observation_items)
    assumptions = (
        "The scenario represents a generic technology family and no product-specific capability.",
        "Unknown input remains unknown; no favorable process or installation condition is inferred.",
    )
    escalation_items = [
        "Escalate if any process, safety, environmental, or mounting input changes.",
        "Escalate before using this scenario for a protective function, hazardous area, or regulated source.",
        "Escalate every failed or missing rule to a competent instrumentation engineer.",
    ]
    if set(request.safety.independent_protection_functions).intersection(
        {
            LevelProtectionFunction.HIGH_HIGH_TRIP,
            LevelProtectionFunction.OVERFILL_PREVENTION,
        }
    ):
        escalation_items.append(
            "Escalate the high-level protection path for independent setpoint, response-time, final-action, bypass, and proof-test acceptance."
        )
    if set(request.safety.independent_protection_functions).intersection(
        {
            LevelProtectionFunction.LOW_LOW_TRIP,
            LevelProtectionFunction.DRY_RUN_PROTECTION,
        }
    ):
        escalation_items.append(
            "Escalate the low-level protection path for independent setpoint, response-time, final-action, bypass, and proof-test acceptance."
        )
    escalation = tuple(escalation_items)
    summary = (
        f"{technology.value} is {disposition.value} with {suitability:.3f}% "
        f"screening suitability and {confidence:.3f}% evidence confidence."
    )
    return LevelTechnologyScenario(
        scenario_id=f"scenario.{technology.value.replace('_', '-')}",
        technology=technology,
        title=_TECHNOLOGY_TITLES[technology],
        summary=summary,
        disposition=disposition,
        rank=None
        if disposition
        in (
            LevelScenarioDisposition.BLOCKED,
            LevelScenarioDisposition.NOT_APPLICABLE,
        )
        else 1,
        suitability_score=float(suitability),
        confidence_score=float(confidence),
        confidence_band=_confidence_band(confidence),
        confidence_rationale=(
            "Confidence combines input completeness, unverified screening "
            "evidence quality, rule applicability, and a fixed unresolved-"
            "assumption factor. Missing facts add zero and user-entered facts "
            "alone cannot produce 100 percent confidence."
        ),
        ranking_rationale=(
            "Dense ranks are shared when disposition, suitability, and "
            "confidence are exactly tied. Technology name is used only as a "
            "deterministic serialization key and does not break a tie."
        ),
        rule_results=rules,
        reasons=reasons,
        limitations=limitations,
        observations=observations,
        assumptions=assumptions,
        escalation_conditions=escalation,
        supporting_calculation_method_ids=_method_links(request, technology),
        missing_information_ids=missing,
        finding_ids=finding_ids,
        verification_requirement_ids=verification,
        reference_ids=reference_ids,
    )


def _rank_scenarios(
    scenarios: tuple[LevelTechnologyScenario, ...],
) -> tuple[LevelTechnologyScenario, ...]:
    disposition_order = {
        LevelScenarioDisposition.PREFERRED: 0,
        LevelScenarioDisposition.PLAUSIBLE: 1,
        LevelScenarioDisposition.CONDITIONAL: 2,
        LevelScenarioDisposition.INSUFFICIENT_INFORMATION: 3,
        LevelScenarioDisposition.NOT_APPLICABLE: 4,
        LevelScenarioDisposition.BLOCKED: 5,
    }
    ordered = sorted(
        scenarios,
        key=lambda item: (
            disposition_order[item.disposition],
            -item.suitability_score,
            -item.confidence_score,
            item.technology.value,
        ),
    )
    ranked: list[LevelTechnologyScenario] = []
    next_rank = 1
    previous_key: tuple[object, ...] | None = None
    for scenario in ordered:
        if scenario.disposition in (
            LevelScenarioDisposition.BLOCKED,
            LevelScenarioDisposition.NOT_APPLICABLE,
        ):
            ranked.append(scenario.model_copy(update={"rank": None}))
        else:
            current_key = (
                scenario.disposition,
                scenario.suitability_score,
                scenario.confidence_score,
            )
            if previous_key is not None and current_key != previous_key:
                next_rank += 1
            ranked.append(scenario.model_copy(update={"rank": next_rank}))
            previous_key = current_key
    return tuple(
        sorted(
            ranked,
            key=lambda item: (
                item.rank is None,
                item.rank or len(ranked) + 1,
                item.technology.value,
            ),
        )
    )


_MISSING_REASONS: Final = {
    "industry": "Industry context can change hygiene, abrasion, dust, regulatory, and maintenance requirements.",
    "installation.electrical_power_available": "Electrical power availability is required for active electronic measurement scenarios.",
    "installation.environments": "Environmental exposure and maintainability are not confirmed.",
    "installation.instrument_air_available": "Instrument-air availability is needed when evaluating an alternative pneumatic utility path.",
    "installation.maintenance_access": "Maintenance access is needed to judge mechanical serviceability.",
    "installation.maximum_ambient_temperature": "The maximum ambient temperature is required for environmental suitability screening.",
    "installation.minimum_ambient_temperature": "The minimum ambient temperature is required for environmental suitability screening.",
    "measurement.contact_preference": "Whether process contact is permitted or preferred is unknown.",
    "measurement.continuous_output_required": "The automation output requirement is unknown.",
    "measurement.local_indication_required": "The local indication requirement is unknown.",
    "measurement.measurement_span": "The required measurement span is undefined.",
    "measurement.required_accuracy_percent_of_span": "The required accuracy is undefined.",
    "measurement.required_response_time": "The required response time is undefined.",
    "measurement.lower_dead_zone_allowance": "The lower unusable measurement zone is not defined.",
    "measurement.objectives": "The required continuous, point, interface, inventory, or protective function is undefined.",
    "measurement.upper_dead_zone_allowance": "The upper blocking or dead-zone allowance is not defined.",
    "process.buildup": "Buildup severity can impair contacting and signal-path technologies.",
    "process.abrasive_service": "Abrasive exposure affects materials and moving elements.",
    "process.agitation": "Agitation affects surface stability, probes, and moving elements.",
    "process.corrosive_service": "Corrosive exposure affects wetted-material suitability.",
    "process.dielectric_constant": "Dielectric behavior affects radar and capacitance applicability.",
    "process.density_variation_percent": "Density variation affects pressure, interface, and buoyancy technologies.",
    "process.dust": "Dust severity affects solids and signal-path technologies.",
    "process.foam": "Foam severity affects acoustic, radar, and surface measurement confidence.",
    "process.hygienic_service": "Hygienic design and cleaning duty are undefined.",
    "process.dynamic_viscosity": "Dynamic viscosity affects contacting and moving technologies.",
    "process.lower_fluid_density": "The lower interface-fluid density is undefined.",
    "process.maximum_absolute_pressure": "Maximum absolute process pressure is undefined.",
    "process.maximum_temperature": "Maximum process temperature is undefined.",
    "process.minimum_temperature": "Minimum process temperature is undefined.",
    "process.normal_absolute_pressure": "Normal absolute process pressure is undefined.",
    "process.normal_temperature": "Normal process temperature is undefined.",
    "process.phase": "The bulk phase is required to screen technology applicability.",
    "process.slurry": "Slurry severity affects impulse paths, probes, and moving elements.",
    "process.steam": "Steam severity affects acoustic and exposed measurement paths.",
    "process.sticky_material": "Sticky-material behavior affects moving and contacting elements.",
    "process.turbulence": "Turbulence severity affects surface and signal stability.",
    "process.upper_fluid_density": "The upper interface-fluid density is undefined.",
    "process.vapor_space_behavior": "Vapor-space behavior affects non-contact signal propagation.",
    "process.vapor_space_composition": "Vapor-space composition affects non-contact signal propagation.",
    "process.bulk_density": "Density is required for pressure and buoyancy-based screening.",
    "safety.hazardous_area": "Unknown hazardous-area status cannot be treated as non-hazardous.",
    "safety.flammable_material": "Flammable-material status is unknown.",
    "safety.independent_protection_required": "The need for an independent protective function is unresolved.",
    "safety.radiation_protection_program_confirmed": "Radiometric governance is not confirmed.",
    "safety.radiometric_source_permitted": "Whether a regulated radiometric source is permitted is unknown.",
    "safety.required_approvals": "Required hazardous-area approvals are not defined.",
    "safety.toxic_material": "Toxic-material status is unknown.",
    "vessel.available_mounting_positions": "Available mounting positions and constraints are undefined.",
    "vessel.configuration": "The vessel pressure-boundary configuration is required for DP and hydrostatic applicability.",
    "vessel.cylindrical_length": "Horizontal cylindrical vessel length is required before linking a volume calculation.",
    "vessel.dp_arrangement": "The DP reference and seal arrangement is undefined.",
    "vessel.geometry": "Vessel geometry is required for inventory-conversion screening.",
    "vessel.internal_diameter": "Vessel internal diameter is required before linking a cylindrical volume calculation.",
    "vessel.internal_obstructions": "Internal obstruction severity and signal path are undefined.",
    "vessel.lower_level_elevation": "The lower measurement or low-protection setpoint elevation is undefined.",
    "vessel.mounting_constraints": "Physical mounting constraints and clearances are undefined.",
    "vessel.nozzle_diameter": "Nozzle diameter evidence is required for signal-path screening.",
    "vessel.nozzle_geometry_confirmed": "Nozzle geometry and clear measurement path are unconfirmed.",
    "vessel.nozzle_height": "Nozzle height evidence is required for signal-path screening.",
    "vessel.straight_side_height": "Vertical cylindrical straight-side height is required before linking a volume calculation.",
    "vessel.upper_level_elevation": "The upper measurement or high-protection setpoint elevation is undefined.",
}


def _missing_information(
    scenarios: tuple[LevelTechnologyScenario, ...],
) -> tuple[LevelMissingInformation, ...]:
    affected: dict[str, set[LevelTechnology]] = {}
    for scenario in scenarios:
        for field_id in scenario.missing_information_ids:
            affected.setdefault(field_id, set()).add(scenario.technology)
    safety_critical_ids = {
        "safety.flammable_material",
        "safety.hazardous_area",
        "safety.independent_protection_required",
        "safety.radiation_protection_program_confirmed",
        "safety.radiometric_source_permitted",
        "safety.required_approvals",
        "safety.toxic_material",
    }
    return tuple(
        LevelMissingInformation(
            field_id=field_id,
            reason=_MISSING_REASONS.get(
                field_id,
                "This information is required by at least one auditable screening rule.",
            ),
            safety_critical=field_id in safety_critical_ids,
            affected_technologies=tuple(sorted(technologies, key=lambda item: item.value)),
        )
        for field_id, technologies in sorted(affected.items())
    )


def _assessment_status(
    findings: tuple[LevelWizardFinding, ...],
    missing: tuple[LevelMissingInformation, ...],
    scenarios: tuple[LevelTechnologyScenario, ...],
) -> CalculationStatus:
    if any(item.blocking for item in findings):
        return CalculationStatus.BLOCKED
    viable = tuple(
        item
        for item in scenarios
        if item.disposition
        in (
            LevelScenarioDisposition.PREFERRED,
            LevelScenarioDisposition.PLAUSIBLE,
        )
    )
    if all(
        item.disposition is LevelScenarioDisposition.NOT_APPLICABLE
        for item in scenarios
    ):
        return CalculationStatus.NOT_APPLICABLE
    if any(item.safety_critical for item in missing):
        return CalculationStatus.INSUFFICIENT_INPUT
    if not viable:
        return (
            CalculationStatus.INSUFFICIENT_INPUT
            if missing
            else CalculationStatus.FAILED
        )
    if findings or missing or any(
        item.disposition is not LevelScenarioDisposition.PREFERRED
        for item in scenarios
    ):
        return CalculationStatus.COMPLETED_WITH_WARNINGS
    return CalculationStatus.COMPLETED


def _fingerprint(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return sha256(canonical).hexdigest()


class LevelApplicationWizard:
    """Immutable, stateless implementation of ruleset 1.0.0."""

    __slots__ = ("_locked",)

    def __init__(self) -> None:
        object.__setattr__(self, "_locked", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_locked", False):
            raise AttributeError("LevelApplicationWizard instances are immutable.")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if getattr(self, "_locked", False):
            raise AttributeError("LevelApplicationWizard instances are immutable.")
        object.__delattr__(self, name)

    @property
    def version(self) -> str:
        return LEVEL_APPLICATION_WIZARD_VERSION

    @property
    def ruleset_version(self) -> str:
        return LEVEL_APPLICATION_RULESET_VERSION

    def assess(
        self,
        request: LevelApplicationRequest,
    ) -> LevelApplicationAssessment:
        if not isinstance(request, LevelApplicationRequest):
            raise TypeError("request must be a LevelApplicationRequest.")
        try:
            validated_request = LevelApplicationRequest.model_validate(
                request.model_dump(mode="python", round_trip=True, warnings="error")
            )
            findings = _findings(validated_request)
            scenarios = _rank_scenarios(
                tuple(
                    _scenario(validated_request, technology, findings)
                    for technology in _ALL_TECHNOLOGIES
                )
            )
            missing = _missing_information(scenarios)
            verification_ids = {
                requirement_id
                for scenario in scenarios
                for requirement_id in scenario.verification_requirement_ids
            }
            verification_ids.update(
                requirement_id
                for finding in findings
                for requirement_id in finding.verification_requirement_ids
            )
            verification_steps = tuple(
                _VERIFICATION_CATALOGUE[item]
                for item in sorted(verification_ids)
            )
            reference_ids = {
                reference_id
                for scenario in scenarios
                for reference_id in scenario.reference_ids
            }
            reference_ids.update(
                reference_id
                for finding in findings
                for reference_id in finding.reference_ids
            )
            references_by_id = {
                item.reference_id: item for item in _REFERENCES
            }
            references = tuple(
                references_by_id[item] for item in sorted(reference_ids)
            )
            status = _assessment_status(findings, missing, scenarios)
            observations = (
                "All twelve generic technology families remain visible unless a typed rule marks one blocked or not applicable.",
                "Suitability and confidence are deterministic screening indicators, not probabilities or product ratings.",
                "Step 95 method identifiers are non-executable supporting links only.",
            )
            limitations = (
                "No product, manufacturer, model, materials-of-construction, certification, sizing, or installation detail is selected.",
                "No linked calculation method is executed and no calculated result is represented by this assessment.",
                "Standards currency, jurisdictional applicability, and site requirements must be reconfirmed at project use.",
            )
            fingerprint_payload = {
                "wizard_version": LEVEL_APPLICATION_WIZARD_VERSION,
                "ruleset_version": LEVEL_APPLICATION_RULESET_VERSION,
                "status": status.value,
                "request": validated_request.model_dump(mode="json"),
                "safety_findings": [item.model_dump(mode="json") for item in findings],
                "observations": observations,
                "missing_information": [item.model_dump(mode="json") for item in missing],
                "scenarios": [item.model_dump(mode="json") for item in scenarios],
                "verification_steps": [
                    item.model_dump(mode="json") for item in verification_steps
                ],
                "references": [item.model_dump(mode="json") for item in references],
                "limitations": limitations,
            }
            return LevelApplicationAssessment(
                wizard_version=LEVEL_APPLICATION_WIZARD_VERSION,
                ruleset_version=LEVEL_APPLICATION_RULESET_VERSION,
                status=status,
                assessment_fingerprint=_fingerprint(fingerprint_payload),
                request=validated_request,
                safety_findings=findings,
                observations=observations,
                missing_information=missing,
                scenarios=scenarios,
                verification_steps=verification_steps,
                references=references,
                limitations=limitations,
            )
        except (TypeError, ValueError, KeyError) as exc:
            raise LevelApplicationWizardError(
                "The static level application assessment could not be constructed."
            ) from exc


DEFAULT_LEVEL_APPLICATION_WIZARD: Final = LevelApplicationWizard()


def assess_level_application(
    request: LevelApplicationRequest,
) -> LevelApplicationAssessment:
    """Assess one request with the immutable reviewed default wizard."""

    return DEFAULT_LEVEL_APPLICATION_WIZARD.assess(request)


__all__ = [
    "DEFAULT_LEVEL_APPLICATION_WIZARD",
    "LEVEL_APPLICATION_RULESET_VERSION",
    "LEVEL_APPLICATION_WIZARD_VERSION",
    "LevelApplicationWizard",
    "LevelApplicationWizardError",
    "assess_level_application",
]

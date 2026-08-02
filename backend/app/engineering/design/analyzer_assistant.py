"""Deterministic, safety-first analyzer application assistant.

The assistant screens only generic measurement principles.  It exposes
unknowns, sample-system risks, interferences, a preliminary declared response
budget, utilities, hazards, confidence, and verification actions.  It performs
no product selection, standards execution, API or persistence work, external
I/O, or voice processing.
"""

from __future__ import annotations

from math import pi
from types import MappingProxyType
from typing import Final

from app.engineering.calculations.models import (
    CalculationStatus,
    FindingCategory,
    FindingSeverity,
)
from app.engineering.design.analyzer_models import (
    ANALYZER_APPLICATION_MODEL_VERSION,
    AnalyzerAnalyteFamily,
    AnalyzerApplicationAssessment,
    AnalyzerApplicationKind,
    AnalyzerApplicationRequest,
    AnalyzerConditionSeverity,
    AnalyzerMeasurementObjective,
    AnalyzerMissingInformation,
    AnalyzerResponseContributorKind,
    AnalyzerRuleResult,
    AnalyzerRuleStatus,
    AnalyzerSafetyFinding,
    AnalyzerSampleApproach,
    AnalyzerSampleDisposition,
    AnalyzerSamplePhase,
    AnalyzerScenarioDisposition,
    AnalyzerTechnology,
    AnalyzerTechnologyDefinition,
    AnalyzerTechnologyScenario,
    AnalyzerTriState,
    AnalyzerUtility,
    AnalyzerVerificationPriority,
    AnalyzerVerificationStep,
    analyzer_confidence_band,
    canonical_analyzer_quantity_value,
    fingerprint_analyzer_payload,
)

ANALYZER_ASSISTANT_VERSION = "1.0.0"
ANALYZER_RULESET_VERSION = "1.0.0"
ANALYZER_TECHNOLOGY_TAXONOMY_VERSION = "1.0.0"

_REF_GOVERNANCE = "ref.eng-070"
_REF_SCENARIO = "ref.e4m-calc-060"
_REF_CONTEXT = "ref.e4m-calc-061"
_REF_CONFIDENCE = "ref.e4m-calc-062"
_REF_ESCALATION = "ref.e4m-calc-063"

_EXTRACTIVE_APPROACHES = frozenset(
    {
        AnalyzerSampleApproach.EXTRACTIVE,
        AnalyzerSampleApproach.FAST_LOOP,
        AnalyzerSampleApproach.GRAB_SAMPLE,
        AnalyzerSampleApproach.ASPIRATED_DETECTION,
    }
)
_HARSH_CONDITIONS = frozenset(
    {
        AnalyzerConditionSeverity.MODERATE,
        AnalyzerConditionSeverity.HIGH,
    }
)


class AnalyzerApplicationAssistantError(RuntimeError):
    """Raised when the static assistant cannot build a valid assessment."""


def _technology(
    technology: AnalyzerTechnology,
    title: str,
    principle: str,
    kinds: tuple[AnalyzerApplicationKind, ...],
    analytes: tuple[AnalyzerAnalyteFamily, ...],
    phases: tuple[AnalyzerSamplePhase, ...],
    approaches: tuple[AnalyzerSampleApproach, ...],
    limitations: tuple[str, ...],
    *,
    utilities: tuple[AnalyzerUtility, ...] = (AnalyzerUtility.ELECTRICAL_POWER,),
    extractive: bool = False,
    cycle_based: bool = False,
) -> AnalyzerTechnologyDefinition:
    return AnalyzerTechnologyDefinition(
        technology=technology,
        title=title,
        principle=principle,
        supported_application_kinds=kinds,
        supported_analyte_families=analytes,
        supported_sample_phases=phases,
        supported_sample_approaches=approaches,
        required_utilities=utilities,
        extractive_sample_system_required=extractive,
        cycle_based_measurement=cycle_based,
        generic_limitations=limitations,
    )


_LIQUID_KIND = (AnalyzerApplicationKind.LIQUID_PROCESS,)
_GAS_KIND = (AnalyzerApplicationKind.PROCESS_GAS,)
_GC_KIND = (AnalyzerApplicationKind.GAS_CHROMATOGRAPHY,)
_DETECTION_KIND = (AnalyzerApplicationKind.GAS_DETECTION,)
_LIQUID_PHASE = (AnalyzerSamplePhase.LIQUID,)
_GAS_PHASE = (AnalyzerSamplePhase.GAS,)
_LIQUID_APPROACHES = (
    AnalyzerSampleApproach.EXTRACTIVE,
    AnalyzerSampleApproach.FAST_LOOP,
    AnalyzerSampleApproach.GRAB_SAMPLE,
    AnalyzerSampleApproach.IN_SITU,
)
_GAS_ANALYZER_APPROACHES = (
    AnalyzerSampleApproach.EXTRACTIVE,
    AnalyzerSampleApproach.FAST_LOOP,
    AnalyzerSampleApproach.IN_SITU,
)
_POINT_APPROACHES = (
    AnalyzerSampleApproach.POINT_DETECTOR,
    AnalyzerSampleApproach.ASPIRATED_DETECTION,
)
_ACOUSTIC_POINT_APPROACH = (AnalyzerSampleApproach.POINT_DETECTOR,)
_OPEN_PATH_APPROACH = (AnalyzerSampleApproach.OPEN_PATH,)


ANALYZER_TECHNOLOGY_CATALOGUE: Final = tuple(
    sorted(
        (
            _technology(
                AnalyzerTechnology.PH_ELECTRODE,
                "pH or ORP electrochemical measurement",
                "A contact electrode develops a potential related to acidity, alkalinity, or oxidation-reduction duty.",
                _LIQUID_KIND,
                (AnalyzerAnalyteFamily.ACIDITY_ALKALINITY,),
                _LIQUID_PHASE,
                _LIQUID_APPROACHES,
                (
                    "Coating, reference condition, temperature, and calibration history require application-specific verification.",
                ),
            ),
            _technology(
                AnalyzerTechnology.CONDUCTIVITY_CELL,
                "Conductivity or resistivity cell",
                "A contact or inductive cell measures the electrical response of a liquid matrix.",
                _LIQUID_KIND,
                (AnalyzerAnalyteFamily.CONDUCTIVITY,),
                _LIQUID_PHASE,
                _LIQUID_APPROACHES,
                (
                    "Cell constant, polarization, coating, temperature compensation, and matrix range remain unverified.",
                ),
            ),
            _technology(
                AnalyzerTechnology.DISSOLVED_OXYGEN,
                "Dissolved-oxygen measurement",
                "An electrochemical or optical sensing element responds to oxygen dissolved in a liquid.",
                _LIQUID_KIND,
                (AnalyzerAnalyteFamily.DISSOLVED_OXYGEN,),
                _LIQUID_PHASE,
                _LIQUID_APPROACHES,
                (
                    "Flow, membrane or optical-cap condition, fouling, salinity, pressure, and temperature effects require verification.",
                ),
            ),
            _technology(
                AnalyzerTechnology.TURBIDITY_OPTICAL,
                "Optical turbidity or suspended-solids measurement",
                "An optical path measures scattering or attenuation associated with particles in a liquid.",
                _LIQUID_KIND,
                (AnalyzerAnalyteFamily.TURBIDITY_SOLIDS,),
                _LIQUID_PHASE,
                _LIQUID_APPROACHES,
                (
                    "Particle size, colour, bubbles, window fouling, and installation geometry can change the response.",
                ),
            ),
            _technology(
                AnalyzerTechnology.UV_VIS_LIQUID,
                "Liquid UV-visible absorption measurement",
                "A liquid optical path measures wavelength-dependent absorption as a generic concentration or organic-load indicator.",
                _LIQUID_KIND,
                (
                    AnalyzerAnalyteFamily.HYDROCARBON,
                    AnalyzerAnalyteFamily.ORGANIC_LOAD,
                    AnalyzerAnalyteFamily.OTHER,
                ),
                _LIQUID_PHASE,
                _LIQUID_APPROACHES,
                (
                    "Spectral overlap, scattering, colour, bubbles, path length, and window fouling require representative testing.",
                ),
            ),
            _technology(
                AnalyzerTechnology.NDIR_GAS,
                "Non-dispersive infrared gas measurement",
                "An infrared optical channel measures absorption in a selected spectral region.",
                _GAS_KIND,
                (
                    AnalyzerAnalyteFamily.COMBUSTIBLE_GAS,
                    AnalyzerAnalyteFamily.HYDROCARBON,
                    AnalyzerAnalyteFamily.OTHER,
                    AnalyzerAnalyteFamily.TOXIC_GAS,
                ),
                _GAS_PHASE,
                _GAS_ANALYZER_APPROACHES,
                (
                    "Cross-sensitivity, pressure, temperature, moisture, optical contamination, and range require verification.",
                ),
            ),
            _technology(
                AnalyzerTechnology.PARAMAGNETIC_OXYGEN,
                "Paramagnetic oxygen measurement",
                "A gas cell responds to the magnetic susceptibility of oxygen relative to the sample matrix.",
                _GAS_KIND,
                (AnalyzerAnalyteFamily.OXYGEN,),
                _GAS_PHASE,
                (AnalyzerSampleApproach.EXTRACTIVE, AnalyzerSampleApproach.FAST_LOOP),
                (
                    "Matrix magnetic susceptibility, pressure, flow, moisture, and sample conditioning require verification.",
                ),
                extractive=True,
            ),
            _technology(
                AnalyzerTechnology.ZIRCONIA_OXYGEN,
                "Zirconia oxygen measurement",
                "A heated solid-electrolyte cell develops a response related to oxygen partial pressure.",
                _GAS_KIND,
                (AnalyzerAnalyteFamily.OXYGEN,),
                _GAS_PHASE,
                _GAS_ANALYZER_APPROACHES,
                (
                    "Combustibles, reducing service, temperature, pressure, poisoning, and installation duty require verification.",
                ),
            ),
            _technology(
                AnalyzerTechnology.TUNABLE_DIODE_LASER,
                "Tunable-diode-laser absorption measurement",
                "A narrow-band optical path measures a selected gas absorption feature.",
                _GAS_KIND,
                (
                    AnalyzerAnalyteFamily.MOISTURE,
                    AnalyzerAnalyteFamily.OXYGEN,
                    AnalyzerAnalyteFamily.OTHER,
                    AnalyzerAnalyteFamily.TOXIC_GAS,
                ),
                _GAS_PHASE,
                _GAS_ANALYZER_APPROACHES,
                (
                    "Spectral selection, path conditions, pressure, temperature, particulates, and alignment require verification.",
                ),
            ),
            _technology(
                AnalyzerTechnology.FTIR_GAS,
                "Fourier-transform infrared gas measurement",
                "A broadband infrared spectrum supports generic multi-component or single-component gas analysis.",
                _GAS_KIND,
                (
                    AnalyzerAnalyteFamily.HYDROCARBON,
                    AnalyzerAnalyteFamily.MULTI_COMPONENT_COMPOSITION,
                    AnalyzerAnalyteFamily.OTHER,
                    AnalyzerAnalyteFamily.TOXIC_GAS,
                ),
                _GAS_PHASE,
                (AnalyzerSampleApproach.EXTRACTIVE, AnalyzerSampleApproach.FAST_LOOP),
                (
                    "Spectral interference, calibration model, moisture, pressure, temperature, and cell cleanliness require verification.",
                ),
                extractive=True,
            ),
            _technology(
                AnalyzerTechnology.THERMAL_CONDUCTIVITY,
                "Thermal-conductivity gas measurement",
                "A detector responds to thermal-conductivity contrast between the target duty and background matrix.",
                _GAS_KIND,
                (
                    AnalyzerAnalyteFamily.HYDROCARBON,
                    AnalyzerAnalyteFamily.OTHER,
                    AnalyzerAnalyteFamily.PHYSICAL_PROPERTY,
                ),
                _GAS_PHASE,
                (AnalyzerSampleApproach.EXTRACTIVE, AnalyzerSampleApproach.FAST_LOOP),
                (
                    "Background composition, pressure, temperature, flow, and sensitivity contrast require verification.",
                ),
                extractive=True,
            ),
            _technology(
                AnalyzerTechnology.GAS_CHROMATOGRAPH,
                "Process gas chromatography",
                "A controlled sample is separated in time and measured by a generic chromatographic detector.",
                _GC_KIND,
                (AnalyzerAnalyteFamily.MULTI_COMPONENT_COMPOSITION,),
                (AnalyzerSamplePhase.GAS, AnalyzerSamplePhase.LIQUID),
                (AnalyzerSampleApproach.EXTRACTIVE, AnalyzerSampleApproach.FAST_LOOP),
                (
                    "Sampling, phase handling, separation, coelution, calibration, carrier purity, cycle time, and disposal require verification.",
                ),
                utilities=(
                    AnalyzerUtility.CALIBRATION_GAS,
                    AnalyzerUtility.CARRIER_GAS,
                    AnalyzerUtility.ELECTRICAL_POWER,
                ),
                extractive=True,
                cycle_based=True,
            ),
            _technology(
                AnalyzerTechnology.MASS_SPECTROMETRY,
                "Process mass-spectrometry screening",
                "A conditioned sample is ionized and screened by mass-to-charge response for multi-component duty.",
                (
                    AnalyzerApplicationKind.GAS_CHROMATOGRAPHY,
                    AnalyzerApplicationKind.PROCESS_GAS,
                ),
                (AnalyzerAnalyteFamily.MULTI_COMPONENT_COMPOSITION,),
                _GAS_PHASE,
                (AnalyzerSampleApproach.EXTRACTIVE, AnalyzerSampleApproach.FAST_LOOP),
                (
                    "Fragment overlap, vacuum interface, calibration model, sample compatibility, and matrix range require verification.",
                ),
                utilities=(
                    AnalyzerUtility.CALIBRATION_GAS,
                    AnalyzerUtility.ELECTRICAL_POWER,
                ),
                extractive=True,
            ),
            _technology(
                AnalyzerTechnology.FLAME_IONIZATION,
                "Flame-ionization hydrocarbon measurement",
                "Organic compounds are ionized in a controlled flame to provide a non-specific hydrocarbon response.",
                _GAS_KIND,
                (
                    AnalyzerAnalyteFamily.HYDROCARBON,
                    AnalyzerAnalyteFamily.VOLATILE_ORGANIC_COMPOUND,
                ),
                _GAS_PHASE,
                (AnalyzerSampleApproach.EXTRACTIVE, AnalyzerSampleApproach.FAST_LOOP),
                (
                    "Response factors, oxygenates, methane/non-methane basis, gases, flame safety, and sample conditioning require verification.",
                ),
                utilities=(
                    AnalyzerUtility.CALIBRATION_GAS,
                    AnalyzerUtility.ELECTRICAL_POWER,
                    AnalyzerUtility.INSTRUMENT_AIR,
                ),
                extractive=True,
            ),
            _technology(
                AnalyzerTechnology.ELECTROCHEMICAL_GAS_DETECTOR,
                "Electrochemical gas detector",
                "A point sensor produces an electrochemical response to a toxic gas or oxygen duty.",
                _DETECTION_KIND,
                (AnalyzerAnalyteFamily.OXYGEN, AnalyzerAnalyteFamily.TOXIC_GAS),
                _GAS_PHASE,
                _POINT_APPROACHES,
                (
                    "Cross-sensitivity, poisoning, humidity, temperature, pressure, life, alarm basis, and coverage require verification.",
                ),
            ),
            _technology(
                AnalyzerTechnology.CATALYTIC_BEAD_GAS_DETECTOR,
                "Catalytic-combustion gas detector",
                "A point sensor responds to heat released by catalytic oxidation of combustible gas.",
                _DETECTION_KIND,
                (AnalyzerAnalyteFamily.COMBUSTIBLE_GAS,),
                _GAS_PHASE,
                _POINT_APPROACHES,
                (
                    "Oxygen availability, poisons, inhibitors, range, alarm basis, and detector coverage require verification.",
                ),
            ),
            _technology(
                AnalyzerTechnology.INFRARED_POINT_GAS_DETECTOR,
                "Infrared point gas detector",
                "A point optical path responds to infrared absorption by a combustible-gas duty.",
                _DETECTION_KIND,
                (
                    AnalyzerAnalyteFamily.COMBUSTIBLE_GAS,
                    AnalyzerAnalyteFamily.HYDROCARBON,
                ),
                _GAS_PHASE,
                _POINT_APPROACHES,
                (
                    "Gas detectability, obscuration, contamination, alarm basis, and detector coverage require verification.",
                ),
            ),
            _technology(
                AnalyzerTechnology.OPEN_PATH_INFRARED_GAS_DETECTOR,
                "Open-path infrared gas detector",
                "An open optical path responds to integrated infrared absorption along a monitored path.",
                _DETECTION_KIND,
                (
                    AnalyzerAnalyteFamily.COMBUSTIBLE_GAS,
                    AnalyzerAnalyteFamily.HYDROCARBON,
                ),
                _GAS_PHASE,
                _OPEN_PATH_APPROACH,
                (
                    "Path geometry, weather, obscuration, alignment, alarm basis, and coverage require verification.",
                ),
            ),
            _technology(
                AnalyzerTechnology.PHOTOIONIZATION_DETECTOR,
                "Photoionization gas detector",
                "A point sensor ionizes compounds below a lamp-energy threshold to provide a non-specific VOC response.",
                _DETECTION_KIND,
                (AnalyzerAnalyteFamily.VOLATILE_ORGANIC_COMPOUND,),
                _GAS_PHASE,
                _POINT_APPROACHES,
                (
                    "Ionization potential, response factor, humidity, lamp condition, alarm basis, and coverage require verification.",
                ),
            ),
            _technology(
                AnalyzerTechnology.SEMICONDUCTOR_GAS_DETECTOR,
                "Semiconductor gas detector",
                "A point sensing material changes electrical behavior in response to a gas exposure.",
                _DETECTION_KIND,
                (
                    AnalyzerAnalyteFamily.COMBUSTIBLE_GAS,
                    AnalyzerAnalyteFamily.TOXIC_GAS,
                    AnalyzerAnalyteFamily.VOLATILE_ORGANIC_COMPOUND,
                ),
                _GAS_PHASE,
                _POINT_APPROACHES,
                (
                    "Selectivity, drift, humidity, temperature, poisoning, alarm basis, and coverage require verification.",
                ),
            ),
            _technology(
                AnalyzerTechnology.ULTRASONIC_GAS_LEAK_DETECTOR,
                "Ultrasonic gas-leak detector",
                "An acoustic detector screens for pressurized leak noise; it does not identify a gas or measure concentration.",
                _DETECTION_KIND,
                (AnalyzerAnalyteFamily.PHYSICAL_PROPERTY,),
                _GAS_PHASE,
                _ACOUSTIC_POINT_APPROACH,
                (
                    "Background noise, leak acoustics, pressure, obstruction, mapping, alarm basis, and coverage require verification.",
                ),
            ),
        ),
        key=lambda item: item.technology.value,
    )
)

ANALYZER_TECHNOLOGY_REGISTRY: Final = MappingProxyType(
    {item.technology: item for item in ANALYZER_TECHNOLOGY_CATALOGUE}
)


def _verification(
    verification_id: str,
    priority: AnalyzerVerificationPriority,
    description: str,
    acceptance_criteria: str,
    competency: str,
    evidence: tuple[str, ...],
    *,
    independent: bool = False,
) -> AnalyzerVerificationStep:
    return AnalyzerVerificationStep(
        verification_id=verification_id,
        priority=priority,
        description=description,
        acceptance_criteria=acceptance_criteria,
        required_competency=competency,
        independent=independent,
        evidence_required=evidence,
    )


ANALYZER_VERIFICATION_STEPS: Final = tuple(
    sorted(
        (
            _verification(
                "verify.measurement_basis",
                AnalyzerVerificationPriority.IMPORTANT,
                "Confirm the measurement objective, analyte identity, range, units, accuracy, detection limit, availability, and response requirement.",
                "A controlled duty specification resolves every performance input without inferred chemistry or units.",
                "Process analyzer engineer",
                ("Approved measurement duty", "Traceable process data"),
            ),
            _verification(
                "verify.process_matrix",
                AnalyzerVerificationPriority.IMPORTANT,
                "Verify process phase, matrix, temperature, pressure, variability, particulates, liquid carryover, wetness, corrosivity, fouling, and reactivity.",
                "Normal, startup, shutdown, upset, calibration, and maintenance cases are documented at the measurement point.",
                "Process engineer",
                ("Process composition envelope", "Process condition envelope"),
            ),
            _verification(
                "verify.sample_representativeness",
                AnalyzerVerificationPriority.IMPORTANT,
                "Verify the takeoff, probe, transport, conditioning, phase preservation, filtration, and sample disposition as one representative system.",
                "A reviewed sample-system design demonstrates that the measurand is neither lost nor biased and that every sample destination is controlled.",
                "Analyzer systems engineer",
                ("Sample-system drawing", "Representativeness review record"),
            ),
            _verification(
                "verify.interference",
                AnalyzerVerificationPriority.IMPORTANT,
                "Test or otherwise substantiate technology-specific cross-sensitivity, spectral, matrix, moisture, pressure, fouling, poisoning, and phase-change effects.",
                "Representative evidence covers the declared matrix and all material interferents with acceptance criteria tied to the measurement duty.",
                "Analytical specialist",
                ("Interference assessment", "Representative test evidence"),
            ),
            _verification(
                "verify.response_time",
                AnalyzerVerificationPriority.IMPORTANT,
                "Verify every serial response contributor and perform an end-to-end step-response test in the final arrangement.",
                "The witnessed end-to-end response, including process, sample, analyzer, filtering, communications, and logic, meets the approved requirement.",
                "Analyzer and control engineer",
                ("Contributor calculation", "End-to-end step-test record"),
            ),
            _verification(
                "verify.materials_phase",
                AnalyzerVerificationPriority.SAFETY_CRITICAL,
                "Confirm wetted-material compatibility and phase integrity through every process, conditioning, disposal, and maintenance case.",
                "Traceable compatibility evidence and phase calculations show no unacceptable corrosion, reaction, adsorption, dissolution, condensation, or target loss.",
                "Materials and process engineer",
                ("Compatibility record", "Phase-integrity review"),
                independent=True,
            ),
            _verification(
                "verify.utilities_environment",
                AnalyzerVerificationPriority.IMPORTANT,
                "Verify utilities, ambient limits, shelter, ingress protection, vibration, washdown, access, calibration, and maintenance arrangements.",
                "The complete installed system remains operable and maintainable for every declared environmental and utility case.",
                "Analyzer and electrical engineer",
                ("Utility schedule", "Installation environmental review"),
            ),
            _verification(
                "verify.hazardous_area",
                AnalyzerVerificationPriority.SAFETY_CRITICAL,
                "Complete hazardous-area classification and equipment-protection verification for the assembled installation.",
                "A competent electrical reviewer accepts the classification, equipment markings, temperature class, gas or dust group, wiring, glands, barriers, purge, and installation conditions.",
                "Hazardous-area electrical engineer",
                (
                    "Area-classification dossier",
                    "Equipment and installation certification evidence",
                ),
                independent=True,
            ),
            _verification(
                "verify.containment_disposal",
                AnalyzerVerificationPriority.SAFETY_CRITICAL,
                "Verify containment, isolation, leak control, ventilation, exposure controls, and the approved return, recovery, vent, flare, drain, or treatment path.",
                "A competent multidisciplinary review accepts all normal, calibration, blowdown, failure, and maintenance releases without an uncontrolled destination.",
                "Process safety engineer",
                (
                    "Containment review",
                    "Disposal and emissions acceptance",
                    "Exposure-control assessment",
                ),
                independent=True,
            ),
            _verification(
                "verify.gas_detection_function",
                AnalyzerVerificationPriority.SAFETY_CRITICAL,
                "Complete gas mapping, placement, coverage, alarm, response, voting, proof-test, bypass, independence, and functional-safety review where applicable.",
                "The project risk process accepts the detection objective and documented coverage; no screening result is used as a setpoint, placement, SIL, or risk-reduction claim.",
                "Functional safety and fire-and-gas engineer",
                (
                    "Approved gas-mapping study",
                    "Cause-and-effect and proof-test basis",
                    "Risk review record",
                ),
                independent=True,
            ),
            _verification(
                "verify.technology_evidence",
                AnalyzerVerificationPriority.IMPORTANT,
                "Obtain application-specific performance, materials, environmental, maintenance, and lifecycle evidence for each technology that remains under consideration.",
                "Controlled evidence demonstrates the project duty without converting this generic screen into a manufacturer or model selection.",
                "Process analyzer engineer",
                ("Technology evidence dossier", "Representative application evidence"),
            ),
            _verification(
                "verify.gc_basis",
                AnalyzerVerificationPriority.IMPORTANT,
                "Verify chromatographic phase handling, sample loop, carrier purity, calibration mixture, separation, coelution, detector response, cycle time, and sample disposition.",
                "Representative chromatograms and controlled calculations meet the approved component, range, precision, response, and disposal duty.",
                "Process chromatography specialist",
                (
                    "Representative chromatograms",
                    "Calibration and carrier specification",
                    "Cycle-time and sample-system record",
                ),
            ),
        ),
        key=lambda item: item.verification_id,
    )
)

_VERIFICATION_REGISTRY: Final = MappingProxyType(
    {item.verification_id: item for item in ANALYZER_VERIFICATION_STEPS}
)


def _rule(
    *,
    rule_id: str,
    status: AnalyzerRuleStatus,
    category: FindingCategory,
    weight: float,
    explanation: str,
    verification_ids: tuple[str, ...],
    missing_ids: tuple[str, ...] = (),
) -> AnalyzerRuleResult:
    awarded = (
        weight
        if status is AnalyzerRuleStatus.PASSED
        else weight * 0.5
        if status is AnalyzerRuleStatus.CAUTION
        else 0.0
    )
    return AnalyzerRuleResult(
        rule_id=rule_id,
        status=status,
        category=category,
        weight=weight,
        awarded_weight=awarded,
        explanation=explanation,
        missing_field_ids=missing_ids,
        verification_requirement_ids=verification_ids,
        reference_ids=(_REF_GOVERNANCE, _REF_SCENARIO),
    )


class AnalyzerApplicationAssistant:
    """Immutable-behavior, stateless analyzer application assistant."""

    __slots__ = ()

    @property
    def catalogue(self) -> tuple[AnalyzerTechnologyDefinition, ...]:
        return ANALYZER_TECHNOLOGY_CATALOGUE

    def assess(
        self,
        request: AnalyzerApplicationRequest,
    ) -> AnalyzerApplicationAssessment:
        """Return a deterministic safety-first generic technology screen."""

        try:
            validated = AnalyzerApplicationRequest.model_validate(
                request.model_dump(mode="python", round_trip=True, warnings="error")
            )
        except Exception as error:  # pragma: no cover - defensive boundary
            raise AnalyzerApplicationAssistantError(
                "request failed strict AnalyzerApplicationRequest revalidation"
            ) from error

        definitions = self._candidate_definitions(validated)
        return self._build_assessment(validated, definitions)

    @staticmethod
    def _candidate_definitions(
        request: AnalyzerApplicationRequest,
    ) -> tuple[AnalyzerTechnologyDefinition, ...]:
        if request.application_kind is AnalyzerApplicationKind.UNKNOWN:
            return ANALYZER_TECHNOLOGY_CATALOGUE
        return tuple(
            item
            for item in ANALYZER_TECHNOLOGY_CATALOGUE
            if request.application_kind in item.supported_application_kinds
        )

    def _build_assessment(
        self,
        request: AnalyzerApplicationRequest,
        definitions: tuple[AnalyzerTechnologyDefinition, ...],
    ) -> AnalyzerApplicationAssessment:
        missing_registry: dict[str, dict[str, object]] = {}
        missing_by_technology: dict[AnalyzerTechnology, set[str]] = {
            item.technology: set() for item in definitions
        }
        finding_by_technology: dict[AnalyzerTechnology, set[str]] = {
            item.technology: set() for item in definitions
        }

        def add_missing(
            field_id: str,
            reason: str,
            safety_critical: bool,
            technologies: tuple[AnalyzerTechnology, ...],
        ) -> None:
            record = missing_registry.setdefault(
                field_id,
                {
                    "reason": reason,
                    "safety_critical": safety_critical,
                    "technologies": set(),
                },
            )
            record["safety_critical"] = bool(record["safety_critical"]) or (
                safety_critical
            )
            technology_set = record["technologies"]
            assert isinstance(technology_set, set)
            technology_set.update(technologies)
            for technology in technologies:
                missing_by_technology[technology].add(field_id)

        findings = self._safety_findings(
            request,
            definitions,
            add_missing,
            finding_by_technology,
        )

        provisional: list[AnalyzerTechnologyScenario] = []
        for definition in definitions:
            technology = definition.technology
            rules = self._rules_for_technology(
                request,
                definition,
                add_missing,
                tuple(sorted(finding_by_technology[technology])),
                missing_by_technology[technology],
            )
            missing_ids = tuple(
                sorted(
                    {field_id for rule in rules for field_id in rule.missing_field_ids}
                )
            )
            # Safety unknowns are added before rules and must be visible in the
            # scenario safety rule.  This assertion guards construction drift.
            if missing_ids != tuple(sorted(missing_by_technology[technology])):
                raise AnalyzerApplicationAssistantError(
                    f"missing-information rule linkage drifted for {technology.value}"
                )
            statuses = {item.status for item in rules}
            blocked = AnalyzerRuleStatus.BLOCKED in statuses
            not_applicable = AnalyzerRuleStatus.NOT_APPLICABLE in statuses
            score = (
                0.0
                if blocked or not_applicable
                else sum(item.awarded_weight for item in rules)
            )
            disposition = (
                AnalyzerScenarioDisposition.BLOCKED
                if blocked
                else AnalyzerScenarioDisposition.NOT_APPLICABLE
                if not_applicable
                else AnalyzerScenarioDisposition.INSUFFICIENT_INFORMATION
                if AnalyzerRuleStatus.MISSING_INFORMATION in statuses
                else AnalyzerScenarioDisposition.CONDITIONAL
                if AnalyzerRuleStatus.FAILED in statuses or score < 65.0
                else AnalyzerScenarioDisposition.PLAUSIBLE
            )
            resolved = sum(
                item.weight
                for item in rules
                if item.status
                not in {
                    AnalyzerRuleStatus.MISSING_INFORMATION,
                    AnalyzerRuleStatus.NOT_APPLICABLE,
                }
            )
            confidence = min(90.0, resolved)
            if any(
                bool(missing_registry[item]["safety_critical"]) for item in missing_ids
            ):
                confidence = min(confidence, 19.0)
            elif missing_ids:
                confidence = min(confidence, 39.0)
            if blocked:
                confidence = min(confidence, 39.0)
            if any(
                item.rule_id in {"rule.interference", "rule.sample_integrity"}
                and item.status
                in {
                    AnalyzerRuleStatus.CAUTION,
                    AnalyzerRuleStatus.FAILED,
                }
                for item in rules
            ):
                confidence = min(confidence, 79.0)
            response_rule = next(
                item for item in rules if item.rule_id == "rule.response_time"
            )
            response_seconds = (
                None
                if response_rule.status is AnalyzerRuleStatus.MISSING_INFORMATION
                else self._preliminary_response_seconds(request)
            )
            verification_ids = tuple(
                sorted(
                    {
                        "verify.technology_evidence",
                        *(
                            identifier
                            for rule in rules
                            for identifier in rule.verification_requirement_ids
                        ),
                        *(
                            identifier
                            for finding in findings
                            if finding.finding_id in finding_by_technology[technology]
                            for identifier in finding.verification_requirement_ids
                        ),
                    }
                )
            )
            reasons = tuple(
                sorted(
                    {
                        item.explanation
                        for item in rules
                        if item.status
                        in {AnalyzerRuleStatus.PASSED, AnalyzerRuleStatus.CAUTION}
                    }
                )
            )
            provisional.append(
                AnalyzerTechnologyScenario(
                    scenario_id=f"scenario.{technology.value}",
                    technology=technology,
                    title=f"{definition.title} scenario",
                    disposition=disposition,
                    screening_order=(None if blocked or not_applicable else 1),
                    suitability_score=score,
                    confidence_score=confidence,
                    confidence_band=analyzer_confidence_band(confidence),
                    confidence_rationale=(
                        "Confidence reflects only the completeness of structured caller evidence and deterministic rule resolution; it is capped below full confidence and does not prove performance or fitness."
                    ),
                    rule_results=tuple(sorted(rules, key=lambda item: item.rule_id)),
                    estimated_total_response_time_seconds=response_seconds,
                    reasons=reasons,
                    limitations=(
                        "Generic technology screening is not a manufacturer or model selection.",
                        "Any summed response value is a preliminary declared serial budget, not a verified end-to-end T90 or compliance result.",
                        "Application-specific analytical, sample-system, materials, environmental, safety, and lifecycle evidence remains mandatory.",
                    ),
                    missing_information_ids=missing_ids,
                    finding_ids=tuple(sorted(finding_by_technology[technology])),
                    verification_requirement_ids=verification_ids,
                    reference_ids=(
                        _REF_CONFIDENCE,
                        _REF_CONTEXT,
                        _REF_ESCALATION,
                        _REF_GOVERNANCE,
                        _REF_SCENARIO,
                    ),
                )
            )

        ranked = sorted(
            (
                item
                for item in provisional
                if item.disposition
                not in {
                    AnalyzerScenarioDisposition.BLOCKED,
                    AnalyzerScenarioDisposition.NOT_APPLICABLE,
                }
            ),
            key=lambda item: (
                -item.suitability_score,
                -item.confidence_score,
                item.technology.value,
            ),
        )
        rank_by_technology = {
            item.technology: index for index, item in enumerate(ranked, start=1)
        }
        scenarios = tuple(
            sorted(
                (
                    item.model_copy(
                        update={
                            "screening_order": rank_by_technology.get(item.technology)
                        }
                    )
                    for item in provisional
                ),
                key=lambda item: (
                    item.screening_order is None,
                    item.screening_order or len(definitions) + 1,
                    item.technology.value,
                ),
            )
        )
        # model_copy does not validate updates; force strict graph revalidation.
        scenarios = tuple(
            AnalyzerTechnologyScenario.model_validate(
                item.model_dump(mode="python", round_trip=True, warnings="error")
            )
            for item in scenarios
        )

        missing_information = tuple(
            AnalyzerMissingInformation(
                field_id=field_id,
                reason=str(record["reason"]),
                safety_critical=bool(record["safety_critical"]),
                affected_technologies=tuple(
                    sorted(record["technologies"], key=lambda item: item.value)
                ),
            )
            for field_id, record in sorted(missing_registry.items())
        )
        used_verifications = {
            identifier
            for scenario in scenarios
            for identifier in scenario.verification_requirement_ids
        } | {
            identifier
            for finding in findings
            for identifier in finding.verification_requirement_ids
        }
        verification_steps = tuple(
            _VERIFICATION_REGISTRY[identifier]
            for identifier in sorted(used_verifications)
        )
        blocking = any(item.blocking for item in findings)
        plausible = any(
            item.disposition is AnalyzerScenarioDisposition.PLAUSIBLE
            for item in scenarios
        )
        safety_missing = any(item.safety_critical for item in missing_information)
        status = (
            CalculationStatus.BLOCKED
            if blocking
            else CalculationStatus.NOT_APPLICABLE
            if all(
                item.disposition is AnalyzerScenarioDisposition.NOT_APPLICABLE
                for item in scenarios
            )
            else CalculationStatus.INSUFFICIENT_INPUT
            if safety_missing or (not plausible and bool(missing_information))
            else CalculationStatus.FAILED
            if not plausible
            else CalculationStatus.COMPLETED_WITH_WARNINGS
        )
        payload: dict[str, object] = {
            "safety_findings": findings,
            "status": status,
            "model_version": ANALYZER_APPLICATION_MODEL_VERSION,
            "assistant_version": ANALYZER_ASSISTANT_VERSION,
            "ruleset_version": ANALYZER_RULESET_VERSION,
            "request": request,
            "missing_information": missing_information,
            "scenarios": scenarios,
            "verification_steps": verification_steps,
            "observations": tuple(sorted(self._observations(request, scenarios))),
            "limitations": tuple(
                sorted(
                    (
                        "No manufacturer, brand, model, product, technology winner, alarm setpoint, detector placement, detector coverage, SIL, or protection-layer decision is made.",
                        "No analytical performance, representative sampling, materials compatibility, hazardous-area approval, safety function, emissions acceptance, or standards conformity is established.",
                        "Current project requirements, representative evidence, and competent multidisciplinary review remain mandatory before design commitment.",
                    )
                )
            ),
            "vendor_neutral": True,
            "manufacturer_selection_performed": False,
            "manufacturer_declared_best": False,
            "model_selection_performed": False,
            "product_selected": False,
            "brand_ranked": False,
            "final_brand_selection": "user_decision_required",
            "standards_conformity_claimed": False,
            "hazardous_area_certification_performed": False,
            "safety_integrity_claimed": False,
            "sample_system_approved": False,
            "alarm_setpoint_selected": False,
            "detector_placement_or_coverage_approved": False,
            "final_design_approval_granted": False,
            "approved_for_project_use": False,
            "disclaimer": AnalyzerApplicationAssessment.model_fields[
                "disclaimer"
            ].default,
        }
        draft = AnalyzerApplicationAssessment.model_construct(
            assessment_fingerprint="0" * 64,
            **payload,
        )
        fingerprint_input = draft.model_dump(
            mode="json",
            round_trip=True,
            warnings="error",
            exclude={"assessment_fingerprint"},
        )
        payload["assessment_fingerprint"] = fingerprint_analyzer_payload(
            fingerprint_input
        )
        try:
            return AnalyzerApplicationAssessment.model_validate(payload)
        except Exception as error:  # pragma: no cover - construction guard
            raise AnalyzerApplicationAssistantError(
                "assistant generated an invalid analyzer assessment with "
                f"fingerprint {payload['assessment_fingerprint']}"
            ) from error

    @staticmethod
    def _observations(
        request: AnalyzerApplicationRequest,
        scenarios: tuple[AnalyzerTechnologyScenario, ...],
    ) -> tuple[str, ...]:
        plausible_count = sum(
            item.disposition is AnalyzerScenarioDisposition.PLAUSIBLE
            for item in scenarios
        )
        return (
            f"Application kind is {request.application_kind.value}; {len(scenarios)} generic technology scenarios were screened.",
            f"{plausible_count} scenarios are plausible on the supplied evidence; ties and alternatives remain visible.",
            "Safety findings are serialized before technology scenarios and take precedence over scores and confidence.",
        )

    @staticmethod
    def _preliminary_response_seconds(
        request: AnalyzerApplicationRequest,
    ) -> float | None:
        sample = request.sample_system
        if sample.response_time_budget_complete is not AnalyzerTriState.YES:
            return None
        contributors = sample.response_time_contributors
        if any(not item.confirmed for item in contributors):
            return None
        values = [
            canonical_analyzer_quantity_value(item.duration) for item in contributors
        ]
        if any(value is None for value in values):
            return None
        transport_declared = any(
            item.kind is AnalyzerResponseContributorKind.TRANSPORT_LINE
            for item in contributors
        )
        geometry = (
            canonical_analyzer_quantity_value(sample.sample_line_length),
            canonical_analyzer_quantity_value(sample.sample_line_internal_diameter),
            canonical_analyzer_quantity_value(sample.sample_flow_rate),
        )
        residence: float | None = None
        if (
            sample.approach in _EXTRACTIVE_APPROACHES
            and not transport_declared
            and not all(value is not None for value in geometry)
        ):
            return None
        if not transport_declared and all(value is not None for value in geometry):
            length, diameter, flow = geometry
            assert length is not None and diameter is not None and flow is not None
            residence = pi * diameter * diameter * length / (4.0 * flow)
        if not values and residence is None:
            return None
        return sum(value for value in values if value is not None) + (residence or 0.0)

    def _rules_for_technology(
        self,
        request: AnalyzerApplicationRequest,
        definition: AnalyzerTechnologyDefinition,
        add_missing,
        finding_ids: tuple[str, ...],
        registered_missing_ids: set[str],
    ) -> tuple[AnalyzerRuleResult, ...]:
        technology = definition.technology

        def missing(
            field_id: str,
            reason: str,
            *,
            safety: bool = False,
        ) -> str:
            add_missing(field_id, reason, safety, (technology,))
            return field_id

        rules: list[AnalyzerRuleResult] = []
        if request.application_kind is AnalyzerApplicationKind.UNKNOWN:
            rules.append(
                _rule(
                    rule_id="rule.application_kind",
                    status=AnalyzerRuleStatus.MISSING_INFORMATION,
                    category=FindingCategory.APPLICABILITY,
                    weight=5.0,
                    explanation="The analyzer application kind is unknown, so this technology cannot be treated as definitive.",
                    verification_ids=("verify.measurement_basis",),
                    missing_ids=(
                        missing(
                            "application_kind",
                            "Declare whether the duty is liquid analysis, process-gas analysis, gas chromatography, or gas detection/switching.",
                        ),
                    ),
                )
            )
        else:
            rules.append(
                _rule(
                    rule_id="rule.application_kind",
                    status=AnalyzerRuleStatus.PASSED,
                    category=FindingCategory.APPLICABILITY,
                    weight=5.0,
                    explanation="The generic technology belongs to the declared analyzer application branch.",
                    verification_ids=("verify.measurement_basis",),
                )
            )

        measurement = request.measurement
        measurement_missing: list[str] = []
        for field_id, is_missing, reason in (
            (
                "measurement.objectives",
                not measurement.objectives,
                "Declare the approved monitoring, control, quality, reporting, composition, safety-detection, or alarm objective.",
            ),
            (
                "measurement.minimum_availability_percent",
                measurement.minimum_availability_percent is None,
                "Declare the required analyzer-system availability basis.",
            ),
            (
                "measurement.continuous_output_required",
                measurement.continuous_output_required is AnalyzerTriState.UNKNOWN,
                "Declare whether continuous output is required.",
            ),
            (
                "measurement.local_indication_required",
                measurement.local_indication_required is AnalyzerTriState.UNKNOWN,
                "Declare whether local indication is required.",
            ),
            (
                "measurement.automatic_calibration_required",
                measurement.automatic_calibration_required is AnalyzerTriState.UNKNOWN,
                "Declare whether automatic calibration or validation is required.",
            ),
        ):
            if is_missing:
                measurement_missing.append(missing(field_id, reason))
        continuous_objective = bool(
            set(measurement.objectives)
            & {
                AnalyzerMeasurementObjective.CONTINUOUS_MONITORING,
                AnalyzerMeasurementObjective.PROCESS_CONTROL,
                AnalyzerMeasurementObjective.SAFETY_DETECTION,
                AnalyzerMeasurementObjective.ALARM_OR_SWITCH,
            }
        )
        measurement_failures: list[str] = []
        if request.sample_system.approach is AnalyzerSampleApproach.GRAB_SAMPLE and (
            measurement.continuous_output_required is AnalyzerTriState.YES
            or continuous_objective
        ):
            measurement_failures.append(
                "a grab-sample arrangement cannot satisfy the declared continuous, control, detection, or alarm duty"
            )
        if (
            measurement.automatic_calibration_required is AnalyzerTriState.YES
            and request.sample_system.calibration_introduction_defined
            is AnalyzerTriState.UNKNOWN
        ):
            measurement_missing.append(
                missing(
                    "sample_system.calibration_introduction_defined",
                    "Define representative calibration or validation introduction for the declared automatic-calibration duty.",
                )
            )
        elif (
            measurement.automatic_calibration_required is AnalyzerTriState.YES
            and request.sample_system.calibration_introduction_defined
            is AnalyzerTriState.NO
        ):
            measurement_failures.append(
                "automatic calibration is required but calibration introduction is explicitly absent"
            )
        rules.append(
            _rule(
                rule_id="rule.measurement_duty",
                status=(
                    AnalyzerRuleStatus.MISSING_INFORMATION
                    if measurement_missing
                    else AnalyzerRuleStatus.FAILED
                    if measurement_failures
                    else AnalyzerRuleStatus.PASSED
                ),
                category=FindingCategory.DATA_QUALITY,
                weight=5.0,
                explanation=(
                    "The measurement and lifecycle duty remains incomplete."
                    if measurement_missing
                    else "The declared measurement duty conflicts with the sample or calibration arrangement: "
                    + "; ".join(measurement_failures)
                    if measurement_failures
                    else "The structured objective, output mode, indication, calibration, and availability duty is declared for downstream verification."
                ),
                verification_ids=("verify.measurement_basis",),
                missing_ids=tuple(sorted(set(measurement_missing))),
            )
        )

        families = {item.family for item in request.measurement.analytes}
        if not families:
            rules.append(
                _rule(
                    rule_id="rule.analyte_duty",
                    status=AnalyzerRuleStatus.MISSING_INFORMATION,
                    category=FindingCategory.DATA_QUALITY,
                    weight=15.0,
                    explanation="No structured analyte duty was supplied; free text is not parsed to infer chemistry.",
                    verification_ids=("verify.measurement_basis",),
                    missing_ids=(
                        missing(
                            "measurement.analytes",
                            "Supply at least one structured analyte family, range, unit, and traceable source.",
                        ),
                    ),
                )
            )
        elif families.issubset(set(definition.supported_analyte_families)):
            rules.append(
                _rule(
                    rule_id="rule.analyte_duty",
                    status=AnalyzerRuleStatus.PASSED,
                    category=FindingCategory.APPLICABILITY,
                    weight=15.0,
                    explanation="Every structured analyte family is within this generic technology's screening taxonomy.",
                    verification_ids=(
                        "verify.measurement_basis",
                        "verify.technology_evidence",
                    ),
                )
            )
        else:
            rules.append(
                _rule(
                    rule_id="rule.analyte_duty",
                    status=AnalyzerRuleStatus.FAILED,
                    category=FindingCategory.APPLICABILITY,
                    weight=15.0,
                    explanation="This single-technology scenario does not cover every structured analyte family; analyte names were not reinterpreted and composite systems were not inferred.",
                    verification_ids=(
                        "verify.measurement_basis",
                        "verify.technology_evidence",
                    ),
                )
            )

        process_phase = request.process.sample_phase
        extractive_phase_boundary = (
            request.sample_system.approach in _EXTRACTIVE_APPROACHES
            or definition.extractive_sample_system_required
        )
        delivered_phase = (
            request.sample_system.delivered_sample_phase
            if extractive_phase_boundary
            else process_phase
        )
        phase_missing: list[str] = []
        if process_phase is AnalyzerSamplePhase.UNKNOWN:
            phase_missing.append(
                missing(
                    "process.sample_phase",
                    "Declare the process phase at the takeoff or measurement boundary.",
                )
            )
        if extractive_phase_boundary and delivered_phase is AnalyzerSamplePhase.UNKNOWN:
            phase_missing.append(
                missing(
                    "sample_system.delivered_sample_phase",
                    "Declare the phase delivered to the analyzer after all extraction and conditioning steps.",
                )
            )
        if (
            process_phase is not AnalyzerSamplePhase.UNKNOWN
            and delivered_phase is not AnalyzerSamplePhase.UNKNOWN
            and process_phase is not delivered_phase
            and request.sample_system.phase_conversion_basis_reference is None
        ):
            phase_missing.append(
                missing(
                    "sample_system.phase_conversion_basis_reference",
                    "Provide the traceable controlled vaporization, condensation, or other phase-conversion basis.",
                )
            )
        if phase_missing:
            rules.append(
                _rule(
                    rule_id="rule.sample_phase",
                    status=AnalyzerRuleStatus.MISSING_INFORMATION,
                    category=FindingCategory.DATA_QUALITY,
                    weight=10.0,
                    explanation="The process-to-analyzer phase boundary is incomplete; phase conversion or preservation is not inferred.",
                    verification_ids=(
                        "verify.process_matrix",
                        "verify.materials_phase",
                    ),
                    missing_ids=tuple(sorted(set(phase_missing))),
                )
            )
        elif delivered_phase in definition.supported_sample_phases:
            rules.append(
                _rule(
                    rule_id="rule.sample_phase",
                    status=AnalyzerRuleStatus.PASSED,
                    category=FindingCategory.APPLICABILITY,
                    weight=10.0,
                    explanation="The declared analyzer-inlet phase is represented in this generic technology scenario; any phase preservation or controlled conversion still requires verification.",
                    verification_ids=(
                        "verify.process_matrix",
                        "verify.materials_phase",
                    ),
                )
            )
        else:
            rules.append(
                _rule(
                    rule_id="rule.sample_phase",
                    status=AnalyzerRuleStatus.FAILED,
                    category=FindingCategory.APPLICABILITY,
                    weight=10.0,
                    explanation="The declared analyzer-inlet phase is not represented by this generic technology scenario.",
                    verification_ids=(
                        "verify.process_matrix",
                        "verify.materials_phase",
                    ),
                )
            )

        approach = request.sample_system.approach
        if approach is AnalyzerSampleApproach.UNKNOWN:
            rules.append(
                _rule(
                    rule_id="rule.sample_approach",
                    status=AnalyzerRuleStatus.MISSING_INFORMATION,
                    category=FindingCategory.DATA_QUALITY,
                    weight=10.0,
                    explanation="The sample or detection approach is unknown.",
                    verification_ids=("verify.sample_representativeness",),
                    missing_ids=(
                        missing(
                            "sample_system.approach",
                            "Declare the in-situ, extractive, fast-loop, grab, point-detector, open-path, or aspirated-detection arrangement.",
                        ),
                    ),
                )
            )
        elif approach in definition.supported_sample_approaches:
            rules.append(
                _rule(
                    rule_id="rule.sample_approach",
                    status=AnalyzerRuleStatus.PASSED,
                    category=FindingCategory.APPLICABILITY,
                    weight=10.0,
                    explanation="The declared sample or detection approach is represented in the technology taxonomy.",
                    verification_ids=("verify.sample_representativeness",),
                )
            )
        else:
            rules.append(
                _rule(
                    rule_id="rule.sample_approach",
                    status=AnalyzerRuleStatus.FAILED,
                    category=FindingCategory.APPLICABILITY,
                    weight=10.0,
                    explanation="The declared sample or detection approach is not represented by this generic technology scenario.",
                    verification_ids=("verify.sample_representativeness",),
                )
            )

        rules.append(self._sample_integrity_rule(request, definition, missing))
        rules.append(self._interference_rule(request, missing))
        rules.append(self._response_rule(request, definition, missing))
        rules.append(self._installation_rule(request, definition, missing))

        global_missing = tuple(
            sorted(
                field_id
                for field_id in registered_missing_ids
                if field_id.startswith("safety.")
                or field_id == "sample_system.materials_compatibility_confirmed"
            )
        )
        blocking_findings = any(
            identifier
            in {
                "finding.hazardous_area_missing_classification",
                "finding.hazardous_area_equipment_rejected",
                "finding.sample_containment_rejected",
                "finding.sample_disposal_rejected",
                "finding.exposure_control_rejected",
                "finding.materials_incompatible",
                "finding.pressure_control_rejected",
                "finding.temperature_control_rejected",
                "finding.detection_alarm_basis_rejected",
                "finding.detection_coverage_basis_rejected",
                "finding.detection_response_basis_rejected",
                "finding.detection_independence_rejected",
                "finding.detection_proof_test_rejected",
            }
            for identifier in finding_ids
        )
        safety_verifications = (
            "verify.gas_detection_function"
            if request.application_kind is AnalyzerApplicationKind.GAS_DETECTION
            else "verify.containment_disposal",
            "verify.hazardous_area",
        )
        if blocking_findings and global_missing:
            rules.append(
                _rule(
                    rule_id="rule.safety_information",
                    status=AnalyzerRuleStatus.MISSING_INFORMATION,
                    category=FindingCategory.SAFETY,
                    weight=5.0,
                    explanation="Safety-critical inputs remain unknown in addition to the blocking finding.",
                    verification_ids=safety_verifications,
                    missing_ids=global_missing,
                )
            )
        rules.append(
            _rule(
                rule_id="rule.safety_boundary",
                status=(
                    AnalyzerRuleStatus.BLOCKED
                    if blocking_findings
                    else AnalyzerRuleStatus.MISSING_INFORMATION
                    if global_missing
                    else AnalyzerRuleStatus.CAUTION
                    if finding_ids
                    else AnalyzerRuleStatus.PASSED
                ),
                category=FindingCategory.SAFETY,
                weight=10.0,
                explanation=(
                    "A blocking safety finding prevents this scenario."
                    if blocking_findings
                    else "Safety-critical inputs remain unknown and cannot be treated as no."
                    if global_missing
                    else "Declared hazards require the linked competent safety verification."
                    if finding_ids
                    else "The caller explicitly declared the screened hazard states as absent; project verification remains required."
                ),
                verification_ids=safety_verifications,
                missing_ids=(() if blocking_findings else global_missing),
            )
        )
        return tuple(rules)

    @staticmethod
    def _sample_integrity_rule(request, definition, missing) -> AnalyzerRuleResult:
        sample = request.sample_system
        process = request.process
        missing_ids: list[str] = []
        failures: list[str] = []
        cautions: list[str] = []
        extractive = (
            sample.approach in _EXTRACTIVE_APPROACHES
            or definition.extractive_sample_system_required
        )
        if process.stream_description is None:
            missing_ids.append(
                missing(
                    "process.stream_description",
                    "Provide a controlled process-stream description at the measurement or sample takeoff boundary.",
                )
            )
        if not process.matrix_components:
            missing_ids.append(
                missing(
                    "process.matrix_components",
                    "Provide the known process matrix and balance components without inferring chemistry from free text.",
                )
            )
        if extractive:
            for field_name, value, reason in (
                (
                    "sample_system.sample_probe_defined",
                    sample.sample_probe_defined,
                    "Define the representative takeoff, probe, isolation, and maintenance arrangement.",
                ),
                (
                    "sample_system.representative_sample_confirmed",
                    sample.representative_sample_confirmed,
                    "Confirm that takeoff, transport, conditioning, and cycle timing preserve a representative sample.",
                ),
                (
                    "sample_system.phase_preservation_confirmed",
                    sample.phase_preservation_confirmed,
                    "Confirm the phase delivered to the analyzer through every operating case.",
                ),
                (
                    "sample_system.materials_compatibility_confirmed",
                    sample.materials_compatibility_confirmed,
                    "Confirm wetted-material compatibility, adsorption, permeation, dissolution, and reaction risk.",
                ),
            ):
                if value is AnalyzerTriState.UNKNOWN:
                    missing_ids.append(
                        missing(field_name, reason, safety="materials" in field_name)
                    )
                elif value is AnalyzerTriState.NO:
                    failures.append(field_name)
            hazardous_sample = (
                request.safety.toxic_material is AnalyzerTriState.YES
                or request.safety.flammable_material is AnalyzerTriState.YES
            )
            if sample.disposition is AnalyzerSampleDisposition.UNKNOWN:
                missing_ids.append(
                    missing(
                        "sample_system.disposition",
                        "Declare the controlled return, recovery, vent, flare, drain, or treatment destination for every sample and calibration release.",
                        safety=hazardous_sample,
                    )
                )
            if sample.disposition_basis_reference is None:
                missing_ids.append(
                    missing(
                        "sample_system.disposition_basis_reference",
                        "Provide the traceable project basis for the declared sample destination.",
                        safety=hazardous_sample,
                    )
                )
            if sample.calibration_introduction_defined is AnalyzerTriState.UNKNOWN:
                missing_ids.append(
                    missing(
                        "sample_system.calibration_introduction_defined",
                        "Define representative and safely contained zero, span, validation, and calibration introduction.",
                        safety=hazardous_sample,
                    )
                )
            elif sample.calibration_introduction_defined is AnalyzerTriState.NO:
                failures.append("calibration introduction")
            if request.safety.high_pressure_sampling is AnalyzerTriState.YES:
                if sample.pressure_control_defined is AnalyzerTriState.UNKNOWN:
                    missing_ids.append(
                        missing(
                            "sample_system.pressure_control_defined",
                            "Define rated isolation, pressure reduction, relief, and low-pressure protection for every sampling case.",
                            safety=True,
                        )
                    )
                elif sample.pressure_control_defined is AnalyzerTriState.NO:
                    failures.append("high-pressure sample control")
            if request.safety.high_temperature_sampling is AnalyzerTriState.YES:
                if sample.temperature_control_defined is AnalyzerTriState.UNKNOWN:
                    missing_ids.append(
                        missing(
                            "sample_system.temperature_control_defined",
                            "Define rated temperature control, heat tracing or cooling, insulation, and phase protection.",
                            safety=True,
                        )
                    )
                elif sample.temperature_control_defined is AnalyzerTriState.NO:
                    failures.append("high-temperature sample control")
            if definition.cycle_based_measurement:
                for field_name, value, reason in (
                    (
                        "sample_system.gc_separation_and_coelution_verified",
                        sample.gc_separation_and_coelution_verified,
                        "Provide representative chromatograms and a reviewed separation/coelution basis for every required component and range.",
                    ),
                    (
                        "sample_system.gc_sample_loop_representative_confirmed",
                        sample.gc_sample_loop_representative_confirmed,
                        "Confirm representative sample-loop fill, purge, switching, pressure, phase, and timing.",
                    ),
                    (
                        "sample_system.gc_calibration_mixture_defined",
                        sample.gc_calibration_mixture_defined,
                        "Define traceable calibration mixtures, introduction, range coverage, stability, and acceptance criteria.",
                    ),
                    (
                        "sample_system.gc_carrier_gas_quality_confirmed",
                        sample.gc_carrier_gas_quality_confirmed,
                        "Confirm carrier-gas identity, purity, pressure, continuity, changeover, and contamination controls.",
                    ),
                ):
                    if value is AnalyzerTriState.UNKNOWN:
                        missing_ids.append(missing(field_name, reason))
                    elif value is AnalyzerTriState.NO:
                        failures.append(field_name)
            if (
                sample.disposition is AnalyzerSampleDisposition.RETURN_TO_PROCESS
                and sample.return_compatibility_confirmed is AnalyzerTriState.UNKNOWN
            ):
                missing_ids.append(
                    missing(
                        "sample_system.return_compatibility_confirmed",
                        "Confirm that every returned process and calibration stream is compatible with the return destination.",
                        safety=hazardous_sample,
                    )
                )
        if process.composition_variability is AnalyzerConditionSeverity.UNKNOWN:
            missing_ids.append(
                missing(
                    "process.composition_variability",
                    "Declare matrix and composition variability across normal, startup, shutdown, upset, calibration, and maintenance cases.",
                )
            )
        elif process.composition_variability in _HARSH_CONDITIONS:
            cautions.append(
                "composition range, calibration model, cross-sensitivity, and representative validation"
            )
        if process.particulate_loading is AnalyzerConditionSeverity.UNKNOWN:
            missing_ids.append(
                missing(
                    "process.particulate_loading",
                    "Declare particulate loading; unknown loading cannot be treated as clean service.",
                )
            )
        elif process.particulate_loading in _HARSH_CONDITIONS:
            cautions.append(
                "particulate fouling, filter bias, pressure drop, and maintenance"
            )
            if sample.filtration_defined is AnalyzerTriState.UNKNOWN:
                missing_ids.append(
                    missing(
                        "sample_system.filtration_defined",
                        "Define and verify filtration without assuming the filter preserves the analyte or particle distribution.",
                    )
                )
            elif sample.filtration_defined is AnalyzerTriState.NO:
                failures.append("particulate protection")
        if process.fouling_tendency is AnalyzerConditionSeverity.UNKNOWN:
            missing_ids.append(
                missing(
                    "process.fouling_tendency",
                    "Declare fouling, coating, optical attenuation, poisoning, cleaning, and maintenance tendencies.",
                )
            )
        elif process.fouling_tendency in _HARSH_CONDITIONS:
            cautions.append(
                "fouling, coating, drift, cleaning interval, and maintenance exposure"
            )
        wet_conditions = (
            process.wet_sample,
            process.liquid_droplets,
        )
        if any(value is AnalyzerConditionSeverity.UNKNOWN for value in wet_conditions):
            missing_ids.append(
                missing(
                    "process.wet_or_condensing_state",
                    "Declare wetness, liquid carryover, dew-point, and phase-change risks.",
                )
            )
        elif any(value in _HARSH_CONDITIONS for value in wet_conditions):
            cautions.append(
                "dew-point, condensation, soluble-target loss, and controlled condensate handling"
            )
            if sample.phase_preservation_confirmed is AnalyzerTriState.UNKNOWN:
                missing_ids.append(
                    missing(
                        "sample_system.phase_preservation_confirmed",
                        "Confirm phase preservation and target retention before heating, cooling, demisting, or knockout.",
                    )
                )
            elif sample.phase_preservation_confirmed is AnalyzerTriState.NO:
                failures.append("wet-sample phase preservation")
        if process.corrosivity is AnalyzerConditionSeverity.UNKNOWN:
            missing_ids.append(
                missing(
                    "process.corrosivity",
                    "Declare corrosivity; unknown corrosivity requires materials review.",
                    safety=True,
                )
            )
        elif process.corrosivity in _HARSH_CONDITIONS:
            cautions.append(
                "corrosion, material compatibility, containment, and disposal"
            )
        if process.reactivity is AnalyzerConditionSeverity.UNKNOWN:
            missing_ids.append(
                missing(
                    "process.reactivity",
                    "Declare reactivity through sampling, calibration, disposal, and maintenance cases.",
                    safety=True,
                )
            )
        elif process.reactivity in _HARSH_CONDITIONS:
            cautions.append(
                "reaction, adsorption, target loss, and incompatible conditioning"
            )
        status = (
            AnalyzerRuleStatus.MISSING_INFORMATION
            if missing_ids
            else AnalyzerRuleStatus.FAILED
            if failures
            else AnalyzerRuleStatus.CAUTION
            if cautions
            else AnalyzerRuleStatus.PASSED
        )
        explanation = (
            "Sample integrity remains unresolved: "
            + "; ".join(sorted(set(failures + cautions)))
            + "."
            if failures or cautions
            else "No declared particulate, wet, corrosive, or reactive condition defeats this preliminary sample-integrity screen."
        )
        return _rule(
            rule_id="rule.sample_integrity",
            status=status,
            category=FindingCategory.DATA_QUALITY,
            weight=15.0,
            explanation=explanation,
            verification_ids=(
                "verify.materials_phase",
                "verify.sample_representativeness",
            ),
            missing_ids=tuple(sorted(set(missing_ids))),
        )

    @staticmethod
    def _interference_rule(request, missing) -> AnalyzerRuleResult:
        process = request.process
        if process.known_interferences_assessed is not AnalyzerTriState.YES:
            return _rule(
                rule_id="rule.interference",
                status=AnalyzerRuleStatus.MISSING_INFORMATION,
                category=FindingCategory.DATA_QUALITY,
                weight=10.0,
                explanation="Technology-specific interference and matrix effects have not been affirmatively assessed.",
                verification_ids=("verify.interference",),
                missing_ids=(
                    missing(
                        "process.known_interferences_assessed",
                        "Complete and affirm a structured interference assessment without inferring chemistry from free text.",
                    ),
                ),
            )
        if process.known_interferences:
            unresolved = any(
                item.severity in _HARSH_CONDITIONS and item.mitigation_basis is None
                for item in process.known_interferences
            )
            return _rule(
                rule_id="rule.interference",
                status=AnalyzerRuleStatus.CAUTION,
                category=FindingCategory.DATA_QUALITY,
                weight=10.0,
                explanation=(
                    "Known interference mechanisms require representative technology-specific verification; at least one material interference lacks a mitigation basis."
                    if unresolved
                    else "Known interference mechanisms and their caller-supplied mitigation bases require representative technology-specific verification."
                ),
                verification_ids=("verify.interference",),
            )
        return _rule(
            rule_id="rule.interference",
            status=AnalyzerRuleStatus.PASSED,
            category=FindingCategory.DATA_QUALITY,
            weight=10.0,
            explanation="The caller reports a completed interference assessment with no structured known interferences; representative verification remains required.",
            verification_ids=("verify.interference",),
        )

    def _response_rule(self, request, definition, missing) -> AnalyzerRuleResult:
        sample = request.sample_system
        contributors = sample.response_time_contributors
        missing_ids: list[str] = []
        extractive = (
            sample.approach in _EXTRACTIVE_APPROACHES
            or definition.extractive_sample_system_required
        )
        geometry_present = (
            sample.sample_line_length is not None,
            sample.sample_line_internal_diameter is not None,
            sample.sample_flow_rate is not None,
        )
        required = canonical_analyzer_quantity_value(
            request.measurement.maximum_total_response_time
        )
        response_basis_declared = (
            bool(contributors)
            or any(geometry_present)
            or required is not None
            or definition.cycle_based_measurement
        )
        if (
            response_basis_declared
            and sample.response_time_budget_complete is not AnalyzerTriState.YES
        ):
            missing_ids.append(
                missing(
                    "sample_system.response_time_budget_complete",
                    "Confirm that every applicable serial response contributor is identified, quantified, traceable, and included in the preliminary budget.",
                )
            )
        has_transport = any(
            item.kind is AnalyzerResponseContributorKind.TRANSPORT_LINE
            for item in contributors
        )
        if extractive and not has_transport and not all(geometry_present):
            missing_ids.append(
                missing(
                    "sample_system.transport_response_basis",
                    "Provide a confirmed transport contributor or complete positive line length, internal diameter, and actual line-condition flow.",
                )
            )
        if any(not item.confirmed for item in contributors):
            missing_ids.append(
                missing(
                    "sample_system.response_time_contributor_confirmation",
                    "Confirm every declared serial response-time contributor and its source.",
                )
            )
        if definition.cycle_based_measurement and not any(
            item.kind is AnalyzerResponseContributorKind.ANALYSIS_CYCLE
            for item in contributors
        ):
            missing_ids.append(
                missing(
                    "sample_system.analysis_cycle_time",
                    "Provide a confirmed analytical-cycle contributor for the cycle-based technology.",
                )
            )
        response = self._preliminary_response_seconds(request)
        verification_ids = (
            ("verify.gc_basis", "verify.response_time")
            if definition.cycle_based_measurement
            else ("verify.response_time",)
        )
        if (
            required is not None
            and response is None
            and sample.response_time_budget_complete is AnalyzerTriState.YES
        ):
            missing_ids.append(
                missing(
                    "sample_system.complete_response_budget",
                    "Quantify all applicable serial contributors before comparing the preliminary budget with the response requirement.",
                )
            )
        if missing_ids:
            return _rule(
                rule_id="rule.response_time",
                status=AnalyzerRuleStatus.MISSING_INFORMATION,
                category=FindingCategory.DATA_QUALITY,
                weight=10.0,
                explanation="The end-to-end response basis is incomplete; no missing duration is fabricated.",
                verification_ids=verification_ids,
                missing_ids=tuple(sorted(set(missing_ids))),
            )
        if response is not None and required is not None and response > required:
            return _rule(
                rule_id="rule.response_time",
                status=AnalyzerRuleStatus.FAILED,
                category=FindingCategory.APPLICABILITY,
                weight=10.0,
                explanation="The preliminary declared serial response budget exceeds the caller's maximum; an end-to-end test is still required.",
                verification_ids=verification_ids,
            )
        return _rule(
            rule_id="rule.response_time",
            status=(
                AnalyzerRuleStatus.PASSED
                if response is not None
                else AnalyzerRuleStatus.CAUTION
            ),
            category=FindingCategory.DATA_QUALITY,
            weight=10.0,
            explanation=(
                "The preliminary declared serial response budget does not exceed the caller's maximum; this is not verified T90 compliance."
                if response is not None and required is not None
                else "A preliminary response budget is available, but only an end-to-end step test can establish installed response."
                if response is not None
                else "No response requirement or complete budget was declared; response remains a mandatory verification topic."
            ),
            verification_ids=verification_ids,
        )

    @staticmethod
    def _installation_rule(request, definition, missing) -> AnalyzerRuleResult:
        installation = request.installation
        missing_ids: list[str] = []
        failures: list[str] = []
        required = set(definition.required_utilities)
        available = set(installation.available_utilities)
        if not installation.environment_conditions:
            missing_ids.append(
                missing(
                    "installation.environment_conditions",
                    "Declare ambient, indoor/outdoor, weather, washdown, vibration, dust, corrosive-atmosphere, and ingress conditions for the complete installation.",
                )
            )
        if required:
            if installation.utility_availability_confirmed is AnalyzerTriState.UNKNOWN:
                missing_ids.append(
                    missing(
                        "installation.utility_availability_confirmed",
                        "Confirm capacity, quality, reliability, isolation, and restoration for all required utilities.",
                    )
                )
            elif installation.utility_availability_confirmed is AnalyzerTriState.NO:
                failures.append("required utility availability")
            elif not required.issubset(available):
                failures.append("required utility list")
        for field_name, state, reason in (
            (
                "installation.maintenance_access_confirmed",
                installation.maintenance_access_confirmed,
                "Confirm safe maintenance and replacement access.",
            ),
            (
                "installation.calibration_access_confirmed",
                installation.calibration_access_confirmed,
                "Confirm safe calibration and validation access.",
            ),
        ):
            if state is AnalyzerTriState.UNKNOWN:
                missing_ids.append(missing(field_name, reason))
            elif state is AnalyzerTriState.NO:
                failures.append(field_name)
        harsh_environment = any(
            item.value != "indoor_controlled"
            for item in installation.environment_conditions
        )
        if harsh_environment:
            if (
                installation.shelter_or_enclosure_basis_defined
                is AnalyzerTriState.UNKNOWN
            ):
                missing_ids.append(
                    missing(
                        "installation.shelter_or_enclosure_basis_defined",
                        "Define environmental protection for the declared installation conditions.",
                    )
                )
            elif installation.shelter_or_enclosure_basis_defined is AnalyzerTriState.NO:
                failures.append("environmental protection")
        status = (
            AnalyzerRuleStatus.MISSING_INFORMATION
            if missing_ids
            else AnalyzerRuleStatus.FAILED
            if failures
            else AnalyzerRuleStatus.CAUTION
            if harsh_environment
            else AnalyzerRuleStatus.PASSED
        )
        return _rule(
            rule_id="rule.utilities_environment",
            status=status,
            category=FindingCategory.APPLICABILITY,
            weight=10.0,
            explanation=(
                "Installation evidence remains incomplete or unsuitable: "
                + "; ".join(sorted(failures))
                if failures
                else "Declared utilities, access, and environment require the linked installed-system verification."
            ),
            verification_ids=("verify.utilities_environment",),
            missing_ids=tuple(sorted(set(missing_ids))),
        )

    @staticmethod
    def _safety_findings(
        request,
        definitions,
        add_missing,
        finding_by_technology,
    ) -> tuple[AnalyzerSafetyFinding, ...]:
        all_technologies = tuple(item.technology for item in definitions)
        extractive_technologies = tuple(
            item.technology
            for item in definitions
            if item.extractive_sample_system_required
            or request.sample_system.approach in _EXTRACTIVE_APPROACHES
        )
        findings: list[AnalyzerSafetyFinding] = []

        def add_finding(
            finding_id: str,
            severity: FindingSeverity,
            title: str,
            message: str,
            blocking: bool,
            action: str,
            verification_ids: tuple[str, ...],
            technologies: tuple[AnalyzerTechnology, ...],
        ) -> None:
            if not technologies:
                return
            finding = AnalyzerSafetyFinding(
                finding_id=finding_id,
                severity=severity,
                title=title,
                message=message,
                blocking=blocking,
                required_action=action,
                verification_requirement_ids=verification_ids,
                affected_technologies=technologies,
                reference_ids=(_REF_CONTEXT, _REF_ESCALATION, _REF_GOVERNANCE),
            )
            findings.append(finding)
            for technology in technologies:
                finding_by_technology[technology].add(finding_id)

        safety = request.safety
        for field_id, state, reason in (
            (
                "safety.hazardous_area",
                safety.hazardous_area,
                "Declare whether the installation is in or can expose equipment to a hazardous area.",
            ),
            (
                "safety.toxic_material",
                safety.toxic_material,
                "Declare toxic-material hazards for operation, calibration, release, and maintenance cases.",
            ),
            (
                "safety.flammable_material",
                safety.flammable_material,
                "Declare flammable-material hazards for operation, calibration, release, and maintenance cases.",
            ),
            (
                "safety.oxygen_deficiency_or_enrichment",
                safety.oxygen_deficiency_or_enrichment,
                "Declare oxygen-deficiency or enrichment hazards for operation, release, calibration, and maintenance cases.",
            ),
            (
                "safety.high_pressure_sampling",
                safety.high_pressure_sampling,
                "Declare high-pressure sampling hazards and pressure-reduction cases.",
            ),
            (
                "safety.high_temperature_sampling",
                safety.high_temperature_sampling,
                "Declare high-temperature sampling hazards and cooling cases.",
            ),
        ):
            if state is AnalyzerTriState.UNKNOWN:
                add_missing(field_id, reason, True, all_technologies)

        if safety.hazardous_area is AnalyzerTriState.YES:
            if safety.hazardous_area_classification is None:
                add_missing(
                    "safety.hazardous_area_classification",
                    "Provide the project hazardous-area classification before screening energized equipment.",
                    True,
                    all_technologies,
                )
                add_finding(
                    "finding.hazardous_area_missing_classification",
                    FindingSeverity.ERROR,
                    "Hazardous-area classification missing",
                    "Hazardous-area service is declared, but the classification required to screen the assembled installation is absent.",
                    True,
                    "Stop equipment application and complete the classification and protection review.",
                    ("verify.hazardous_area",),
                    all_technologies,
                )
            elif (
                safety.hazardous_area_equipment_certification_confirmed
                is AnalyzerTriState.NO
            ):
                add_finding(
                    "finding.hazardous_area_equipment_rejected",
                    FindingSeverity.ERROR,
                    "Hazardous-area equipment evidence rejected",
                    "The caller explicitly rejected the equipment-certification basis for a declared hazardous area.",
                    True,
                    "Do not use the affected equipment until a competent hazardous-area review accepts the complete installation.",
                    ("verify.hazardous_area",),
                    all_technologies,
                )
            elif (
                safety.hazardous_area_equipment_certification_confirmed
                is AnalyzerTriState.UNKNOWN
            ):
                add_missing(
                    "safety.hazardous_area_equipment_certification_confirmed",
                    "Confirm equipment and assembled-installation certification evidence against the declared classification.",
                    True,
                    all_technologies,
                )
            else:
                add_finding(
                    "finding.hazardous_area_review",
                    FindingSeverity.WARNING,
                    "Hazardous-area installation review mandatory",
                    "Caller confirmation is screening evidence only and does not certify the assembled installation.",
                    False,
                    "Complete and retain the competent hazardous-area review before use.",
                    ("verify.hazardous_area",),
                    all_technologies,
                )

        hazardous_extractive = bool(extractive_technologies) and (
            safety.toxic_material is AnalyzerTriState.YES
            or safety.flammable_material is AnalyzerTriState.YES
            or safety.oxygen_deficiency_or_enrichment is AnalyzerTriState.YES
            or safety.high_pressure_sampling is AnalyzerTriState.YES
            or safety.high_temperature_sampling is AnalyzerTriState.YES
            or request.process.corrosivity in _HARSH_CONDITIONS
            or request.process.reactivity in _HARSH_CONDITIONS
        )
        if hazardous_extractive:
            for field_id, state, title, reason, rejected_id in (
                (
                    "safety.sample_containment_confirmed",
                    safety.sample_containment_confirmed,
                    "Sample containment",
                    "Confirm containment, isolation, leak control, ventilation, and maintenance-release controls.",
                    "finding.sample_containment_rejected",
                ),
                (
                    "safety.safe_vent_or_disposal_confirmed",
                    safety.safe_vent_or_disposal_confirmed,
                    "Sample return or disposal",
                    "Confirm an approved return, recovery, vent, flare, drain, or treatment path for every release case.",
                    "finding.sample_disposal_rejected",
                ),
            ):
                if state is AnalyzerTriState.UNKNOWN:
                    add_missing(field_id, reason, True, extractive_technologies)
                elif state is AnalyzerTriState.NO:
                    add_finding(
                        rejected_id,
                        FindingSeverity.CRITICAL,
                        f"{title} explicitly rejected",
                        f"The declared hazardous extractive service has no accepted {title.lower()} basis.",
                        True,
                        "Stop the affected extractive scenario and establish a competent, documented safe arrangement.",
                        ("verify.containment_disposal",),
                        extractive_technologies,
                    )
            if safety.toxic_material is AnalyzerTriState.YES:
                if safety.exposure_control_defined is AnalyzerTriState.UNKNOWN:
                    add_missing(
                        "safety.exposure_control_defined",
                        "Define exposure, ventilation, PPE, decontamination, and maintenance controls for toxic service.",
                        True,
                        extractive_technologies,
                    )
                elif safety.exposure_control_defined is AnalyzerTriState.NO:
                    add_finding(
                        "finding.exposure_control_rejected",
                        FindingSeverity.CRITICAL,
                        "Toxic exposure controls rejected",
                        "The caller explicitly reports no accepted exposure-control basis for toxic extractive service.",
                        True,
                        "Stop the affected scenario and complete a competent occupational and process-safety assessment.",
                        ("verify.containment_disposal",),
                        extractive_technologies,
                    )
            add_finding(
                "finding.hazardous_sample_handling",
                FindingSeverity.WARNING,
                "Hazardous sample handling requires review",
                "Even confirmed screening inputs do not approve containment, disposal, emissions, stored energy, temperature, exposure, calibration, or maintenance releases.",
                False,
                "Complete the linked multidisciplinary containment and disposal verification.",
                ("verify.containment_disposal",),
                extractive_technologies,
            )

        corrosive_or_reactive = request.process.corrosivity in _HARSH_CONDITIONS or (
            request.process.reactivity in _HARSH_CONDITIONS
        )
        if corrosive_or_reactive:
            if (
                request.sample_system.materials_compatibility_confirmed
                is AnalyzerTriState.NO
            ):
                add_finding(
                    "finding.materials_incompatible",
                    FindingSeverity.ERROR,
                    "Wetted materials explicitly incompatible",
                    "The caller reports incompatible wetted materials for corrosive or reactive service.",
                    True,
                    "Stop affected contact and extractive scenarios until traceable materials compatibility is established.",
                    ("verify.materials_phase",),
                    all_technologies,
                )
            elif (
                request.sample_system.materials_compatibility_confirmed
                is AnalyzerTriState.UNKNOWN
            ):
                add_missing(
                    "sample_system.materials_compatibility_confirmed",
                    "Confirm wetted-material, seal, window, coating, calibration, and disposal compatibility.",
                    True,
                    all_technologies,
                )

        if safety.high_pressure_sampling is AnalyzerTriState.YES:
            if request.sample_system.pressure_control_defined is AnalyzerTriState.NO:
                add_finding(
                    "finding.pressure_control_rejected",
                    FindingSeverity.CRITICAL,
                    "High-pressure sample control rejected",
                    "High-pressure sampling is declared while pressure control is explicitly absent.",
                    True,
                    "Stop the affected sampling scenario and define rated isolation, reduction, relief, and downstream protection.",
                    ("verify.containment_disposal", "verify.materials_phase"),
                    extractive_technologies or all_technologies,
                )
            add_finding(
                "finding.high_pressure_sampling",
                FindingSeverity.WARNING,
                "High-pressure sampling review mandatory",
                "Pressure reduction can introduce stored-energy, cooling, condensation, phase, and release hazards.",
                False,
                "Verify rated isolation, pressure reduction, relief, phase behavior, containment, and maintenance controls.",
                ("verify.containment_disposal", "verify.materials_phase"),
                all_technologies,
            )
        if safety.high_temperature_sampling is AnalyzerTriState.YES:
            if request.sample_system.temperature_control_defined is AnalyzerTriState.NO:
                add_finding(
                    "finding.temperature_control_rejected",
                    FindingSeverity.CRITICAL,
                    "High-temperature sample control rejected",
                    "High-temperature sampling is declared while temperature control is explicitly absent.",
                    True,
                    "Stop the affected sampling scenario and define rated conditioning, insulation, isolation, and phase protection.",
                    ("verify.containment_disposal", "verify.materials_phase"),
                    extractive_technologies or all_technologies,
                )
            add_finding(
                "finding.high_temperature_sampling",
                FindingSeverity.WARNING,
                "High-temperature sampling review mandatory",
                "Cooling or heat tracing can alter phase, reaction, adsorption, condensation, and personnel exposure.",
                False,
                "Verify temperature rating, conditioning, phase integrity, insulation, isolation, and maintenance controls.",
                ("verify.containment_disposal", "verify.materials_phase"),
                all_technologies,
            )
        if safety.oxygen_deficiency_or_enrichment is AnalyzerTriState.YES:
            add_finding(
                "finding.oxygen_hazard_review",
                FindingSeverity.WARNING,
                "Oxygen hazard review mandatory",
                "Oxygen deficiency or enrichment can affect personnel exposure, combustion behavior, calibration, ventilation, and release cases.",
                False,
                "Complete the competent oxygen-hazard, ventilation, containment, calibration, and maintenance review.",
                ("verify.containment_disposal", "verify.hazardous_area"),
                all_technologies,
            )

        if request.application_kind is AnalyzerApplicationKind.GAS_DETECTION:
            if safety.gas_detection_safety_function is AnalyzerTriState.UNKNOWN:
                add_missing(
                    "safety.gas_detection_safety_function",
                    "Declare whether the detector participates in a safety, shutdown, evacuation, or other protective function.",
                    True,
                    all_technologies,
                )
            elif (
                safety.gas_detection_safety_function is AnalyzerTriState.NO
                and AnalyzerMeasurementObjective.SAFETY_DETECTION
                in request.measurement.objectives
            ):
                add_finding(
                    "finding.detection_function_rejected",
                    FindingSeverity.CRITICAL,
                    "Safety-detection function rejected",
                    "The declared safety-detection objective conflicts with an explicit declaration that no gas-detection safety function exists.",
                    True,
                    "Stop reliance on the affected detection scenarios and reconcile the approved detection objective and protective-function basis.",
                    ("verify.gas_detection_function",),
                    all_technologies,
                )
            for field_id, state, reason, rejected_id, title in (
                (
                    "safety.alarm_basis_defined",
                    safety.alarm_basis_defined,
                    "Provide the approved detection and alarm objective; this assistant does not determine a setpoint.",
                    "finding.detection_alarm_basis_rejected",
                    "Detection alarm basis rejected",
                ),
                (
                    "safety.detector_coverage_basis_defined",
                    safety.detector_coverage_basis_defined,
                    "Provide the gas-mapping, placement, and coverage basis; this assistant does not place detectors.",
                    "finding.detection_coverage_basis_rejected",
                    "Detection coverage basis rejected",
                ),
                (
                    "safety.detector_response_basis_defined",
                    safety.detector_response_basis_defined,
                    "Provide the complete detector, alarm, communication, and action response basis.",
                    "finding.detection_response_basis_rejected",
                    "Detection response basis rejected",
                ),
            ):
                if state is AnalyzerTriState.UNKNOWN:
                    add_missing(field_id, reason, True, all_technologies)
                elif state is AnalyzerTriState.NO:
                    add_finding(
                        rejected_id,
                        FindingSeverity.CRITICAL,
                        title,
                        "A gas-detection or switch duty lacks an accepted mandatory alarm, coverage, or response basis.",
                        True,
                        "Stop reliance on the affected detection scenario and complete the competent fire-and-gas review.",
                        ("verify.gas_detection_function",),
                        all_technologies,
                    )
            if safety.gas_detection_safety_function is AnalyzerTriState.YES:
                for field_id, state, reason, rejected_id, title in (
                    (
                        "safety.independence_requirement_defined",
                        safety.independence_requirement_defined,
                        "Define independence from initiating causes, control functions, utilities, communications, and other protection layers.",
                        "finding.detection_independence_rejected",
                        "Detection independence rejected",
                    ),
                    (
                        "safety.proof_test_and_bypass_basis_defined",
                        safety.proof_test_and_bypass_basis_defined,
                        "Define calibration, proof-test, bypass, impairment, restoration, and audit controls.",
                        "finding.detection_proof_test_rejected",
                        "Detection proof-test basis rejected",
                    ),
                ):
                    if state is AnalyzerTriState.UNKNOWN:
                        add_missing(field_id, reason, True, all_technologies)
                    elif state is AnalyzerTriState.NO:
                        add_finding(
                            rejected_id,
                            FindingSeverity.CRITICAL,
                            title,
                            "A declared gas-detection safety function lacks an accepted mandatory governance basis.",
                            True,
                            "Stop reliance on the function and complete the competent functional-safety and fire-and-gas review.",
                            ("verify.gas_detection_function",),
                            all_technologies,
                        )
            add_finding(
                "finding.gas_detection_scope",
                FindingSeverity.WARNING,
                "Gas-detection engineering remains outside generic screening",
                "No technology scenario establishes alarm setpoint, detector placement, coverage, voting, SIL, independence, proof-test interval, or risk reduction.",
                False,
                "Complete the linked gas mapping, alarm, response, proof-test, hazardous-area, and functional-safety review.",
                ("verify.gas_detection_function",),
                all_technologies,
            )
        elif safety.gas_detection_safety_function is AnalyzerTriState.YES:
            add_finding(
                "finding.detection_function_outside_scope",
                FindingSeverity.CRITICAL,
                "Gas-detection safety function outside application scope",
                "A gas-detection safety function was declared for an application branch that is not gas detection.",
                True,
                "Stop reliance on the affected scenarios and submit the duty through the gas-detection application branch with the complete alarm, coverage, response, independence, and proof-test basis.",
                ("verify.gas_detection_function",),
                all_technologies,
            )

        return tuple(sorted(findings, key=lambda item: item.finding_id))


DEFAULT_ANALYZER_APPLICATION_ASSISTANT: Final = AnalyzerApplicationAssistant()


def assess_analyzer_application(
    request: AnalyzerApplicationRequest,
) -> AnalyzerApplicationAssessment:
    """Assess one strict request with the immutable default assistant."""

    return DEFAULT_ANALYZER_APPLICATION_ASSISTANT.assess(request)


__all__ = [
    "ANALYZER_ASSISTANT_VERSION",
    "ANALYZER_RULESET_VERSION",
    "ANALYZER_TECHNOLOGY_CATALOGUE",
    "ANALYZER_TECHNOLOGY_REGISTRY",
    "ANALYZER_TECHNOLOGY_TAXONOMY_VERSION",
    "ANALYZER_VERIFICATION_STEPS",
    "DEFAULT_ANALYZER_APPLICATION_ASSISTANT",
    "AnalyzerApplicationAssistant",
    "AnalyzerApplicationAssistantError",
    "assess_analyzer_application",
]

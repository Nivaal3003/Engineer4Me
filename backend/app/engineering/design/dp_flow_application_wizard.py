"""Deterministic vendor-neutral DP primary-element screening wizard.

The wizard compares technology and owned variants on disclosed engineering
evidence. It never ranks manufacturers, derives protected coefficients,
executes a standards correlation, or makes a conformity claim.
"""

from __future__ import annotations

from hashlib import sha256
import json
from typing import Final

from pydantic import ValidationError

from app.engineering.design.dp_flow_application_models import DPConfidenceBand
from app.engineering.design.dp_flow_application_models import DPCalculationReadiness
from app.engineering.design.dp_flow_application_models import DPFlowApplicationAssessment
from app.engineering.design.dp_flow_application_models import DPFlowApplicationRequest
from app.engineering.design.dp_flow_application_models import DPFluidPhase
from app.engineering.design.dp_flow_application_models import DPMeasurementObjective
from app.engineering.design.dp_flow_application_models import DPOfficialSource
from app.engineering.design.dp_flow_application_models import DPOwnershipType
from app.engineering.design.dp_flow_application_models import DPPressureLossClass
from app.engineering.design.dp_flow_application_models import DPPrimaryElementDefinition
from app.engineering.design.dp_flow_application_models import DPPrimaryElementFamily
from app.engineering.design.dp_flow_application_models import DPPrimaryElementScenario
from app.engineering.design.dp_flow_application_models import DPProprietaryNotice
from app.engineering.design.dp_flow_application_models import DPScenarioDisposition
from app.engineering.design.dp_flow_application_models import DPTriState
from app.engineering.design.dp_flow_application_models import DPVerificationPriority
from app.engineering.design.dp_flow_application_models import DPVerificationStep
from app.engineering.design.dp_flow_application_models import FINAL_BRAND_DECISION_NOTICE


DP_FLOW_APPLICATION_WIZARD_VERSION = "1.1.0"
DP_FLOW_APPLICATION_RULESET_VERSION = "1.1.0"


OFFICIAL_SOURCES: Final = (
    DPOfficialSource(
        source_id="official.iso.5167-2", owner="International Organization for Standardization",
        title="ISO 5167-2 pressure differential devices — orifice plates",
        public_url="https://www.iso.org/standard/79180.html", reviewed_on="2026-08-01",
        usage_boundary="Public identity and scope metadata only; protected requirements and correlations are not reproduced or executed.",
    ),
    DPOfficialSource(
        source_id="official.iso.5167-3", owner="International Organization for Standardization",
        title="ISO 5167-3 pressure differential devices — nozzles and Venturi nozzles",
        public_url="https://www.iso.org/standard/84845.html", reviewed_on="2026-08-01",
        usage_boundary="Public identity and scope metadata only; licensed controlled content and engineering approval are required for implementation.",
    ),
    DPOfficialSource(
        source_id="official.iso.5167-4", owner="International Organization for Standardization",
        title="ISO 5167-4 pressure differential devices — Venturi tubes",
        public_url="https://www.iso.org/standard/79181.html", reviewed_on="2026-08-01",
        usage_boundary="Public identity and scope metadata only; no conformity or correlation is provided.",
    ),
    DPOfficialSource(
        source_id="official.iso.5167-5", owner="International Organization for Standardization",
        title="ISO 5167-5 pressure differential devices — cone meters",
        public_url="https://www.iso.org/standard/83688.html", reviewed_on="2026-08-01",
        usage_boundary="Public identity and scope metadata only; cone remains a generic family and project calibration/applicability must be verified.",
    ),
    DPOfficialSource(
        source_id="official.iso.5167-6", owner="International Organization for Standardization",
        title="ISO 5167-6 pressure differential devices — wedge meters",
        public_url="https://www.iso.org/standard/83689.html", reviewed_on="2026-08-01",
        usage_boundary="Public identity and scope metadata only; wedge remains a generic family and protected requirements are not reproduced.",
    ),
    DPOfficialSource(
        source_id="official.emerson.annubar",
        owner="Emerson / Rosemount",
        title="Rosemount Annubar Flow Meter Series reference material",
        public_url="https://www.emerson.com/is/content/emerson/en/measurement-instrumentation/technical/products/dp-flow/documents/doc-rosemount-00809-0100-4809.pdf",
        reviewed_on="2026-08-01",
        usage_boundary="Identity and ownership metadata only; current model, coefficient, installation, and approval data must come from controlled OEM documentation.",
    ),
    DPOfficialSource(
        source_id="official.emerson.1595",
        owner="Emerson / Rosemount",
        title="Rosemount 1595 Conditioning Orifice Plate product page",
        public_url="https://www.emerson.com/en/measurement-instrumentation/products/rosemount-1595-conditioning-orifice-plate",
        reviewed_on="2026-08-01",
        usage_boundary="Proprietary identity metadata only; no performance value is accepted without current project-specific OEM evidence.",
    ),
    DPOfficialSource(
        source_id="official.mccrometer.vcone",
        owner="McCrometer",
        title="McCrometer V-Cone differential-pressure flow meter product page",
        public_url="https://www.mccrometer.com/product/v-cone/",
        reviewed_on="2026-08-01",
        usage_boundary="Registered-trademark and product identity metadata only; calculation data requires controlled OEM documentation and calibration evidence.",
    ),
    DPOfficialSource(
        source_id="official.mccrometer.wafercone",
        owner="McCrometer",
        title="McCrometer Wafer-Cone product page",
        public_url="https://www.mccrometer.com/product/wafer-cone/",
        reviewed_on="2026-08-01",
        usage_boundary="Registered-trademark and product identity metadata only; project suitability and coefficients remain subject to controlled OEM review.",
    ),
    DPOfficialSource(
        source_id="official.armstrong.verabar",
        owner="Armstrong International / VERIS",
        title="VERIS Verabar product specification",
        public_url="https://web-material3.yokogawa.com/1/23041/files/V100-V110-SpecSheet_1637-EN.pdf",
        reviewed_on="2026-08-01",
        usage_boundary="Owned product identity metadata only; model-specific limits and coefficients require current controlled manufacturer documentation.",
    ),
    DPOfficialSource(
        source_id="official.armstrong.accelabar",
        owner="Armstrong International / VERIS",
        title="VERIS Accelabar partner product page",
        public_url="https://www.yokogawa.com/solutions/products-and-services/measurement/field-instruments-products/partners-product/veris-accelabar/",
        reviewed_on="2026-08-01",
        usage_boundary="Patented-product identity metadata only; no performance or installation claim is adopted by the wizard.",
    ),
    DPOfficialSource(
        source_id="official.abb.torbar",
        owner="ABB",
        title="ABB Torbar multiport self-averaging flowmeter data sheet",
        public_url="https://library.e.abb.com/public/0a7a578aaf2a477f9e3da0d08f1042a3/DS_FPD350-EN_M.pdf",
        reviewed_on="2026-08-01",
        usage_boundary="Owned product identity metadata only; model-specific coefficients and application limits require current controlled ABB documentation.",
    ),
)


def _notice(name: str, owner: str, ownership: DPOwnershipType, source_id: str) -> DPProprietaryNotice:
    return DPProprietaryNotice(
        name=name,
        owner=owner,
        ownership_type=ownership,
        notice=(
            f"{name} is an owned product name of {owner}; it is not a generic DP primary-element category. "
            "Engineer4Me provides no affiliation, endorsement, licence, or equivalence claim."
        ),
        source_ids=(source_id,),
    )


def _generic(
    option_id: str,
    family: DPPrimaryElementFamily,
    title: str,
    variant: str,
    loss: DPPressureLossClass,
    strengths: tuple[str, ...],
    limitations: tuple[str, ...],
    readiness: DPCalculationReadiness = DPCalculationReadiness.REVIEWED_STANDARD_METHOD_REQUIRED,
) -> DPPrimaryElementDefinition:
    return DPPrimaryElementDefinition(
        option_id=option_id,
        family=family,
        title=title,
        variant=variant,
        ownership_type=DPOwnershipType.GENERIC_TECHNOLOGY,
        typical_pressure_loss=loss,
        calculation_readiness=readiness,
        coefficient_basis="Use only a project-approved standard correlation or a traceable calibrated coefficient applicable to the exact geometry and conditions.",
        calculation_basis="Calculate with explicit flowing properties, pressure basis, expansibility treatment, geometry, tap arrangement, and uncertainty contributors.",
        strengths_to_verify=strengths,
        limitations_to_verify=limitations,
    )


GENERIC_PRIMARY_ELEMENTS: Final = (
    _generic("generic.orifice.concentric-square-edge", DPPrimaryElementFamily.ORIFICE_PLATE, "Concentric square-edge orifice plate", "Standard-shaped concentric sharp-edge plate with specified taps", DPPressureLossClass.HIGH, ("broad engineering familiarity", "replaceable primary element"), ("edge condition and bore geometry", "straight-run sensitivity", "permanent pressure loss"), readiness=DPCalculationReadiness.STEP97_GENERIC_SUPPLIED_COEFFICIENTS),
    _generic("generic.orifice.eccentric-or-segmental", DPPrimaryElementFamily.ORIFICE_PLATE, "Eccentric or segmental orifice plate", "Alternative-bore plate for solids, entrained phase, or drainage considerations", DPPressureLossClass.HIGH, ("passage for selected entrained material", "simple plate construction"), ("orientation is critical", "coefficient and standard applicability are geometry-specific")),
    _generic("generic.orifice.integral-compact", DPPrimaryElementFamily.INTEGRAL_ORIFICE, "Integral or compact orifice assembly", "Small-line or integrated plate-and-transmitter arrangement", DPPressureLossClass.HIGH, ("compact assembly", "reduced impulse-path complexity may be possible"), ("small bores can plug", "OEM geometry and coefficient evidence required"), readiness=DPCalculationReadiness.MANUFACTURER_SIZING_REQUIRED),
    _generic("generic.nozzle.isa-or-long-radius", DPPrimaryElementFamily.FLOW_NOZZLE, "Flow nozzle", "ISA-style or long-radius nozzle selected under an approved method", DPPressureLossClass.MODERATE, ("robust contour", "potential high-velocity service suitability"), ("method-specific geometry", "installation and machining verification"), readiness=DPCalculationReadiness.STEP98_GENERIC_SUPPLIED_COEFFICIENTS),
    _generic("generic.venturi.classical", DPPrimaryElementFamily.VENTURI_TUBE, "Classical Venturi tube", "Convergent throat and pressure-recovery diffuser", DPPressureLossClass.LOW, ("pressure recovery", "potential dirty-service tolerance with suitable design"), ("space, mass, and cost", "fabrication and calibration evidence"), readiness=DPCalculationReadiness.STEP98_GENERIC_SUPPLIED_COEFFICIENTS),
    _generic("generic.venturi-nozzle", DPPrimaryElementFamily.VENTURI_NOZZLE, "Venturi nozzle", "Nozzle inlet with pressure-recovery section", DPPressureLossClass.MODERATE, ("more recovery than a simple sharp-edge plate", "robust inlet geometry"), ("geometry-specific correlation", "fabrication and installation requirements"), readiness=DPCalculationReadiness.STEP98_GENERIC_SUPPLIED_COEFFICIENTS),
    _generic("generic.wedge", DPPrimaryElementFamily.WEDGE, "Wedge primary element", "Wedge restriction with geometry suited to the selected service", DPPressureLossClass.MODERATE, ("potential viscous or solids-bearing service applicability", "open lower flow path in selected orientation"), ("coefficient is geometry/Reynolds dependent", "calibration may be required")),
    _generic("generic.averaging-pitot", DPPrimaryElementFamily.AVERAGING_PITOT, "Averaging pitot tube", "Generic multi-port velocity-averaging probe", DPPressureLossClass.LOW, ("low blockage", "potential large-pipe retrofit"), ("low DP signal at low velocity", "profile, support, vibration, and port plugging"), readiness=DPCalculationReadiness.STEP98_GENERIC_SUPPLIED_COEFFICIENTS),
    _generic("generic.single-point-pitot", DPPrimaryElementFamily.SINGLE_POINT_PITOT, "Single-point pitot-static probe", "Local velocity probe or engineered traverse arrangement", DPPressureLossClass.LOW, ("minimal blockage", "duct or traverse applications"), ("point velocity may not represent mean flow", "traverse and profile evidence")),
    _generic("generic.cone.dp", DPPrimaryElementFamily.CONE_METER, "Cone-type DP primary element", "Generic centrally mounted cone technology; owned implementations are separate variants", DPPressureLossClass.MODERATE, ("potential flow-profile conditioning", "compact installed length may be possible"), ("coefficient and geometry are design-specific", "do not assume equivalence among owned products")),
    _generic("generic.conditioning.multi-hole", DPPrimaryElementFamily.CONDITIONING_ELEMENT, "Multi-hole conditioning DP element", "Generic category only; individual hole patterns may be proprietary", DPPressureLossClass.HIGH, ("potential disturbed-profile mitigation" ,), ("pattern-specific coefficient evidence", "owned designs require explicit attribution")),
    _generic("generic.laminar-flow-element", DPPrimaryElementFamily.LAMINAR_FLOW_ELEMENT, "Laminar flow element", "Engineered viscous-flow element using a traceable calibration/method", DPPressureLossClass.MODERATE, ("linear DP relation may be available in its controlled regime",), ("narrow regime and contamination sensitivity", "temperature-viscosity dependence"), readiness=DPCalculationReadiness.DEVICE_SPECIFIC_CALIBRATION_REQUIRED),
    _generic("generic.elbow-tap", DPPrimaryElementFamily.ELBOW_METER, "Elbow-tap DP measurement", "Pressure taps across an engineered pipe elbow", DPPressureLossClass.LOW, ("may use existing fitting in screening applications",), ("profile and geometry sensitivity", "normally requires site calibration and lower confidence"), readiness=DPCalculationReadiness.DEVICE_SPECIFIC_CALIBRATION_REQUIRED),
    _generic("generic.orifice.quadrant-or-conical-entry", DPPrimaryElementFamily.ORIFICE_PLATE, "Quadrant-edge or conical-entry orifice", "Special inlet geometry for a controlled low-Reynolds or viscous-flow method", DPPressureLossClass.HIGH, ("specialist low-Reynolds application may be possible",), ("not interchangeable with a square-edge plate", "geometry-specific calibration and condition limits"), readiness=DPCalculationReadiness.DEVICE_SPECIFIC_CALIBRATION_REQUIRED),
    _generic("generic.orifice.meter-run", DPPrimaryElementFamily.ORIFICE_PLATE, "Orifice meter run", "Controlled plate, taps, pipe bore, and upstream/downstream spool assembly", DPPressureLossClass.HIGH, ("controlled assembled geometry", "traceable bore and tap configuration"), ("assembly-specific coefficient and inspection", "permanent pressure loss")),
    _generic("generic.pitot.traverse-grid", DPPrimaryElementFamily.SINGLE_POINT_PITOT, "Pitot traverse or multi-point grid", "Engineered multi-point duct or pipe velocity survey", DPPressureLossClass.LOW, ("profile measurement rather than one assumed point",), ("traverse plan and area integration", "alignment, blockage, and calibration"), readiness=DPCalculationReadiness.DEVICE_SPECIFIC_CALIBRATION_REQUIRED),
    _generic("legacy.dall-or-low-loss-tube", DPPrimaryElementFamily.VENTURI_TUBE, "Dall or legacy low-loss DP tube", "Legacy/custom pressure-recovery element requiring device evidence", DPPressureLossClass.LOW, ("legacy pressure-recovery installation may remain serviceable",), ("device identity, geometry, and coefficient may be unavailable", "do not substitute a Venturi correlation"), readiness=DPCalculationReadiness.DEVICE_SPECIFIC_CALIBRATION_REQUIRED),
    _generic("excluded.restriction-orifice", DPPrimaryElementFamily.ORIFICE_PLATE, "Restriction orifice", "Pressure-reduction device, not accepted as a measurement element by default", DPPressureLossClass.HIGH, ("controlled process-pressure reduction",), ("no measurement status without traceable calibration", "choking, noise, cavitation, vibration, and erosion review"), readiness=DPCalculationReadiness.UNSUPPORTED),
)


PROPRIETARY_PRIMARY_ELEMENTS: Final = (
    DPPrimaryElementDefinition(
        option_id="owned.emerson-rosemount.annubar", family=DPPrimaryElementFamily.AVERAGING_PITOT,
        title="Rosemount Annubar", variant="Owned averaging pitot-tube product family",
        ownership_type=DPOwnershipType.REGISTERED_TRADEMARK_PRODUCT, owner="Emerson / Rosemount",
        generic_alternative_id="generic.averaging-pitot", typical_pressure_loss=DPPressureLossClass.LOW,
        calculation_readiness=DPCalculationReadiness.MANUFACTURER_SIZING_REQUIRED,
        coefficient_basis="Use current controlled Rosemount model-specific sizing and coefficient evidence only.",
        calculation_basis="OEM-controlled sizing or independently approved calibrated method; the generic Step 97 kernel may use supplied traceable coefficients but makes no OEM or standards claim.",
        strengths_to_verify=("low-blockage averaging-pitot application", "available insertion and integrated configurations"),
        limitations_to_verify=("model, support, vibration, port plugging, and Reynolds limits", "trademark and OEM method boundary"),
        source_ids=("official.emerson.annubar",), proprietary_notice=_notice("Annubar", "Emerson / Rosemount", DPOwnershipType.REGISTERED_TRADEMARK_PRODUCT, "official.emerson.annubar"),
    ),
    DPPrimaryElementDefinition(
        option_id="owned.emerson-rosemount.1595", family=DPPrimaryElementFamily.CONDITIONING_ELEMENT,
        title="Rosemount 1595 Conditioning Orifice Plate", variant="Owned proprietary four-hole conditioning plate",
        ownership_type=DPOwnershipType.PROPRIETARY_PRODUCT, owner="Emerson / Rosemount",
        generic_alternative_id="generic.conditioning.multi-hole", typical_pressure_loss=DPPressureLossClass.HIGH,
        calculation_readiness=DPCalculationReadiness.MANUFACTURER_SIZING_REQUIRED,
        coefficient_basis="Use current controlled Rosemount 1595 sizing, geometry, and coefficient evidence only.",
        calculation_basis="OEM-controlled method; no generic four-hole equivalence or ISO conformity is inferred.",
        strengths_to_verify=("disturbed-profile application option", "compact installation potential"),
        limitations_to_verify=("OEM-specific pattern and orientation", "permanent pressure loss and current model limits"),
        source_ids=("official.emerson.1595",), proprietary_notice=_notice("Rosemount 1595 Conditioning Orifice Plate", "Emerson / Rosemount", DPOwnershipType.PROPRIETARY_PRODUCT, "official.emerson.1595"),
    ),
    DPPrimaryElementDefinition(
        option_id="owned.mccrometer.v-cone", family=DPPrimaryElementFamily.CONE_METER,
        title="McCrometer V-Cone", variant="Registered-trademark cone DP flow meter",
        ownership_type=DPOwnershipType.REGISTERED_TRADEMARK_PRODUCT, owner="McCrometer",
        generic_alternative_id="generic.cone.dp", typical_pressure_loss=DPPressureLossClass.MODERATE,
        calculation_readiness=DPCalculationReadiness.MANUFACTURER_SIZING_REQUIRED,
        coefficient_basis="Use current controlled McCrometer sizing and calibration evidence only.",
        calculation_basis="OEM-controlled or traceably calibrated method; no equivalence to other cone designs is assumed.",
        strengths_to_verify=("cone-type profile interaction", "project-specific calibration availability"),
        limitations_to_verify=("owned geometry and coefficient", "installation, inspection, and pressure-loss evidence"),
        source_ids=("official.mccrometer.vcone",), proprietary_notice=_notice("V-Cone", "McCrometer", DPOwnershipType.REGISTERED_TRADEMARK_PRODUCT, "official.mccrometer.vcone"),
    ),
    DPPrimaryElementDefinition(
        option_id="owned.mccrometer.wafer-cone", family=DPPrimaryElementFamily.CONE_METER,
        title="McCrometer Wafer-Cone", variant="Registered-trademark wafer cone DP flow meter",
        ownership_type=DPOwnershipType.REGISTERED_TRADEMARK_PRODUCT, owner="McCrometer",
        generic_alternative_id="generic.cone.dp", typical_pressure_loss=DPPressureLossClass.MODERATE,
        calculation_readiness=DPCalculationReadiness.MANUFACTURER_SIZING_REQUIRED,
        coefficient_basis="Use current controlled McCrometer model and calibration evidence only.",
        calculation_basis="OEM-controlled method; no generic cone coefficient is substituted.",
        strengths_to_verify=("compact cone-type configuration",),
        limitations_to_verify=("owned geometry", "line size, calibration, and installation limits"),
        source_ids=("official.mccrometer.wafercone",), proprietary_notice=_notice("Wafer-Cone", "McCrometer", DPOwnershipType.REGISTERED_TRADEMARK_PRODUCT, "official.mccrometer.wafercone"),
    ),
    DPPrimaryElementDefinition(
        option_id="owned.armstrong-veris.verabar", family=DPPrimaryElementFamily.AVERAGING_PITOT,
        title="VERIS Verabar", variant="Owned averaging pitot-tube product family",
        ownership_type=DPOwnershipType.REGISTERED_TRADEMARK_PRODUCT, owner="Armstrong International / VERIS",
        generic_alternative_id="generic.averaging-pitot", typical_pressure_loss=DPPressureLossClass.LOW,
        calculation_readiness=DPCalculationReadiness.MANUFACTURER_SIZING_REQUIRED,
        coefficient_basis="Use current controlled VERIS model-specific coefficient evidence only.",
        calculation_basis="OEM-controlled sizing or independently approved calibration; no generic interchangeability claim.",
        strengths_to_verify=("low-blockage averaging-pitot application", "multiple mounting configurations"),
        limitations_to_verify=("support, insertion, vibration, plugging, and model limits",),
        source_ids=("official.armstrong.verabar",), proprietary_notice=_notice("VERIS Verabar", "Armstrong International / VERIS", DPOwnershipType.REGISTERED_TRADEMARK_PRODUCT, "official.armstrong.verabar"),
    ),
    DPPrimaryElementDefinition(
        option_id="owned.armstrong-veris.accelabar", family=DPPrimaryElementFamily.CONDITIONING_ELEMENT,
        title="VERIS Accelabar", variant="Owned nozzle and Verabar combination product",
        ownership_type=DPOwnershipType.PROPRIETARY_PRODUCT, owner="Armstrong International / VERIS",
        generic_alternative_id="generic.averaging-pitot", typical_pressure_loss=DPPressureLossClass.MODERATE,
        calculation_readiness=DPCalculationReadiness.MANUFACTURER_SIZING_REQUIRED,
        coefficient_basis="Use current controlled VERIS model-specific sizing and coefficient evidence only.",
        calculation_basis="Patented/OEM-controlled method; no generic nozzle-plus-probe equivalence is inferred.",
        strengths_to_verify=("integrated profile-conditioning application",),
        limitations_to_verify=("owned geometry and method", "pressure loss, installation, and calibration evidence"),
        source_ids=("official.armstrong.accelabar",), proprietary_notice=_notice("VERIS Accelabar", "Armstrong International / VERIS", DPOwnershipType.PROPRIETARY_PRODUCT, "official.armstrong.accelabar"),
    ),
    DPPrimaryElementDefinition(
        option_id="owned.abb.torbar", family=DPPrimaryElementFamily.AVERAGING_PITOT,
        title="ABB Torbar", variant="Owned multiport self-averaging pitot product family",
        ownership_type=DPOwnershipType.PROPRIETARY_PRODUCT, owner="ABB",
        generic_alternative_id="generic.averaging-pitot", typical_pressure_loss=DPPressureLossClass.LOW,
        calculation_readiness=DPCalculationReadiness.MANUFACTURER_SIZING_REQUIRED,
        coefficient_basis="Use current controlled ABB model-specific sizing and coefficient evidence only.",
        calculation_basis="OEM-controlled sizing or independently approved calibration; no coefficient transfer from another averaging-pitot design.",
        strengths_to_verify=("low-blockage averaging-pitot application", "multiport velocity sampling"),
        limitations_to_verify=("model, support, vibration, port plugging, and application limits",),
        source_ids=("official.abb.torbar",), proprietary_notice=_notice("ABB Torbar", "ABB", DPOwnershipType.PROPRIETARY_PRODUCT, "official.abb.torbar"),
    ),
)


PRIMARY_ELEMENT_CATALOGUE: Final = GENERIC_PRIMARY_ELEMENTS + PROPRIETARY_PRIMARY_ELEMENTS


def _impulse_arrangement(request: DPFlowApplicationRequest) -> str:
    if request.fluid_phase is DPFluidPhase.LIQUID or request.fluid_phase is DPFluidPhase.SLURRY:
        return "Prefer side taps and route both impulse legs continuously downward to a transmitter below the taps; verify venting, flushing, freezing, plugging, and equal hydrostatic head."
    if request.fluid_phase in {DPFluidPhase.GAS, DPFluidPhase.VAPOUR}:
        return "Prefer top taps and route both impulse legs continuously upward to a transmitter above the taps; verify drainage, condensation, plugging, and equal elevation."
    if request.fluid_phase is DPFluidPhase.STEAM:
        return "Use matched condensate legs with approved condensate pots or controlled equal-head arrangement; verify fill, warm-up, temperature limits, freezing, blowdown, and safe isolation."
    return "Fluid phase is unresolved; a competent engineer must define tap orientation, leg slope, phase management, isolation, equal-head effects, and safe vent/drain facilities."


def _screen(option: DPPrimaryElementDefinition, request: DPFlowApplicationRequest) -> DPPrimaryElementScenario:
    score = 0
    reasons: list[str] = []
    rejected: list[str] = []
    if option.ownership_type is DPOwnershipType.GENERIC_TECHNOLOGY:
        reasons.append("generic technology can be compared without selecting a manufacturer")
    else:
        reasons.append("owned variant is disclosed and compared only against its generic family")
    if request.maximum_permanent_pressure_loss_pa is not None:
        if option.typical_pressure_loss is DPPressureLossClass.LOW:
            score += 18; reasons.append("low-loss family is relevant to the stated pressure-loss constraint")
        elif option.typical_pressure_loss is DPPressureLossClass.HIGH:
            score -= 18; reasons.append("high-loss family requires a project pressure-loss check")
    if (
        request.pipe_inside_diameter_m is not None
        and request.pipe_inside_diameter_m >= 0.6
        and option.family in {
            DPPrimaryElementFamily.AVERAGING_PITOT,
            DPPrimaryElementFamily.SINGLE_POINT_PITOT,
        }
    ):
        score += 14; reasons.append("probe technology may suit a large-pipe installation")
    if request.dirty_or_solids_bearing is DPTriState.YES or request.fluid_phase is DPFluidPhase.SLURRY:
        if option.option_id == "generic.orifice.concentric-square-edge":
            rejected.append("concentric sharp-edge plate is screened out until solids passage, plugging, erosion, and drainability are resolved")
        elif option.family in {DPPrimaryElementFamily.WEDGE, DPPrimaryElementFamily.VENTURI_TUBE} or option.option_id == "generic.orifice.eccentric-or-segmental":
            score += 18; reasons.append("geometry may offer a more suitable solids passage subject to detailed verification")
        elif option.family in {DPPrimaryElementFamily.AVERAGING_PITOT, DPPrimaryElementFamily.INTEGRAL_ORIFICE, DPPrimaryElementFamily.LAMINAR_FLOW_ELEMENT}:
            score -= 16; reasons.append("pressure ports or small passages require a plugging and purge assessment")
    if request.erosive is DPTriState.YES and option.family in {
        DPPrimaryElementFamily.ORIFICE_PLATE,
        DPPrimaryElementFamily.FLOW_NOZZLE,
        DPPrimaryElementFamily.WEDGE,
    }:
        score -= 12; reasons.append("edge/profile wear and coefficient drift require material and inspection controls")
    upstream = request.available_upstream_straight_run_d
    if upstream is not None and upstream < 5.0:
        if option.family in {DPPrimaryElementFamily.CONDITIONING_ELEMENT, DPPrimaryElementFamily.CONE_METER}:
            score += 12; reasons.append("conditioning-style geometry may be relevant where straight run is constrained")
        elif option.family in {DPPrimaryElementFamily.ORIFICE_PLATE, DPPrimaryElementFamily.FLOW_NOZZLE, DPPrimaryElementFamily.SINGLE_POINT_PITOT}:
            score -= 16; reasons.append("limited straight run increases profile uncertainty and requires a controlled mitigation")
    if request.bidirectional_flow is DPTriState.YES:
        rejected.append("bidirectional flow is outside the current unidirectional calculation workflow")
    if request.pulsating_flow is DPTriState.YES:
        rejected.append("pulsating flow requires a separately reviewed dynamic method")
    if request.full_pipe_confirmed is DPTriState.NO:
        rejected.append("closed-conduit DP flow screening requires a confirmed full pipe")
    if request.wet_gas_or_condensing is DPTriState.YES or request.fluid_phase is DPFluidPhase.MULTIPHASE:
        rejected.append("two-phase or wet-gas behavior requires a separately reviewed correction or calibrated method")
    if request.flashing_or_cavitation_risk is DPTriState.YES:
        rejected.append("flashing or cavitation risk must be resolved before this incompressible/subsonic screening can proceed")
    if request.sonic_or_choked_flow_risk is DPTriState.YES:
        rejected.append("sonic or choked flow requires a separately reviewed critical-flow method")
    if request.intrusive_element_allowed is DPTriState.NO:
        rejected.append("the request prohibits an intrusive DP primary element")
    if request.traceable_coefficient_available is DPTriState.NO:
        rejected.append("the executable supplied-coefficient workflow requires traceable coefficient evidence")
    if option.calculation_readiness is DPCalculationReadiness.UNSUPPORTED:
        rejected.append("this option is not supported as a measurement element without device-specific traceable calibration evidence")
    if request.objective in {DPMeasurementObjective.CUSTODY_TRANSFER, DPMeasurementObjective.SAFETY_RELATED}:
        score -= 8; reasons.append("high-consequence objective requires an approved method, uncertainty budget, independent review, and project acceptance")
    critical_missing = (
        request.fluid_phase is DPFluidPhase.UNKNOWN
        or request.full_pipe_confirmed is DPTriState.UNKNOWN
        or request.flashing_or_cavitation_risk is DPTriState.UNKNOWN
        or request.sonic_or_choked_flow_risk is DPTriState.UNKNOWN
        or request.intrusive_element_allowed is DPTriState.UNKNOWN
        or request.wet_gas_or_condensing is DPTriState.UNKNOWN
        or request.pulsating_flow is DPTriState.UNKNOWN
        or request.bidirectional_flow is DPTriState.UNKNOWN
        or request.traceable_coefficient_available is DPTriState.UNKNOWN
        or request.pipe_inside_diameter_m is None
        or request.minimum_mass_flow_kg_s is None
        or request.normal_mass_flow_kg_s is None
        or request.maximum_mass_flow_kg_s is None
        or request.flowing_density_kg_m3 is None
        or request.flowing_viscosity_pa_s is None
        or request.flowing_absolute_pressure_pa is None
        or request.flowing_temperature_k is None
    )
    if rejected:
        disposition = DPScenarioDisposition.REJECTED
    elif critical_missing:
        disposition = DPScenarioDisposition.INSUFFICIENT_INFORMATION
    elif option.ownership_type is not DPOwnershipType.GENERIC_TECHNOLOGY:
        disposition = DPScenarioDisposition.CONDITIONAL
    elif score < -20:
        disposition = DPScenarioDisposition.REJECTED
    elif score < 8:
        disposition = DPScenarioDisposition.CONDITIONAL
    else:
        disposition = DPScenarioDisposition.VIABLE
    if rejected:
        disposition = DPScenarioDisposition.REJECTED
    return DPPrimaryElementScenario(
        option=option, disposition=disposition, engineering_score=score,
        reasons=tuple(reasons) or ("no differentiating evidence was supplied",),
        rejected_reasons=tuple(rejected), pressure_loss=option.typical_pressure_loss,
        pressure_loss_output="Calculate permanent pressure loss at minimum, normal, maximum, start-up, and credible upset conditions using the selected approved method or controlled OEM evidence.",
        straight_run_output="Verify upstream/downstream fittings, planes, reducers, valves, swirl, profile, and required straight lengths against the exact approved method or current OEM instructions.",
        uncertainty_output="Build a project uncertainty budget including primary coefficient, DP transmitter, density, geometry, installation, Reynolds number, expansibility, reference conditions, and operating range.",
        impulse_line_arrangement=_impulse_arrangement(request),
        calculation_method=option.calculation_basis,
        calculation_readiness=option.calculation_readiness,
    )


def _missing(request: DPFlowApplicationRequest) -> tuple[str, ...]:
    values = {
        "fluid phase": request.fluid_phase is DPFluidPhase.UNKNOWN,
        "pipe inside diameter": request.pipe_inside_diameter_m is None,
        "minimum/normal/maximum flow cases": any(value is None for value in (request.minimum_mass_flow_kg_s, request.normal_mass_flow_kg_s, request.maximum_mass_flow_kg_s)),
        "flowing density": request.flowing_density_kg_m3 is None,
        "flowing viscosity": request.flowing_viscosity_pa_s is None,
        "flowing absolute pressure": request.flowing_absolute_pressure_pa is None,
        "flowing temperature": request.flowing_temperature_k is None,
        "available upstream/downstream straight run": request.available_upstream_straight_run_d is None or request.available_downstream_straight_run_d is None,
        "required total uncertainty": request.required_total_uncertainty_percent is None,
        "approved method availability": request.approved_standard_or_oem_method_available is DPTriState.UNKNOWN,
        "traceable coefficient availability": request.traceable_coefficient_available is DPTriState.UNKNOWN,
        "hazardous-area classification": request.hazardous_area is DPTriState.UNKNOWN,
        "full-pipe confirmation": request.full_pipe_confirmed is DPTriState.UNKNOWN,
        "flashing or cavitation risk": request.flashing_or_cavitation_risk is DPTriState.UNKNOWN,
        "sonic or choked-flow risk": request.sonic_or_choked_flow_risk is DPTriState.UNKNOWN,
        "intrusive-element permission": request.intrusive_element_allowed is DPTriState.UNKNOWN,
        "wet-gas or condensing risk": request.wet_gas_or_condensing is DPTriState.UNKNOWN,
        "pulsating-flow status": request.pulsating_flow is DPTriState.UNKNOWN,
        "bidirectional-flow status": request.bidirectional_flow is DPTriState.UNKNOWN,
    }
    return tuple(name for name, missing in values.items() if missing)


def _safety(request: DPFlowApplicationRequest) -> tuple[str, ...]:
    findings = ["Isolate, depressurize, drain/vent, lock out, and prove a safe state before opening any pressure boundary unless an approved engineered online-insertion procedure applies."]
    if request.hazardous_area is not DPTriState.NO:
        findings.append("Verify hazardous-area classification, equipment protection, wiring, earthing, temperature class, certificates, and installation practice.")
    if request.sour_or_toxic_service is not DPTriState.NO:
        findings.append("Verify toxic/sour-service materials, containment, PPE, gas testing, escape, decontamination, and controlled vent/drain disposal.")
    if request.oxygen_or_high_purity_service is not DPTriState.NO:
        findings.append("Verify oxygen/high-purity cleaning, compatible materials, contamination control, and approved assembly practices.")
    if request.fluid_phase is DPFluidPhase.STEAM:
        findings.append("Treat steam impulse systems as burn and stored-energy hazards; verify equal condensate heads and controlled warm-up before placing the transmitter in service.")
    if request.online_insertion_or_hot_tap_requested is DPTriState.YES:
        findings.append("Online insertion or hot tapping requires an engineered pressure-boundary design, rated access valve and retrieval system, competent authorization, exclusion zone, and approved live-work procedure.")
    return tuple(findings)


VERIFICATION_STEPS: Final = (
    DPVerificationStep(verification_id="dp.verify.process-basis", priority=DPVerificationPriority.MANDATORY, action="Approve the process design basis and all minimum, normal, maximum, start-up, shutdown, and upset cases.", acceptance_criteria="Every case has traceable fluid properties, absolute pressure, temperature, composition, phase, and flow basis.", required_evidence=("approved process datasheet", "controlled fluid-property source")),
    DPVerificationStep(verification_id="dp.verify.method", priority=DPVerificationPriority.MANDATORY, action="Select and approve the exact calculation method before sizing or final recommendation.", acceptance_criteria="Method lifecycle is approved for the exact element geometry, tap arrangement, fluid, Reynolds range, and project jurisdiction.", required_evidence=("approved method record", "standards or OEM entitlement evidence")),
    DPVerificationStep(verification_id="dp.verify.coefficient", priority=DPVerificationPriority.MANDATORY, action="Verify the discharge or flow coefficient and expansibility treatment are traceable and applicable.", acceptance_criteria="No inferred, default, unrelated, or unlicensed coefficient is used.", required_evidence=("coefficient source", "applicability record")),
    DPVerificationStep(verification_id="dp.verify.installation", priority=DPVerificationPriority.HIGH, action="Survey actual piping, disturbances, bore, schedule, ovality, roughness, taps, orientation, supports, and access.", acceptance_criteria="As-built installation matches the approved calculation and installation method.", required_evidence=("site survey", "piping drawing", "installation inspection")),
    DPVerificationStep(verification_id="dp.verify.performance", priority=DPVerificationPriority.HIGH, action="Calculate DP signal, permanent pressure loss, rangeability, uncertainty, velocity, Reynolds number, and overload margins for every case.", acceptance_criteria="All project performance limits pass with documented margin.", required_evidence=("controlled calculations", "independent check", "uncertainty budget")),
    DPVerificationStep(verification_id="dp.verify.safety", priority=DPVerificationPriority.MANDATORY, action="Complete pressure-boundary, process-hazard, impulse-line, maintenance, and hazardous-area reviews.", acceptance_criteria="Required competent persons approve the design and safe work controls before procurement or intervention.", required_evidence=("risk assessment", "MOC or design approval", "certification record")),
)


def assess_dp_flow_application(request: DPFlowApplicationRequest) -> DPFlowApplicationAssessment:
    if not isinstance(request, DPFlowApplicationRequest):
        raise TypeError("request must be a DPFlowApplicationRequest")
    try:
        request = DPFlowApplicationRequest.model_validate(
            request.model_dump(
                mode="python",
                round_trip=True,
                warnings="error",
            )
        )
    except (TypeError, ValueError, ValidationError) as error:
        raise ValueError(
            "request failed controlled DPFlowApplicationRequest validation"
        ) from error
    catalogue = PRIMARY_ELEMENT_CATALOGUE if request.include_proprietary_variants else GENERIC_PRIMARY_ELEMENTS
    screened = tuple(_screen(option, request) for option in catalogue)
    generic_viable = [item for item in screened if item.option.ownership_type is DPOwnershipType.GENERIC_TECHNOLOGY and item.disposition is DPScenarioDisposition.VIABLE]
    generic_viable.sort(key=lambda item: (-item.engineering_score, item.option.option_id))
    recommended = generic_viable[0] if generic_viable else None
    viable = tuple(item for item in screened if item.disposition is not DPScenarioDisposition.REJECTED and item is not recommended)
    rejected = tuple(item for item in screened if item.disposition is DPScenarioDisposition.REJECTED)
    missing = _missing(request)
    score = max(0, min(100, 100 - 6 * len(missing)))
    if recommended is None:
        score = min(score, 45)
    confidence = DPConfidenceBand.HIGH if score >= 80 else DPConfidenceBand.MODERATE if score >= 50 else DPConfidenceBand.LOW
    notices = tuple(item.proprietary_notice for item in catalogue if item.proprietary_notice is not None)
    payload = {
        "request": request.model_dump(mode="json"),
        "recommended": None if recommended is None else recommended.option.option_id,
        "screened": [(item.option.option_id, item.disposition.value, item.engineering_score) for item in screened],
        "ruleset": DP_FLOW_APPLICATION_RULESET_VERSION,
    }
    fingerprint = sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return DPFlowApplicationAssessment(
        assessment_id=request.assessment_id,
        model_version=DP_FLOW_APPLICATION_WIZARD_VERSION,
        ruleset_version=DP_FLOW_APPLICATION_RULESET_VERSION,
        recommended_element=recommended,
        viable_alternatives=viable,
        rejected_options=rejected,
        all_screened_options=screened,
        missing_information=missing,
        safety_findings=_safety(request),
        verification_steps=VERIFICATION_STEPS,
        confidence_band=confidence,
        confidence_score=score,
        proprietary_notices=notices,
        official_sources=OFFICIAL_SOURCES if request.include_proprietary_variants else OFFICIAL_SOURCES[:5],
        final_brand_decision_notice=FINAL_BRAND_DECISION_NOTICE,
        final_brand_selection="user_decision_required",
        assessment_fingerprint=fingerprint,
    )


class DPFlowApplicationWizard:
    """Immutable facade for deterministic assessment."""

    __slots__ = ()

    def assess(self, request: DPFlowApplicationRequest) -> DPFlowApplicationAssessment:
        return assess_dp_flow_application(request)


DEFAULT_DP_FLOW_APPLICATION_WIZARD: Final = DPFlowApplicationWizard()


__all__ = [
    "DEFAULT_DP_FLOW_APPLICATION_WIZARD", "DPFlowApplicationWizard",
    "DP_FLOW_APPLICATION_RULESET_VERSION", "DP_FLOW_APPLICATION_WIZARD_VERSION",
    "GENERIC_PRIMARY_ELEMENTS", "OFFICIAL_SOURCES", "PRIMARY_ELEMENT_CATALOGUE",
    "PROPRIETARY_PRIMARY_ELEMENTS", "VERIFICATION_STEPS", "assess_dp_flow_application",
]

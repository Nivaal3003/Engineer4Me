"""Fail-closed pressure-relief readiness foundation for Phase 7 Step 103.

This module records the evidence needed before any pressure-relief sizing
method can be considered.  It deliberately contains no sizing equation,
orifice table, correction-factor correlation, device selection, or executable
standards adapter.  Incomplete requests produce deterministic blocking
findings instead of guessed engineering inputs.

The API 520/521 and ISO 4126 records below are discovery metadata only.  The
applicable jurisdiction, exact edition and amendments, licensed engineering
basis, independent reference vectors, and competent reviewers must be
established by later controlled work before a numerical method may execute.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from enum import StrEnum
from hashlib import sha256
from math import isfinite
from types import MappingProxyType
from typing import Final, Literal

from pydantic import Field, StrictBool, field_validator, model_validator

from app.engineering.calculations.models import (
    CalculationModel,
    CalculationStatus,
    FindingSeverity,
    MethodLifecycleStatus,
)

PRESSURE_RELIEF_FOUNDATION_VERSION: Final = "1.0.0"
PRESSURE_RELIEF_STANDARDS_PACK_VERSION: Final = "1.0.0"

API_520_521_STANDARDS_PACK_ID: Final = "pressure-relief.api-520-521.discovery"
ISO_4126_STANDARDS_PACK_ID: Final = "pressure-relief.iso-4126.discovery"

PRESSURE_RELIEF_MISSING_SCENARIO_FINDING_ID: Final = (
    "pressure-relief.missing-credible-scenario"
)
PRESSURE_RELIEF_MISSING_FLOW_BASIS_FINDING_ID: Final = (
    "pressure-relief.missing-required-flow-basis"
)
PRESSURE_RELIEF_MISSING_PRESSURE_BASIS_FINDING_ID: Final = (
    "pressure-relief.missing-pressure-basis"
)
PRESSURE_RELIEF_MISSING_JURISDICTION_FINDING_ID: Final = (
    "pressure-relief.missing-jurisdiction"
)
PRESSURE_RELIEF_MISSING_PROPERTIES_FINDING_ID: Final = (
    "pressure-relief.missing-phase-properties"
)
PRESSURE_RELIEF_MISSING_COMPETENCY_FINDING_ID: Final = (
    "pressure-relief.missing-review-competency"
)
PRESSURE_RELIEF_UNAPPROVED_METHOD_FINDING_ID: Final = (
    "pressure-relief.no-approved-method"
)

PRESSURE_RELIEF_REQUIRED_REVIEWER_COMPETENCY: Final = (
    "Independent competent pressure-systems engineer"
)

_MAX_PRESSURE_PA: Final = 1.0e12
_MAX_FLOW_KG_S: Final = 1.0e9
_MAX_DENSITY_KG_M3: Final = 1.0e7
_MAX_TEMPERATURE_K: Final = 1.0e6
_MAX_MOLAR_MASS_KG_KMOL: Final = 1.0e6
_MAX_SPECIFIC_VOLUME_M3_KG: Final = 1.0e9
_FINGERPRINT_SCHEMA: Final = "engineer4me.pressure-relief.readiness.v1"
_RESULT_FINGERPRINT_FIELDS: Final = (
    "foundation_version",
    "fingerprint_schema",
    "request_id",
    "request_fingerprint",
    "status",
    "blocking_findings",
    "competency_requirement",
    "ready_for_sizing",
    "calculation_performed",
    "device_selected",
    "standards_conformity_claimed",
    "preliminary_engineering_decision_support",
    "independent_review_required",
    "required_reviewer_competency",
)


class PressureReliefError(ValueError):
    """Base error for the Step 103 pressure-relief readiness boundary."""


class PressureReliefInputError(PressureReliefError):
    """Raised when a public readiness input cannot be validated safely."""


def _strict_text(
    value: object,
    *,
    field_name: str,
    allow_none: bool = False,
) -> str | None:
    """Require bounded callers to supply already-trimmed nonblank text."""

    if value is None and allow_none:
        return None
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be text")
    if not value.strip():
        raise ValueError(f"{field_name} cannot be blank")
    if value != value.strip():
        raise ValueError(f"{field_name} cannot contain surrounding whitespace")
    return value


def _finite_number(
    value: object,
    *,
    field_name: str,
    allow_none: bool = False,
) -> float | None:
    """Return a finite non-boolean number without coercing strings."""

    if value is None and allow_none:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{field_name} must be a finite real number")
    try:
        normalized = float(value)
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be a finite real number") from exc
    if not isfinite(normalized):
        raise ValueError(f"{field_name} must be a finite real number")
    return 0.0 if normalized == 0.0 else normalized


def _canonical_value(value: object) -> object:
    """Return a deterministic JSON-safe readiness fingerprint value."""

    if isinstance(value, CalculationModel):
        return _canonical_value(value.model_dump(mode="json", round_trip=True))
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise PressureReliefInputError(
                "pressure-relief fingerprint keys must be strings"
            )
        return {key: _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_canonical_value(item) for item in value]
    if isinstance(value, float):
        if not isfinite(value):
            raise PressureReliefInputError(
                "pressure-relief fingerprint cannot contain non-finite values"
            )
        return 0.0 if value == 0.0 else value
    if value is None or isinstance(value, (str, int, bool)):
        return value
    raise PressureReliefInputError(
        f"unsupported pressure-relief fingerprint value: {type(value).__name__}"
    )


def fingerprint_pressure_relief_readiness(value: object) -> str:
    """Return one lowercase SHA-256 over canonical UTF-8 JSON."""

    canonical = _canonical_value(value)
    try:
        payload = json.dumps(
            canonical,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as error:
        raise PressureReliefInputError(
            "pressure-relief fingerprint payload is invalid"
        ) from error
    return sha256(payload).hexdigest()


def _result_fingerprint_payload(
    values: Mapping[str, object],
) -> dict[str, object]:
    """Return the complete public result payload except its self-hash."""

    missing_fields = tuple(
        field_name
        for field_name in _RESULT_FINGERPRINT_FIELDS
        if field_name not in values
    )
    if missing_fields:
        raise PressureReliefInputError(
            "pressure-relief result fingerprint payload is incomplete"
        )
    return {
        field_name: values[field_name]
        for field_name in _RESULT_FINGERPRINT_FIELDS
    }


class PressureReliefScenarioKind(StrEnum):
    """Credible overpressure-scenario categories recorded by Step 103."""

    BLOCKED_OUTLET = "blocked_outlet"
    EXTERNAL_FIRE = "external_fire"
    THERMAL_EXPANSION = "thermal_expansion"
    CONTROL_FAILURE = "control_failure"
    UTILITY_FAILURE = "utility_failure"
    EXCHANGER_TUBE_RUPTURE = "exchanger_tube_rupture"
    RUNAWAY_REACTION = "runaway_reaction"
    DEPRESSURIZATION = "depressurization"
    OTHER_DOCUMENTED = "other_documented"


class PressureReliefFluidPhase(StrEnum):
    """Phase families reserved for separately reviewed Step 104 methods."""

    LIQUID = "liquid"
    GAS_VAPOUR = "gas_vapour"
    STEAM = "steam"


class PressureReliefPressureBasisKind(StrEnum):
    """Explicit pressure bases accepted by the readiness model."""

    ABSOLUTE = "absolute"
    GAUGE_WITH_ATMOSPHERIC_REFERENCE = "gauge_with_atmospheric_reference"


class PressureReliefStandardsFamily(StrEnum):
    """Initial standards families; the jurisdiction chooses the applicable one."""

    API_520_521 = "api_520_521"
    ISO_4126 = "iso_4126"
    JURISDICTION_SPECIFIC_OTHER = "jurisdiction_specific_other"


class PressureReliefReadinessFindingCode(StrEnum):
    """Stable ordering and public identity of Step 103 safety blocks."""

    MISSING_SCENARIO = "missing_credible_scenario"
    MISSING_FLOW_BASIS = "missing_required_flow_basis"
    MISSING_PRESSURE_BASIS = "missing_pressure_basis"
    MISSING_JURISDICTION = "missing_jurisdiction"
    MISSING_PROPERTIES = "missing_phase_properties"
    MISSING_COMPETENCY = "missing_review_competency"
    UNAPPROVED_METHOD = "no_approved_method"


class PressureReliefFlowBasis(CalculationModel):
    """Caller-supplied required relieving rate and its separate derivation record."""

    required_relieving_mass_flow_kg_s: float | None = None
    load_determination_reference: str | None = Field(
        default=None,
        min_length=3,
        max_length=500,
    )
    load_determination_basis: str | None = Field(
        default=None,
        min_length=10,
        max_length=1500,
    )
    supplied_by: str | None = Field(
        default=None,
        min_length=2,
        max_length=200,
    )

    @field_validator("required_relieving_mass_flow_kg_s", mode="before")
    @classmethod
    def validate_raw_rate(cls, value: object) -> float | None:
        return _finite_number(
            value,
            field_name="required relieving mass flow",
            allow_none=True,
        )

    @field_validator(
        "load_determination_reference",
        "load_determination_basis",
        "supplied_by",
        mode="before",
    )
    @classmethod
    def validate_raw_provenance(cls, value: object, info) -> str | None:
        return _strict_text(value, field_name=info.field_name, allow_none=True)

    @model_validator(mode="after")
    def validate_rate_domain(self) -> PressureReliefFlowBasis:
        value = self.required_relieving_mass_flow_kg_s
        if value is not None and (value <= 0.0 or value > _MAX_FLOW_KG_S):
            raise ValueError(
                "required relieving mass flow must be positive and bounded"
            )
        return self

    @property
    def is_complete(self) -> bool:
        """Return whether rate, derivation basis, source, and supplier exist."""

        return (
            self.required_relieving_mass_flow_kg_s is not None
            and self.load_determination_reference is not None
            and self.load_determination_basis is not None
            and self.supplied_by is not None
        )


class PressureReliefScenarioBasis(CalculationModel):
    """One selected and documented credible overpressure scenario."""

    scenario_id: str = Field(
        min_length=3,
        max_length=120,
        pattern=r"^[a-z0-9][a-z0-9._-]+$",
    )
    scenario_kind: PressureReliefScenarioKind
    title: str = Field(min_length=3, max_length=240)
    protected_equipment_reference: str = Field(min_length=2, max_length=240)
    scenario_description: str = Field(min_length=20, max_length=2500)
    credibility_confirmed: StrictBool = False
    credibility_basis_reference: str | None = Field(
        default=None,
        min_length=3,
        max_length=500,
    )
    flow_basis: PressureReliefFlowBasis | None = None

    @field_validator(
        "scenario_id",
        "title",
        "protected_equipment_reference",
        "scenario_description",
        "credibility_basis_reference",
        mode="before",
    )
    @classmethod
    def validate_raw_text(cls, value: object, info) -> str | None:
        return _strict_text(
            value,
            field_name=info.field_name,
            allow_none=info.field_name == "credibility_basis_reference",
        )

    @property
    def is_credible_and_documented(self) -> bool:
        """Return whether a competent workflow confirmed the scenario basis."""

        return self.credibility_confirmed and (
            self.credibility_basis_reference is not None
        )


class PressureReliefPressureBasis(CalculationModel):
    """Explicit set, MAWP, relieving, backpressure, and reference basis."""

    basis_kind: PressureReliefPressureBasisKind | None = None
    set_pressure_pa: float | None = None
    maximum_allowable_working_pressure_pa: float | None = None
    relieving_pressure_pa: float | None = None
    total_backpressure_pa: float | None = None
    atmospheric_pressure_absolute_pa: float | None = None
    pressure_source_reference: str | None = Field(
        default=None,
        min_length=3,
        max_length=500,
    )

    @field_validator(
        "set_pressure_pa",
        "maximum_allowable_working_pressure_pa",
        "relieving_pressure_pa",
        "total_backpressure_pa",
        "atmospheric_pressure_absolute_pa",
        mode="before",
    )
    @classmethod
    def validate_raw_pressures(cls, value: object, info) -> float | None:
        return _finite_number(value, field_name=info.field_name, allow_none=True)

    @field_validator("pressure_source_reference", mode="before")
    @classmethod
    def validate_raw_source(cls, value: object) -> str | None:
        return _strict_text(
            value,
            field_name="pressure_source_reference",
            allow_none=True,
        )

    @model_validator(mode="after")
    def validate_pressure_domain(self) -> PressureReliefPressureBasis:
        positive_fields = (
            self.set_pressure_pa,
            self.maximum_allowable_working_pressure_pa,
            self.relieving_pressure_pa,
            self.atmospheric_pressure_absolute_pa,
        )
        if any(
            value is not None and (value <= 0.0 or value > _MAX_PRESSURE_PA)
            for value in positive_fields
        ):
            raise ValueError("positive pressure values must be bounded")
        if self.total_backpressure_pa is not None and (
            self.total_backpressure_pa < 0.0
            or self.total_backpressure_pa > _MAX_PRESSURE_PA
        ):
            raise ValueError("total backpressure must be non-negative and bounded")
        if (
            self.basis_kind is PressureReliefPressureBasisKind.ABSOLUTE
            and self.atmospheric_pressure_absolute_pa is not None
        ):
            raise ValueError(
                "an absolute pressure basis cannot include a conversion atmosphere"
            )
        if (
            self.set_pressure_pa is not None
            and self.maximum_allowable_working_pressure_pa is not None
            and self.set_pressure_pa > self.maximum_allowable_working_pressure_pa
        ):
            raise ValueError("set pressure cannot exceed MAWP")
        if (
            self.relieving_pressure_pa is not None
            and self.set_pressure_pa is not None
            and self.relieving_pressure_pa < self.set_pressure_pa
        ):
            raise ValueError("relieving pressure cannot be below set pressure")
        if (
            self.total_backpressure_pa is not None
            and self.relieving_pressure_pa is not None
            and self.total_backpressure_pa >= self.relieving_pressure_pa
        ):
            raise ValueError(
                "total backpressure must be below relieving pressure"
            )
        return self

    @property
    def is_complete(self) -> bool:
        """Return whether the pressure basis is explicit and traceable."""

        values_complete = all(
            value is not None
            for value in (
                self.set_pressure_pa,
                self.maximum_allowable_working_pressure_pa,
                self.relieving_pressure_pa,
                self.total_backpressure_pa,
            )
        )
        gauge_reference_complete = (
            self.basis_kind
            is not PressureReliefPressureBasisKind.GAUGE_WITH_ATMOSPHERIC_REFERENCE
            or self.atmospheric_pressure_absolute_pa is not None
        )
        return (
            self.basis_kind is not None
            and values_complete
            and gauge_reference_complete
            and self.pressure_source_reference is not None
        )


class PressureReliefJurisdictionBasis(CalculationModel):
    """Authority, code, standard family, edition, and source selected by users."""

    jurisdiction_id: str | None = Field(
        default=None,
        min_length=2,
        max_length=120,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]+$",
    )
    authority_having_jurisdiction: str | None = Field(
        default=None,
        min_length=3,
        max_length=500,
    )
    applicable_design_code_reference: str | None = Field(
        default=None,
        min_length=3,
        max_length=500,
    )
    standards_family: PressureReliefStandardsFamily | None = None
    exact_edition_and_amendment_reference: str | None = Field(
        default=None,
        min_length=3,
        max_length=500,
    )
    jurisdiction_source_reference: str | None = Field(
        default=None,
        min_length=3,
        max_length=500,
    )

    @field_validator(
        "jurisdiction_id",
        "authority_having_jurisdiction",
        "applicable_design_code_reference",
        "exact_edition_and_amendment_reference",
        "jurisdiction_source_reference",
        mode="before",
    )
    @classmethod
    def validate_raw_text(cls, value: object, info) -> str | None:
        return _strict_text(value, field_name=info.field_name, allow_none=True)

    @property
    def is_complete(self) -> bool:
        """Return whether one explicit legal and standards basis is traceable."""

        return all(
            value is not None
            for value in (
                self.jurisdiction_id,
                self.authority_having_jurisdiction,
                self.applicable_design_code_reference,
                self.standards_family,
                self.exact_edition_and_amendment_reference,
                self.jurisdiction_source_reference,
            )
        )


class PressureReliefFluidProperties(CalculationModel):
    """Incomplete-safe phase properties reserved for reviewed sizing methods."""

    phase: PressureReliefFluidPhase | None = None
    relieving_temperature_k: float | None = None
    liquid_density_kg_m3: float | None = None
    gas_molar_mass_kg_kmol: float | None = None
    compressibility_factor: float | None = None
    isentropic_exponent: float | None = None
    steam_specific_volume_m3_kg: float | None = None
    dry_or_superheated_steam_confirmed: StrictBool | None = None
    property_source_reference: str | None = Field(
        default=None,
        min_length=3,
        max_length=500,
    )
    condition_basis: str | None = Field(
        default=None,
        min_length=10,
        max_length=1500,
    )

    @field_validator(
        "relieving_temperature_k",
        "liquid_density_kg_m3",
        "gas_molar_mass_kg_kmol",
        "compressibility_factor",
        "isentropic_exponent",
        "steam_specific_volume_m3_kg",
        mode="before",
    )
    @classmethod
    def validate_raw_properties(cls, value: object, info) -> float | None:
        return _finite_number(value, field_name=info.field_name, allow_none=True)

    @field_validator(
        "property_source_reference",
        "condition_basis",
        mode="before",
    )
    @classmethod
    def validate_raw_provenance(cls, value: object, info) -> str | None:
        return _strict_text(value, field_name=info.field_name, allow_none=True)

    @model_validator(mode="after")
    def validate_property_domain(self) -> PressureReliefFluidProperties:
        if self.relieving_temperature_k is not None and (
            self.relieving_temperature_k <= 0.0
            or self.relieving_temperature_k > _MAX_TEMPERATURE_K
        ):
            raise ValueError("relieving temperature must be positive and bounded")
        if self.liquid_density_kg_m3 is not None and (
            self.liquid_density_kg_m3 <= 0.0
            or self.liquid_density_kg_m3 > _MAX_DENSITY_KG_M3
        ):
            raise ValueError("liquid density must be positive and bounded")
        if self.gas_molar_mass_kg_kmol is not None and (
            self.gas_molar_mass_kg_kmol <= 0.0
            or self.gas_molar_mass_kg_kmol > _MAX_MOLAR_MASS_KG_KMOL
        ):
            raise ValueError("gas molar mass must be positive and bounded")
        if self.compressibility_factor is not None and (
            self.compressibility_factor <= 0.0
            or self.compressibility_factor > 10.0
        ):
            raise ValueError("compressibility factor must be in (0, 10]")
        if self.isentropic_exponent is not None and (
            self.isentropic_exponent <= 1.0 or self.isentropic_exponent > 10.0
        ):
            raise ValueError("isentropic exponent must be in (1, 10]")
        if self.steam_specific_volume_m3_kg is not None and (
            self.steam_specific_volume_m3_kg <= 0.0
            or self.steam_specific_volume_m3_kg > _MAX_SPECIFIC_VOLUME_M3_KG
        ):
            raise ValueError("steam specific volume must be positive and bounded")

        liquid_only = (self.liquid_density_kg_m3,)
        gas_only = (
            self.gas_molar_mass_kg_kmol,
            self.compressibility_factor,
            self.isentropic_exponent,
        )
        steam_only = (
            self.steam_specific_volume_m3_kg,
            self.dry_or_superheated_steam_confirmed,
        )
        if self.phase is PressureReliefFluidPhase.LIQUID and any(
            value is not None for value in (*gas_only, *steam_only)
        ):
            raise ValueError("liquid properties cannot include gas or steam fields")
        if self.phase is PressureReliefFluidPhase.GAS_VAPOUR and any(
            value is not None for value in (*liquid_only, *steam_only)
        ):
            raise ValueError("gas/vapour properties cannot include liquid or steam fields")
        if self.phase is PressureReliefFluidPhase.STEAM and any(
            value is not None for value in (*liquid_only, *gas_only)
        ):
            raise ValueError("steam properties cannot include liquid or gas fields")
        return self

    @property
    def is_complete(self) -> bool:
        """Return whether all Step 103 phase-dependent evidence is present."""

        common_complete = (
            self.phase is not None
            and self.relieving_temperature_k is not None
            and self.property_source_reference is not None
            and self.condition_basis is not None
        )
        if not common_complete:
            return False
        if self.phase is PressureReliefFluidPhase.LIQUID:
            return self.liquid_density_kg_m3 is not None
        if self.phase is PressureReliefFluidPhase.GAS_VAPOUR:
            return all(
                value is not None
                for value in (
                    self.gas_molar_mass_kg_kmol,
                    self.compressibility_factor,
                    self.isentropic_exponent,
                )
            )
        if self.phase is PressureReliefFluidPhase.STEAM:
            return (
                self.steam_specific_volume_m3_kg is not None
                and self.dry_or_superheated_steam_confirmed is True
            )
        return False


class PressureReliefCompetencyRequirement(CalculationModel):
    """Mandatory independent competency and remaining review activities."""

    requirement_id: Literal["pressure-relief.independent-review"] = (
        "pressure-relief.independent-review"
    )
    required_reviewer_competency: Literal[
        "Independent competent pressure-systems engineer"
    ] = PRESSURE_RELIEF_REQUIRED_REVIEWER_COMPETENCY
    independent_review_required: Literal[True] = True
    jurisdiction_review_required: Literal[True] = True
    site_and_installation_review_required: Literal[True] = True
    manufacturer_review_required: Literal[True] = True
    required_checks: tuple[str, ...] = (
        "Confirm the credible overpressure scenario and required relieving rate.",
        "Confirm the jurisdiction, design code, exact standards edition, and amendments.",
        "Confirm equipment MAWP, pressure basis, inlet loss, and backpressure.",
        "Confirm fluid properties at the relieving condition and disposal-system limits.",
        "Approve the final device, materials, installation, testing, and documentation.",
    )


PRESSURE_RELIEF_COMPETENCY_REQUIREMENT: Final = (
    PressureReliefCompetencyRequirement()
)


class PressureReliefStandardsPackMetadata(CalculationModel):
    """Discoverable but non-executable standards-family lifecycle record."""

    pack_id: str = Field(
        min_length=3,
        max_length=160,
        pattern=r"^[a-z0-9][a-z0-9.-]+$",
    )
    pack_version: Literal["1.0.0"] = PRESSURE_RELIEF_STANDARDS_PACK_VERSION
    title: str = Field(min_length=3, max_length=240)
    standards_family: PressureReliefStandardsFamily
    official_catalog_urls: tuple[str, ...] = Field(min_length=1, max_length=4)
    lifecycle_status: Literal[MethodLifecycleStatus.STANDARDS_REVIEW] = (
        MethodLifecycleStatus.STANDARDS_REVIEW
    )
    executable: Literal[False] = False
    conformity_claimed: Literal[False] = False
    protected_content_embedded: Literal[False] = False
    exact_edition_selection_required: Literal[True] = True
    independent_review_required: Literal[True] = True
    boundary: str = Field(min_length=20, max_length=1500)

    @field_validator("pack_id", "title", "boundary", mode="before")
    @classmethod
    def validate_raw_text(cls, value: object, info) -> str:
        validated = _strict_text(value, field_name=info.field_name)
        if validated is None:  # pragma: no cover - non-optional field
            raise ValueError(f"{info.field_name} is required")
        return validated

    @field_validator("official_catalog_urls", mode="before")
    @classmethod
    def validate_raw_urls(cls, value: object) -> object:
        if isinstance(value, list):
            value = tuple(value)
        if not isinstance(value, tuple):
            raise TypeError("official_catalog_urls must be an ordered collection")
        normalized: list[str] = []
        for item in value:
            validated = _strict_text(item, field_name="official_catalog_url")
            if validated is None or not validated.startswith("https://"):
                raise ValueError("official catalog URLs must use https")
            normalized.append(validated)
        if len(normalized) != len(set(normalized)):
            raise ValueError("official catalog URLs must be unique")
        return tuple(normalized)


API_520_521_STANDARDS_PACK: Final = PressureReliefStandardsPackMetadata(
    pack_id=API_520_521_STANDARDS_PACK_ID,
    title="API 520/521 pressure-relief standards discovery pack",
    standards_family=PressureReliefStandardsFamily.API_520_521,
    official_catalog_urls=(
        "https://www.api.org/products-and-services/standards/important-standards-announcements/520parti",
        "https://www.api.org/products-and-services/standards/important-standards-announcements/520part-ii",
        "https://www.api.org/products-and-services/standards/important-standards-announcements/standard521",
    ),
    boundary=(
        "Catalogue metadata only. The jurisdiction, exact edition and amendments, "
        "licensed equations, correction factors, reference vectors, installation "
        "rules, and reviewer approvals are not executable in Step 103."
    ),
)

ISO_4126_STANDARDS_PACK: Final = PressureReliefStandardsPackMetadata(
    pack_id=ISO_4126_STANDARDS_PACK_ID,
    title="ISO 4126 pressure-relief standards discovery pack",
    standards_family=PressureReliefStandardsFamily.ISO_4126,
    official_catalog_urls=("https://www.iso.org/standard/50826.html",),
    boundary=(
        "Catalogue metadata only. Product-standard metadata does not approve an "
        "application or sizing method; exact jurisdiction, edition, amendments, "
        "licensed implementation, vectors, and reviewer approvals remain required."
    ),
)

PRESSURE_RELIEF_DISCOVERY_ENTRIES: Final = (
    API_520_521_STANDARDS_PACK,
    ISO_4126_STANDARDS_PACK,
)
PRESSURE_RELIEF_STANDARDS_PACK_REGISTRY: Final = MappingProxyType(
    {
        (entry.pack_id, entry.pack_version): entry
        for entry in PRESSURE_RELIEF_DISCOVERY_ENTRIES
    }
)
if len(PRESSURE_RELIEF_STANDARDS_PACK_REGISTRY) != len(
    PRESSURE_RELIEF_DISCOVERY_ENTRIES
):
    raise RuntimeError("duplicate exact-version pressure-relief standards pack")

PRESSURE_RELIEF_EXECUTABLE_ADAPTERS: Final = ()
PRESSURE_RELIEF_METHOD_REGISTRY: Final = MappingProxyType({})
PRESSURE_RELIEF_METHOD_IMPLEMENTATIONS: Final = MappingProxyType({})


class PressureReliefReadinessRequest(CalculationModel):
    """Incomplete-safe request evaluated before any future sizing method."""

    request_id: str = Field(
        min_length=3,
        max_length=120,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]+$",
    )
    scenarios: tuple[PressureReliefScenarioBasis, ...] = Field(
        default_factory=tuple,
        max_length=16,
    )
    pressure_basis: PressureReliefPressureBasis | None = None
    jurisdiction_basis: PressureReliefJurisdictionBasis | None = None
    fluid_properties: PressureReliefFluidProperties | None = None
    selected_standards_pack_id: str | None = Field(
        default=None,
        min_length=3,
        max_length=160,
        pattern=r"^[a-z0-9][a-z0-9.-]+$",
    )
    selected_standards_pack_version: str | None = Field(
        default=None,
        pattern=r"^\d+\.\d+\.\d+$",
        max_length=32,
    )
    competency_requirement_acknowledged: StrictBool = False
    proposed_reviewer_evidence_reference: str | None = Field(
        default=None,
        min_length=3,
        max_length=500,
    )

    @field_validator(
        "request_id",
        "selected_standards_pack_id",
        "selected_standards_pack_version",
        "proposed_reviewer_evidence_reference",
        mode="before",
    )
    @classmethod
    def validate_raw_text(cls, value: object, info) -> str | None:
        return _strict_text(
            value,
            field_name=info.field_name,
            allow_none=info.field_name != "request_id",
        )

    @model_validator(mode="after")
    def validate_request_identity(self) -> PressureReliefReadinessRequest:
        scenario_ids = [scenario.scenario_id.casefold() for scenario in self.scenarios]
        if len(scenario_ids) != len(set(scenario_ids)):
            raise ValueError("scenario IDs must be unique")
        protected_equipment_references = {
            scenario.protected_equipment_reference.casefold()
            for scenario in self.scenarios
        }
        if len(protected_equipment_references) > 1:
            raise ValueError(
                "all scenarios in one readiness request must reference the "
                "same protected equipment"
            )
        if (self.selected_standards_pack_id is None) != (
            self.selected_standards_pack_version is None
        ):
            raise ValueError(
                "standards pack ID and version must be supplied together"
            )
        selected_pack = None
        if (
            self.selected_standards_pack_id is not None
            and self.selected_standards_pack_version is not None
        ):
            selected_pack = PRESSURE_RELIEF_STANDARDS_PACK_REGISTRY.get(
                (
                    self.selected_standards_pack_id,
                    self.selected_standards_pack_version,
                )
            )
            if selected_pack is None:
                raise ValueError(
                    "selected standards pack ID and version must resolve exactly"
                )
        if (
            selected_pack is not None
            and self.jurisdiction_basis is not None
            and self.jurisdiction_basis.standards_family is not None
            and selected_pack.standards_family
            is not self.jurisdiction_basis.standards_family
        ):
            raise ValueError(
                "selected standards pack must match the jurisdiction standards family"
            )
        if (
            self.competency_requirement_acknowledged is False
            and self.proposed_reviewer_evidence_reference is not None
        ):
            raise ValueError(
                "reviewer evidence requires competency acknowledgement"
            )
        return self


class PressureReliefSafetyFinding(CalculationModel):
    """One deterministic critical finding that prevents sizing execution."""

    finding_id: str = Field(
        min_length=3,
        max_length=160,
        pattern=r"^[a-z0-9][a-z0-9.-]+$",
    )
    code: PressureReliefReadinessFindingCode
    severity: Literal[FindingSeverity.CRITICAL] = FindingSeverity.CRITICAL
    blocking: Literal[True] = True
    title: str = Field(min_length=3, max_length=240)
    detail: str = Field(min_length=10, max_length=1500)
    required_action: str = Field(min_length=10, max_length=1500)


class PressureReliefSafetyGateResult(CalculationModel):
    """Preliminary, non-numerical result of the Step 103 readiness gate."""

    foundation_version: Literal["1.0.0"] = PRESSURE_RELIEF_FOUNDATION_VERSION
    fingerprint_schema: Literal[
        "engineer4me.pressure-relief.readiness.v1"
    ] = _FINGERPRINT_SCHEMA
    request_id: str = Field(
        min_length=3,
        max_length=120,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]+$",
    )
    request_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal[CalculationStatus.BLOCKED] = CalculationStatus.BLOCKED
    blocking_findings: tuple[PressureReliefSafetyFinding, ...] = Field(
        min_length=1,
        max_length=16,
    )
    competency_requirement: PressureReliefCompetencyRequirement = (
        PRESSURE_RELIEF_COMPETENCY_REQUIREMENT
    )
    ready_for_sizing: Literal[False] = False
    calculation_performed: Literal[False] = False
    device_selected: Literal[False] = False
    standards_conformity_claimed: Literal[False] = False
    preliminary_engineering_decision_support: Literal[True] = True
    independent_review_required: Literal[True] = True
    required_reviewer_competency: Literal[
        "Independent competent pressure-systems engineer"
    ] = PRESSURE_RELIEF_REQUIRED_REVIEWER_COMPETENCY
    result_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("request_id", mode="before")
    @classmethod
    def validate_raw_request_id(cls, value: object) -> str:
        validated = _strict_text(value, field_name="request_id")
        if validated is None:  # pragma: no cover - non-optional field
            raise ValueError("request_id is required")
        return validated

    @model_validator(mode="after")
    def validate_result_integrity(self) -> PressureReliefSafetyGateResult:
        if self.competency_requirement != PRESSURE_RELIEF_COMPETENCY_REQUIREMENT:
            raise ValueError(
                "pressure-relief competency requirement must remain exact"
            )
        values = self.model_dump(mode="python", round_trip=True)
        expected_fingerprint = fingerprint_pressure_relief_readiness(
            _result_fingerprint_payload(values)
        )
        if self.result_fingerprint != expected_fingerprint:
            raise ValueError("pressure-relief result fingerprint is inconsistent")
        return self


if tuple(
    field_name
    for field_name in PressureReliefSafetyGateResult.model_fields
    if field_name != "result_fingerprint"
) != _RESULT_FINGERPRINT_FIELDS:
    raise RuntimeError("pressure-relief result fingerprint fields are incomplete")


def _finding(
    *,
    finding_id: str,
    code: PressureReliefReadinessFindingCode,
    title: str,
    detail: str,
    required_action: str,
) -> PressureReliefSafetyFinding:
    """Build one internally controlled critical blocking finding."""

    return PressureReliefSafetyFinding(
        finding_id=finding_id,
        code=code,
        title=title,
        detail=detail,
        required_action=required_action,
    )


def _revalidate_request(value: object) -> PressureReliefReadinessRequest:
    """Revalidate an immutable model at the public readiness boundary."""

    if not isinstance(value, PressureReliefReadinessRequest):
        raise PressureReliefInputError(
            "PressureReliefReadinessRequest input is required"
        )
    try:
        return PressureReliefReadinessRequest.model_validate(
            value.model_dump(mode="python", round_trip=True)
        )
    except Exception as error:
        raise PressureReliefInputError(
            "PressureReliefReadinessRequest failed validation"
        ) from error


def assess_pressure_relief_readiness(
    request: PressureReliefReadinessRequest,
) -> PressureReliefSafetyGateResult:
    """Return every applicable block without running a sizing calculation."""

    normalized = _revalidate_request(request)
    findings: list[PressureReliefSafetyFinding] = []

    if not normalized.scenarios or any(
        not scenario.is_credible_and_documented
        for scenario in normalized.scenarios
    ):
        findings.append(
            _finding(
                finding_id=PRESSURE_RELIEF_MISSING_SCENARIO_FINDING_ID,
                code=PressureReliefReadinessFindingCode.MISSING_SCENARIO,
                title="Credible overpressure scenario is not established",
                detail=(
                    "Every assessed case requires a selected, documented, and "
                    "explicitly confirmed credible overpressure scenario."
                ),
                required_action=(
                    "Have an authorised engineering workflow document and confirm "
                    "the credible scenario before sizing."
                ),
            )
        )

    if not normalized.scenarios or any(
        scenario.flow_basis is None or not scenario.flow_basis.is_complete
        for scenario in normalized.scenarios
    ):
        findings.append(
            _finding(
                finding_id=PRESSURE_RELIEF_MISSING_FLOW_BASIS_FINDING_ID,
                code=PressureReliefReadinessFindingCode.MISSING_FLOW_BASIS,
                title="Required relieving rate is not traceably supplied",
                detail=(
                    "Step 103 never determines a relief load. Every scenario must "
                    "carry a positive required mass flow and its derivation record."
                ),
                required_action=(
                    "Supply an independently reviewed required relieving rate, "
                    "load-determination basis, source, and responsible supplier."
                ),
            )
        )

    if normalized.pressure_basis is None or not normalized.pressure_basis.is_complete:
        findings.append(
            _finding(
                finding_id=PRESSURE_RELIEF_MISSING_PRESSURE_BASIS_FINDING_ID,
                code=PressureReliefReadinessFindingCode.MISSING_PRESSURE_BASIS,
                title="Pressure basis is incomplete",
                detail=(
                    "Set pressure, MAWP, relieving pressure, backpressure, pressure "
                    "basis, any gauge-reference atmosphere, and source are required."
                ),
                required_action=(
                    "Confirm the complete pressure state and absolute or explicit "
                    "gauge-to-absolute basis with traceable project evidence."
                ),
            )
        )

    if (
        normalized.jurisdiction_basis is None
        or not normalized.jurisdiction_basis.is_complete
    ):
        findings.append(
            _finding(
                finding_id=PRESSURE_RELIEF_MISSING_JURISDICTION_FINDING_ID,
                code=PressureReliefReadinessFindingCode.MISSING_JURISDICTION,
                title="Jurisdiction and exact standards basis are incomplete",
                detail=(
                    "The authority, design code, standards family, exact edition and "
                    "amendments, and source must be selected explicitly."
                ),
                required_action=(
                    "Obtain the jurisdictional and owner code basis and record the "
                    "exact legally usable standards references."
                ),
            )
        )

    if normalized.fluid_properties is None or not normalized.fluid_properties.is_complete:
        findings.append(
            _finding(
                finding_id=PRESSURE_RELIEF_MISSING_PROPERTIES_FINDING_ID,
                code=PressureReliefReadinessFindingCode.MISSING_PROPERTIES,
                title="Relieving-condition fluid properties are incomplete",
                detail=(
                    "The selected liquid, gas/vapour, or eligible-steam method needs "
                    "phase-specific properties and a traceable relieving-condition basis."
                ),
                required_action=(
                    "Supply the complete phase-dependent property set from a reviewed "
                    "source at the relieving condition."
                ),
            )
        )

    if (
        normalized.competency_requirement_acknowledged is False
        or normalized.proposed_reviewer_evidence_reference is None
    ):
        findings.append(
            _finding(
                finding_id=PRESSURE_RELIEF_MISSING_COMPETENCY_FINDING_ID,
                code=PressureReliefReadinessFindingCode.MISSING_COMPETENCY,
                title="Independent pressure-systems competency is not evidenced",
                detail=(
                    "All pressure-relief work remains preliminary and requires an "
                    "independent competent pressure-systems engineer."
                ),
                required_action=(
                    "Identify the competent independent reviewer and record the "
                    "project evidence for their authorised review."
                ),
            )
        )

    selected_pack = None
    if (
        normalized.selected_standards_pack_id is not None
        and normalized.selected_standards_pack_version is not None
    ):
        selected_pack = PRESSURE_RELIEF_STANDARDS_PACK_REGISTRY.get(
            (
                normalized.selected_standards_pack_id,
                normalized.selected_standards_pack_version,
            )
        )
    lifecycle = (
        None if selected_pack is None else selected_pack.lifecycle_status
    )
    findings.append(
        _finding(
            finding_id=PRESSURE_RELIEF_UNAPPROVED_METHOD_FINDING_ID,
            code=PressureReliefReadinessFindingCode.UNAPPROVED_METHOD,
            title="No approved pressure-relief sizing method is executable",
            detail=(
                "Step 103 contains only inert standards discovery metadata. "
                f"Selected lifecycle: {getattr(lifecycle, 'value', 'unresolved')}."
            ),
            required_action=(
                "Complete the technical, safety, standards, reference-vector, and "
                "final approval gates in the separately reviewed sizing step."
            ),
        )
    )

    request_payload = {
        "schema": _FINGERPRINT_SCHEMA,
        "foundation_version": PRESSURE_RELIEF_FOUNDATION_VERSION,
        "request": normalized,
    }
    request_fingerprint = fingerprint_pressure_relief_readiness(request_payload)
    result_values: dict[str, object] = {
        "foundation_version": PRESSURE_RELIEF_FOUNDATION_VERSION,
        "fingerprint_schema": _FINGERPRINT_SCHEMA,
        "request_id": normalized.request_id,
        "request_fingerprint": request_fingerprint,
        "status": CalculationStatus.BLOCKED,
        "blocking_findings": tuple(findings),
        "competency_requirement": PRESSURE_RELIEF_COMPETENCY_REQUIREMENT,
        "ready_for_sizing": False,
        "calculation_performed": False,
        "device_selected": False,
        "standards_conformity_claimed": False,
        "preliminary_engineering_decision_support": True,
        "independent_review_required": True,
        "required_reviewer_competency": (
            PRESSURE_RELIEF_REQUIRED_REVIEWER_COMPETENCY
        ),
    }
    result_fingerprint = fingerprint_pressure_relief_readiness(
        _result_fingerprint_payload(result_values)
    )
    return PressureReliefSafetyGateResult(
        **result_values,
        result_fingerprint=result_fingerprint,
    )


__all__ = [
    "API_520_521_STANDARDS_PACK",
    "API_520_521_STANDARDS_PACK_ID",
    "ISO_4126_STANDARDS_PACK",
    "ISO_4126_STANDARDS_PACK_ID",
    "PRESSURE_RELIEF_COMPETENCY_REQUIREMENT",
    "PRESSURE_RELIEF_DISCOVERY_ENTRIES",
    "PRESSURE_RELIEF_EXECUTABLE_ADAPTERS",
    "PRESSURE_RELIEF_FOUNDATION_VERSION",
    "PRESSURE_RELIEF_METHOD_IMPLEMENTATIONS",
    "PRESSURE_RELIEF_METHOD_REGISTRY",
    "PRESSURE_RELIEF_MISSING_COMPETENCY_FINDING_ID",
    "PRESSURE_RELIEF_MISSING_FLOW_BASIS_FINDING_ID",
    "PRESSURE_RELIEF_MISSING_JURISDICTION_FINDING_ID",
    "PRESSURE_RELIEF_MISSING_PRESSURE_BASIS_FINDING_ID",
    "PRESSURE_RELIEF_MISSING_PROPERTIES_FINDING_ID",
    "PRESSURE_RELIEF_MISSING_SCENARIO_FINDING_ID",
    "PRESSURE_RELIEF_REQUIRED_REVIEWER_COMPETENCY",
    "PRESSURE_RELIEF_STANDARDS_PACK_REGISTRY",
    "PRESSURE_RELIEF_STANDARDS_PACK_VERSION",
    "PRESSURE_RELIEF_UNAPPROVED_METHOD_FINDING_ID",
    "PressureReliefCompetencyRequirement",
    "PressureReliefError",
    "PressureReliefFlowBasis",
    "PressureReliefFluidPhase",
    "PressureReliefFluidProperties",
    "PressureReliefInputError",
    "PressureReliefJurisdictionBasis",
    "PressureReliefPressureBasis",
    "PressureReliefPressureBasisKind",
    "PressureReliefReadinessFindingCode",
    "PressureReliefReadinessRequest",
    "PressureReliefSafetyFinding",
    "PressureReliefSafetyGateResult",
    "PressureReliefScenarioBasis",
    "PressureReliefScenarioKind",
    "PressureReliefStandardsFamily",
    "PressureReliefStandardsPackMetadata",
    "assess_pressure_relief_readiness",
    "fingerprint_pressure_relief_readiness",
]

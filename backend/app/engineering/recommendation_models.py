"""Data models for the Engineer4Me engineering recommendation engine.

These models define the input requirements, individual engineering rule
results, safety findings, product evaluations, ranked recommendations, and
overall response returned by the Phase 3 recommendation engine.
"""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RequirementImportance(StrEnum):
    """Defines whether an engineering requirement is mandatory or preferred."""

    MANDATORY = "mandatory"
    PREFERRED = "preferred"


class RuleCategory(StrEnum):
    """Supported engineering rule categories."""

    PROCESS_TEMPERATURE = "process_temperature"
    PROCESS_PRESSURE = "process_pressure"
    AMBIENT_TEMPERATURE = "ambient_temperature"
    ACCURACY = "accuracy"
    INGRESS_PROTECTION = "ingress_protection"
    HAZARDOUS_AREA = "hazardous_area"
    WETTED_MATERIAL = "wetted_material"
    PROCESS_CONNECTION = "process_connection"
    COMMUNICATION_PROTOCOL = "communication_protocol"
    DATA_COMPLETENESS = "data_completeness"
    GENERAL_SAFETY = "general_safety"


class RuleStatus(StrEnum):
    """Outcome of an individual engineering rule evaluation."""

    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    NOT_EVALUATED = "not_evaluated"


class SafetySeverity(StrEnum):
    """Severity level assigned to a safety finding."""

    INFORMATION = "information"
    CAUTION = "caution"
    WARNING = "warning"
    CRITICAL = "critical"


class RecommendationStatus(StrEnum):
    """Overall engineering suitability assigned to a product."""

    RECOMMENDED = "recommended"
    CONDITIONALLY_RECOMMENDED = "conditionally_recommended"
    NOT_RECOMMENDED = "not_recommended"
    INSUFFICIENT_INFORMATION = "insufficient_information"


class EngineeringRequirements(BaseModel):
    """Engineering and operating requirements supplied by the user.

    Mandatory requirements may disqualify a product when they fail.
    Preferred requirements contribute to ranking but do not necessarily
    disqualify a product.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    measurement_type: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        description="Required measurement or instrument type.",
    )

    process_temperature_c: float | None = Field(
        default=None,
        ge=-273.15,
        description="Normal or maximum expected process temperature in °C.",
    )
    process_temperature_importance: RequirementImportance = (
        RequirementImportance.MANDATORY
    )

    process_pressure_bar: float | None = Field(
        default=None,
        description="Normal or maximum expected process pressure in bar.",
    )
    process_pressure_importance: RequirementImportance = (
        RequirementImportance.MANDATORY
    )

    ambient_temperature_c: float | None = Field(
        default=None,
        ge=-273.15,
        description="Expected ambient temperature in °C.",
    )
    ambient_temperature_importance: RequirementImportance = (
        RequirementImportance.MANDATORY
    )

    required_accuracy_percent: float | None = Field(
        default=None,
        gt=0,
        description=(
            "Maximum acceptable accuracy error as a percentage. "
            "Lower values represent stricter requirements."
        ),
    )
    accuracy_importance: RequirementImportance = RequirementImportance.PREFERRED

    required_ingress_protection_rating: str | None = Field(
        default=None,
        min_length=2,
        max_length=20,
        description="Required ingress protection rating, for example IP66.",
    )
    ingress_protection_importance: RequirementImportance = (
        RequirementImportance.MANDATORY
    )

    hazardous_area_required: bool = Field(
        default=False,
        description="Whether certified hazardous-area equipment is required.",
    )
    required_hazardous_area_approvals: list[str] = Field(
        default_factory=list,
        description="Required approvals or protection concepts.",
    )
    hazardous_area_importance: RequirementImportance = (
        RequirementImportance.MANDATORY
    )

    process_medium: str | None = Field(
        default=None,
        min_length=1,
        max_length=150,
        description="Process fluid, gas, slurry, chemical, or other medium.",
    )
    required_wetted_materials: list[str] = Field(
        default_factory=list,
        description="Acceptable or specifically required wetted materials.",
    )
    wetted_material_importance: RequirementImportance = (
        RequirementImportance.MANDATORY
    )

    required_process_connections: list[str] = Field(
        default_factory=list,
        description="Acceptable process connection types or sizes.",
    )
    process_connection_importance: RequirementImportance = (
        RequirementImportance.PREFERRED
    )

    required_protocols: list[str] = Field(
        default_factory=list,
        description="Acceptable communication protocols.",
    )
    communication_protocol_importance: RequirementImportance = (
        RequirementImportance.PREFERRED
    )

    installation_environment: list[str] = Field(
        default_factory=list,
        description=(
            "Environmental conditions such as corrosive atmosphere, "
            "high vibration, dust, humidity, altitude, UV exposure, "
            "washdown, or marine service."
        ),
    )

    application_notes: str | None = Field(
        default=None,
        max_length=2000,
        description="Additional application or installation information.",
    )

    @model_validator(mode="after")
    def validate_hazardous_area_requirements(self) -> "EngineeringRequirements":
        """Prevent contradictory hazardous-area input."""

        if (
            self.required_hazardous_area_approvals
            and not self.hazardous_area_required
        ):
            raise ValueError(
                "hazardous_area_required must be true when hazardous-area "
                "approvals are specified."
            )

        return self


class RuleEvaluation(BaseModel):
    """Result of evaluating one engineering rule against one product."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    rule_code: str = Field(min_length=1, max_length=100)
    category: RuleCategory
    title: str = Field(min_length=1, max_length=200)
    status: RuleStatus
    importance: RequirementImportance

    requirement_value: Any | None = None
    product_value: Any | None = None

    explanation: str = Field(min_length=1, max_length=2000)
    engineering_reference: str | None = Field(
        default=None,
        max_length=500,
        description="Rule, standard, source, or evidence reference.",
    )

    score_awarded: float = Field(default=0.0, ge=0.0)
    maximum_score: float = Field(default=0.0, ge=0.0)

    @model_validator(mode="after")
    def validate_rule_score(self) -> "RuleEvaluation":
        """Ensure a rule cannot award more than its maximum score."""

        if self.score_awarded > self.maximum_score:
            raise ValueError(
                "score_awarded cannot be greater than maximum_score."
            )

        return self


class SafetyFinding(BaseModel):
    """Safety warning or consideration identified during evaluation."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    code: str = Field(min_length=1, max_length=100)
    severity: SafetySeverity
    title: str = Field(min_length=1, max_length=200)
    message: str = Field(min_length=1, max_length=2000)

    required_action: str | None = Field(default=None, max_length=2000)
    verification_step: str | None = Field(default=None, max_length=2000)
    reference: str | None = Field(default=None, max_length=500)

    blocks_recommendation: bool = Field(
        default=False,
        description=(
            "Whether the safety finding prevents the product from being "
            "recommended."
        ),
    )


class ProductEvaluation(BaseModel):
    """Complete evaluation of a single product."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    product_id: int = Field(gt=0)
    manufacturer_name: str | None = Field(default=None, max_length=150)
    product_name: str = Field(min_length=1, max_length=200)
    model_number: str | None = Field(default=None, max_length=150)

    status: RecommendationStatus
    suitability_score: float = Field(ge=0.0, le=100.0)
    confidence_score: float = Field(ge=0.0, le=100.0)

    mandatory_rules_passed: int = Field(default=0, ge=0)
    mandatory_rules_failed: int = Field(default=0, ge=0)
    preferred_rules_passed: int = Field(default=0, ge=0)
    preferred_rules_failed: int = Field(default=0, ge=0)

    rule_evaluations: list[RuleEvaluation] = Field(default_factory=list)
    safety_findings: list[SafetyFinding] = Field(default_factory=list)

    recommendation_reasons: list[str] = Field(default_factory=list)
    rejection_reasons: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_recommendation_status(self) -> "ProductEvaluation":
        """Ensure failed mandatory rules cannot produce a recommendation."""

        if (
            self.mandatory_rules_failed > 0
            and self.status
            in {
                RecommendationStatus.RECOMMENDED,
                RecommendationStatus.CONDITIONALLY_RECOMMENDED,
            }
        ):
            raise ValueError(
                "A product with failed mandatory rules cannot be recommended."
            )

        if (
            any(finding.blocks_recommendation for finding in self.safety_findings)
            and self.status
            in {
                RecommendationStatus.RECOMMENDED,
                RecommendationStatus.CONDITIONALLY_RECOMMENDED,
            }
        ):
            raise ValueError(
                "A product with a blocking safety finding cannot be recommended."
            )

        return self


class RankedRecommendation(BaseModel):
    """A product evaluation together with its recommendation position."""

    model_config = ConfigDict(extra="forbid")

    rank: int = Field(gt=0)
    evaluation: ProductEvaluation


class RecommendationSummary(BaseModel):
    """Summary statistics for an engineering recommendation request."""

    model_config = ConfigDict(extra="forbid")

    products_evaluated: int = Field(default=0, ge=0)
    products_recommended: int = Field(default=0, ge=0)
    products_conditionally_recommended: int = Field(default=0, ge=0)
    products_not_recommended: int = Field(default=0, ge=0)
    products_with_insufficient_information: int = Field(default=0, ge=0)


class EngineeringRecommendationResponse(BaseModel):
    """Final explainable response returned by the recommendation engine."""

    model_config = ConfigDict(extra="forbid")

    requirements: EngineeringRequirements
    summary: RecommendationSummary

    recommendations: list[RankedRecommendation] = Field(default_factory=list)
    excluded_products: list[ProductEvaluation] = Field(default_factory=list)

    general_safety_findings: list[SafetyFinding] = Field(default_factory=list)
    missing_request_information: list[str] = Field(default_factory=list)

    disclaimer: str = Field(
        default=(
            "Engineer4Me provides engineering decision support and does not "
            "replace site-specific risk assessments, applicable legislation, "
            "manufacturer documentation, certified engineering review, or "
            "authorised plant safety procedures."
        )
    )
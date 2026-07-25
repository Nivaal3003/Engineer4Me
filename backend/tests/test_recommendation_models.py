"""Tests for the Phase 3 engineering recommendation data models."""

import pytest
from pydantic import ValidationError

from app.engineering.recommendation_models import (
    EngineeringRecommendationResponse,
    EngineeringRequirements,
    ProductEvaluation,
    RankedRecommendation,
    RecommendationStatus,
    RecommendationSummary,
    RequirementImportance,
    RuleCategory,
    RuleEvaluation,
    RuleStatus,
    SafetyFinding,
    SafetySeverity,
)


def test_engineering_requirements_use_safe_defaults() -> None:
    """Default requirements should be valid and safety-oriented."""

    requirements = EngineeringRequirements()

    assert requirements.hazardous_area_required is False
    assert requirements.required_hazardous_area_approvals == []
    assert requirements.required_wetted_materials == []
    assert requirements.required_process_connections == []
    assert requirements.required_protocols == []
    assert requirements.installation_environment == []

    assert (
        requirements.process_temperature_importance
        == RequirementImportance.MANDATORY
    )
    assert (
        requirements.process_pressure_importance
        == RequirementImportance.MANDATORY
    )
    assert (
        requirements.hazardous_area_importance
        == RequirementImportance.MANDATORY
    )


def test_engineering_requirements_accept_complete_input() -> None:
    """A complete engineering request should validate successfully."""

    requirements = EngineeringRequirements(
        measurement_type="pressure",
        process_temperature_c=120.0,
        process_pressure_bar=40.0,
        ambient_temperature_c=45.0,
        required_accuracy_percent=0.1,
        required_ingress_protection_rating="IP66",
        hazardous_area_required=True,
        required_hazardous_area_approvals=["ATEX", "IECEx"],
        process_medium="Hydrochloric acid",
        required_wetted_materials=["Hastelloy C-276"],
        required_process_connections=["1/2 NPT"],
        required_protocols=["HART"],
        installation_environment=[
            "corrosive atmosphere",
            "outdoor installation",
        ],
        application_notes="Installed near an acid storage vessel.",
    )

    assert requirements.measurement_type == "pressure"
    assert requirements.process_temperature_c == 120.0
    assert requirements.process_pressure_bar == 40.0
    assert requirements.hazardous_area_required is True
    assert requirements.required_hazardous_area_approvals == [
        "ATEX",
        "IECEx",
    ]
    assert requirements.required_protocols == ["HART"]


def test_hazardous_approvals_require_hazardous_area_flag() -> None:
    """Approvals must not be supplied while hazardous-area use is false."""

    with pytest.raises(
        ValidationError,
        match="hazardous_area_required must be true",
    ):
        EngineeringRequirements(
            hazardous_area_required=False,
            required_hazardous_area_approvals=["IECEx"],
        )


def test_engineering_requirements_reject_unknown_fields() -> None:
    """Unexpected fields should be rejected to prevent silent input errors."""

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        EngineeringRequirements(
            measurement_type="temperature",
            unsupported_requirement="example",
        )


def test_engineering_requirements_reject_impossible_temperature() -> None:
    """Temperatures below absolute zero must be rejected."""

    with pytest.raises(ValidationError):
        EngineeringRequirements(process_temperature_c=-274.0)


def test_rule_evaluation_accepts_valid_score() -> None:
    """A rule may award a score up to its configured maximum."""

    result = RuleEvaluation(
        rule_code="PROCESS_TEMP_001",
        category=RuleCategory.PROCESS_TEMPERATURE,
        title="Process temperature suitability",
        status=RuleStatus.PASSED,
        importance=RequirementImportance.MANDATORY,
        requirement_value=120.0,
        product_value={
            "minimum_process_temperature_c": -40.0,
            "maximum_process_temperature_c": 200.0,
        },
        explanation="The required process temperature is within product limits.",
        score_awarded=20.0,
        maximum_score=20.0,
    )

    assert result.status == RuleStatus.PASSED
    assert result.score_awarded == 20.0
    assert result.maximum_score == 20.0


def test_rule_evaluation_rejects_score_above_maximum() -> None:
    """A rule must never award more than its maximum score."""

    with pytest.raises(
        ValidationError,
        match="score_awarded cannot be greater than maximum_score",
    ):
        RuleEvaluation(
            rule_code="ACCURACY_001",
            category=RuleCategory.ACCURACY,
            title="Accuracy suitability",
            status=RuleStatus.PASSED,
            importance=RequirementImportance.PREFERRED,
            explanation="Product accuracy meets the requested accuracy.",
            score_awarded=15.0,
            maximum_score=10.0,
        )


def test_product_with_failed_mandatory_rule_cannot_be_recommended() -> None:
    """Mandatory engineering failures must block recommendation."""

    with pytest.raises(
        ValidationError,
        match="failed mandatory rules cannot be recommended",
    ):
        ProductEvaluation(
            product_id=1,
            manufacturer_name="Example Manufacturer",
            product_name="Example Pressure Transmitter",
            model_number="PT-100",
            status=RecommendationStatus.RECOMMENDED,
            suitability_score=85.0,
            confidence_score=90.0,
            mandatory_rules_passed=4,
            mandatory_rules_failed=1,
        )


def test_blocking_safety_finding_prevents_recommendation() -> None:
    """A critical blocking safety finding must reject the product."""

    safety_finding = SafetyFinding(
        code="HAZARDOUS_AREA_CERTIFICATION_MISSING",
        severity=SafetySeverity.CRITICAL,
        title="Hazardous-area certification not confirmed",
        message=(
            "The product does not have verified certification for the "
            "specified hazardous area."
        ),
        required_action=(
            "Select equipment with certification matching the site "
            "classification."
        ),
        verification_step=(
            "Confirm the product certificate, equipment protection level, "
            "gas group, and temperature class."
        ),
        blocks_recommendation=True,
    )

    with pytest.raises(
        ValidationError,
        match="blocking safety finding cannot be recommended",
    ):
        ProductEvaluation(
            product_id=2,
            manufacturer_name="Example Manufacturer",
            product_name="Example Flowmeter",
            status=RecommendationStatus.CONDITIONALLY_RECOMMENDED,
            suitability_score=75.0,
            confidence_score=80.0,
            safety_findings=[safety_finding],
        )


def test_non_recommended_product_may_include_blocking_finding() -> None:
    """Rejected products should retain their blocking safety evidence."""

    safety_finding = SafetyFinding(
        code="PRESSURE_LIMIT_EXCEEDED",
        severity=SafetySeverity.CRITICAL,
        title="Product pressure limit exceeded",
        message="The requested process pressure exceeds the product limit.",
        required_action="Select a product with a higher rated pressure limit.",
        blocks_recommendation=True,
    )

    evaluation = ProductEvaluation(
        product_id=3,
        manufacturer_name="Example Manufacturer",
        product_name="Example Level Transmitter",
        status=RecommendationStatus.NOT_RECOMMENDED,
        suitability_score=35.0,
        confidence_score=95.0,
        mandatory_rules_failed=1,
        safety_findings=[safety_finding],
        rejection_reasons=[
            "Required process pressure exceeds the product rating."
        ],
    )

    assert evaluation.status == RecommendationStatus.NOT_RECOMMENDED
    assert evaluation.safety_findings[0].blocks_recommendation is True
    assert evaluation.mandatory_rules_failed == 1


def test_complete_recommendation_response_can_be_created() -> None:
    """The final response should contain ranked and excluded products."""

    requirements = EngineeringRequirements(
        measurement_type="pressure",
        process_temperature_c=80.0,
        process_pressure_bar=10.0,
        required_protocols=["HART"],
    )

    recommended_evaluation = ProductEvaluation(
        product_id=10,
        manufacturer_name="Vendor A",
        product_name="Pressure Transmitter A",
        model_number="PT-A",
        status=RecommendationStatus.RECOMMENDED,
        suitability_score=95.0,
        confidence_score=90.0,
        mandatory_rules_passed=3,
        preferred_rules_passed=1,
        recommendation_reasons=[
            "Temperature and pressure requirements are satisfied.",
            "The preferred HART protocol is supported.",
        ],
    )

    excluded_evaluation = ProductEvaluation(
        product_id=11,
        manufacturer_name="Vendor B",
        product_name="Pressure Transmitter B",
        model_number="PT-B",
        status=RecommendationStatus.NOT_RECOMMENDED,
        suitability_score=40.0,
        confidence_score=85.0,
        mandatory_rules_passed=2,
        mandatory_rules_failed=1,
        rejection_reasons=[
            "The required process pressure exceeds the product rating."
        ],
    )

    response = EngineeringRecommendationResponse(
        requirements=requirements,
        summary=RecommendationSummary(
            products_evaluated=2,
            products_recommended=1,
            products_not_recommended=1,
        ),
        recommendations=[
            RankedRecommendation(
                rank=1,
                evaluation=recommended_evaluation,
            )
        ],
        excluded_products=[excluded_evaluation],
    )

    assert response.summary.products_evaluated == 2
    assert response.summary.products_recommended == 1
    assert len(response.recommendations) == 1
    assert response.recommendations[0].rank == 1
    assert response.recommendations[0].evaluation.product_id == 10
    assert response.excluded_products[0].product_id == 11
    assert "does not replace" in response.disclaimer
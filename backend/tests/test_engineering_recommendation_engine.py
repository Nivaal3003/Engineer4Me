"""Tests for the Phase 3 engineering recommendation engine."""

from types import SimpleNamespace

from app.engineering.engineering_recommendation_engine import (
    EngineeringRecommendationEngine,
)
from app.engineering.recommendation_models import (
    EngineeringRequirements,
    RecommendationStatus,
    RequirementImportance,
    RuleCategory,
    RuleEvaluation,
    RuleStatus,
    SafetySeverity,
)


def build_product(**overrides):
    """Create a lightweight product object for recommendation tests."""

    defaults = {
        "id": 1,
        "name": "Pressure Transmitter",
        "model": "PT-1000",
        "model_number": "PT-1000",
        "manufacturer": SimpleNamespace(name="Example Instruments"),
        "minimum_process_temperature_c": -40.0,
        "maximum_process_temperature_c": 200.0,
        "minimum_process_pressure_bar": 0.0,
        "maximum_process_pressure_bar": 100.0,
        "minimum_ambient_temperature_c": -20.0,
        "maximum_ambient_temperature_c": 70.0,
        "accuracy_percent": 0.1,
        "ingress_protection_rating": "IP66",
        "hazardous_area_approvals": ["ATEX", "IECEx"],
        "wetted_materials": ["316L Stainless Steel"],
        "process_connections": ["1/2 NPT"],
        "protocols": [
            SimpleNamespace(name="HART"),
            SimpleNamespace(name="Modbus"),
        ],
    }

    defaults.update(overrides)

    return SimpleNamespace(**defaults)


def build_rule(
    *,
    status: RuleStatus,
    importance: RequirementImportance,
    score_awarded: float,
    maximum_score: float,
    rule_code: str = "TEST_RULE",
    category: RuleCategory = RuleCategory.ACCURACY,
) -> RuleEvaluation:
    """Create a reusable engineering rule result."""

    return RuleEvaluation(
        rule_code=rule_code,
        category=category,
        title="Test rule",
        status=status,
        importance=importance,
        explanation="Test engineering explanation.",
        score_awarded=score_awarded,
        maximum_score=maximum_score,
    )


def test_suitability_score_uses_only_evaluated_scored_rules() -> None:
    rules = [
        build_rule(
            status=RuleStatus.PASSED,
            importance=RequirementImportance.MANDATORY,
            score_awarded=10.0,
            maximum_score=10.0,
        ),
        build_rule(
            status=RuleStatus.FAILED,
            importance=RequirementImportance.PREFERRED,
            score_awarded=0.0,
            maximum_score=10.0,
        ),
        build_rule(
            status=RuleStatus.NOT_EVALUATED,
            importance=RequirementImportance.MANDATORY,
            score_awarded=0.0,
            maximum_score=20.0,
        ),
    ]

    score = EngineeringRecommendationEngine.calculate_suitability_score(
        rules
    )

    assert score == 50.0


def test_suitability_score_returns_zero_without_scored_rules() -> None:
    rules = [
        build_rule(
            status=RuleStatus.NOT_EVALUATED,
            importance=RequirementImportance.MANDATORY,
            score_awarded=0.0,
            maximum_score=10.0,
        )
    ]

    score = EngineeringRecommendationEngine.calculate_suitability_score(
        rules
    )

    assert score == 0.0


def test_confidence_score_is_reduced_by_missing_product_data() -> None:
    rules = [
        build_rule(
            status=RuleStatus.PASSED,
            importance=RequirementImportance.MANDATORY,
            score_awarded=10.0,
            maximum_score=10.0,
        ),
        build_rule(
            status=RuleStatus.WARNING,
            importance=RequirementImportance.MANDATORY,
            score_awarded=0.0,
            maximum_score=10.0,
            rule_code="PROCESS_PRESSURE_DATA_MISSING",
            category=RuleCategory.PROCESS_PRESSURE,
        ),
    ]

    confidence = EngineeringRecommendationEngine.calculate_confidence_score(
        rules
    )

    assert confidence == 50.0


def test_rule_result_counts_are_separated_by_importance() -> None:
    rules = [
        build_rule(
            status=RuleStatus.PASSED,
            importance=RequirementImportance.MANDATORY,
            score_awarded=10.0,
            maximum_score=10.0,
        ),
        build_rule(
            status=RuleStatus.FAILED,
            importance=RequirementImportance.MANDATORY,
            score_awarded=0.0,
            maximum_score=10.0,
        ),
        build_rule(
            status=RuleStatus.PASSED,
            importance=RequirementImportance.PREFERRED,
            score_awarded=5.0,
            maximum_score=5.0,
        ),
        build_rule(
            status=RuleStatus.FAILED,
            importance=RequirementImportance.PREFERRED,
            score_awarded=0.0,
            maximum_score=5.0,
        ),
    ]

    counts = EngineeringRecommendationEngine.count_rule_results(rules)

    assert counts == {
        "mandatory_rules_passed": 1,
        "mandatory_rules_failed": 1,
        "preferred_rules_passed": 1,
        "preferred_rules_failed": 1,
    }


def test_missing_information_is_collected_without_duplicates() -> None:
    rules = [
        RuleEvaluation(
            rule_code="PRODUCT_ENGINEERING_DATA_INCOMPLETE",
            category=RuleCategory.DATA_COMPLETENESS,
            title="Product engineering data completeness",
            status=RuleStatus.WARNING,
            importance=RequirementImportance.MANDATORY,
            explanation="Product data is incomplete.",
            product_value={
                "missing_fields": [
                    "process pressure limits",
                    "communication protocols",
                    "process pressure limits",
                ]
            },
            score_awarded=0.0,
            maximum_score=0.0,
        )
    ]

    missing = (
        EngineeringRecommendationEngine.collect_missing_information(rules)
    )

    assert missing == [
        "process pressure limits",
        "communication protocols",
    ]


def test_mandatory_failure_creates_blocking_safety_finding() -> None:
    rules = [
        RuleEvaluation(
            rule_code="PROCESS_PRESSURE_OUTSIDE_LIMITS",
            category=RuleCategory.PROCESS_PRESSURE,
            title="Process pressure suitability",
            status=RuleStatus.FAILED,
            importance=RequirementImportance.MANDATORY,
            explanation="The required pressure exceeds product limits.",
            score_awarded=0.0,
            maximum_score=15.0,
        )
    ]

    findings = EngineeringRecommendationEngine.build_safety_findings(rules)

    assert len(findings) == 1
    assert findings[0].severity == SafetySeverity.CRITICAL
    assert findings[0].blocks_recommendation is True


def test_preferred_failure_safety_finding_does_not_block() -> None:
    rules = [
        RuleEvaluation(
            rule_code="PROCESS_CONNECTION_NO_MATCH",
            category=RuleCategory.PROCESS_CONNECTION,
            title="Process connection suitability",
            status=RuleStatus.FAILED,
            importance=RequirementImportance.PREFERRED,
            explanation="The preferred process connection does not match.",
            score_awarded=0.0,
            maximum_score=7.5,
        )
    ]

    findings = EngineeringRecommendationEngine.build_safety_findings(rules)

    assert len(findings) == 1
    assert findings[0].blocks_recommendation is False


def test_status_is_not_recommended_when_mandatory_rule_fails() -> None:
    status = EngineeringRecommendationEngine.determine_recommendation_status(
        mandatory_rules_failed=1,
        preferred_rules_failed=0,
        missing_information=[],
        safety_findings=[],
    )

    assert status == RecommendationStatus.NOT_RECOMMENDED


def test_status_is_insufficient_when_information_is_missing() -> None:
    status = EngineeringRecommendationEngine.determine_recommendation_status(
        mandatory_rules_failed=0,
        preferred_rules_failed=0,
        missing_information=["process pressure limits"],
        safety_findings=[],
    )

    assert status == RecommendationStatus.INSUFFICIENT_INFORMATION


def test_status_is_conditional_when_only_preferred_rule_fails() -> None:
    status = EngineeringRecommendationEngine.determine_recommendation_status(
        mandatory_rules_failed=0,
        preferred_rules_failed=1,
        missing_information=[],
        safety_findings=[],
    )

    assert status == RecommendationStatus.CONDITIONALLY_RECOMMENDED


def test_status_is_recommended_when_all_applicable_rules_pass() -> None:
    status = EngineeringRecommendationEngine.determine_recommendation_status(
        mandatory_rules_failed=0,
        preferred_rules_failed=0,
        missing_information=[],
        safety_findings=[],
    )

    assert status == RecommendationStatus.RECOMMENDED


def test_evaluate_product_returns_recommended_product() -> None:
    requirements = EngineeringRequirements(
        process_temperature_c=100.0,
        process_pressure_bar=20.0,
        ambient_temperature_c=40.0,
        required_accuracy_percent=0.25,
        required_ingress_protection_rating="IP65",
        hazardous_area_required=True,
        required_hazardous_area_approvals=["ATEX"],
        required_wetted_materials=["316L Stainless Steel"],
        required_process_connections=["1/2 NPT"],
        required_protocols=["HART"],
    )
    product = build_product()

    evaluation = EngineeringRecommendationEngine.evaluate_product(
        product,
        requirements,
    )

    assert evaluation.product_id == 1
    assert evaluation.manufacturer_name == "Example Instruments"
    assert evaluation.product_name == "Pressure Transmitter"
    assert evaluation.model_number == "PT-1000"
    assert evaluation.status == RecommendationStatus.RECOMMENDED
    assert evaluation.suitability_score == 100.0
    assert evaluation.confidence_score == 100.0
    assert evaluation.mandatory_rules_failed == 0
    assert evaluation.rejection_reasons == []


def test_evaluate_product_rejects_pressure_failure() -> None:
    requirements = EngineeringRequirements(
        process_pressure_bar=150.0,
    )
    product = build_product()

    evaluation = EngineeringRecommendationEngine.evaluate_product(
        product,
        requirements,
    )

    assert evaluation.status == RecommendationStatus.NOT_RECOMMENDED
    assert evaluation.mandatory_rules_failed == 1
    assert evaluation.suitability_score == 0.0
    assert len(evaluation.rejection_reasons) == 1
    assert any(
        finding.blocks_recommendation
        for finding in evaluation.safety_findings
    )


def test_evaluate_product_is_conditional_for_preferred_protocol_failure() -> None:
    requirements = EngineeringRequirements(
        required_protocols=["PROFINET"],
        communication_protocol_importance=RequirementImportance.PREFERRED,
    )
    product = build_product()

    evaluation = EngineeringRecommendationEngine.evaluate_product(
        product,
        requirements,
    )

    assert (
        evaluation.status
        == RecommendationStatus.CONDITIONALLY_RECOMMENDED
    )
    assert evaluation.preferred_rules_failed == 1
    assert evaluation.mandatory_rules_failed == 0


def test_evaluate_product_reports_insufficient_information() -> None:
    requirements = EngineeringRequirements(
        process_pressure_bar=20.0,
    )
    product = build_product(
        minimum_process_pressure_bar=None,
        maximum_process_pressure_bar=None,
    )

    evaluation = EngineeringRecommendationEngine.evaluate_product(
        product,
        requirements,
    )

    assert (
        evaluation.status
        == RecommendationStatus.INSUFFICIENT_INFORMATION
    )
    assert "process pressure limits" in evaluation.missing_information
    assert evaluation.confidence_score < 100.0